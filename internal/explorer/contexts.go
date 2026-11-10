package explorer

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
)

type ContextInfo struct {
	Mode       string   `json:"mode"`
	Contexts   []string `json:"contexts"`
	Current    string   `json:"current"`
	Generation string   `json:"generation"`
	Status     string   `json:"status"`
	Message    string   `json:"message,omitempty"`
}

type contextSession struct {
	process *proxyProcess
	ctx     context.Context
	cancel  context.CancelFunc
	handler http.Handler
}

type ContextManager struct {
	Assessment AssessmentOptions
	mu         sync.RWMutex
	change     sync.Mutex
	refresh    sync.Mutex
	runner     contextRunner
	assets     fs.FS
	info       ContextInfo
	ctx        context.Context
	cancel     context.CancelFunc
	session    *contextSession
	closed     bool
}

func NewContextManager(assets fs.FS) *ContextManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ContextManager{Assessment: AssessmentOptions{ExpectIstio: true}, runner: kubectlRunner{}, assets: assets, ctx: ctx, cancel: cancel, info: ContextInfo{Mode: "managed", Contexts: []string{}, Status: "stopped", Message: "Choose a context to start its read-only proxy."}}
}

func (m *ContextManager) Info() ContextInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info := m.info
	info.Contexts = append([]string{}, info.Contexts...)
	if m.session != nil {
		select {
		case <-m.session.process.done:
			info.Status, info.Message = "disconnected", "The proxy stopped. Reconnect this context after checking local authentication."
		default:
		}
	}
	return info
}

func (m *ContextManager) Refresh(ctx context.Context) error {
	if !m.refresh.TryLock() {
		return errors.New("Context discovery is already running. Retry shortly.")
	}
	defer m.refresh.Unlock()
	names, err := m.runner.names(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		return err
	}
	m.info.Contexts = names
	return nil
}

func (m *ContextManager) disconnectLocked() {
	if m.session != nil {
		m.session.cancel()
		m.session.process.stop()
		m.session.process.client.http.CloseIdleConnections()
		m.session = nil
	}
}

func (m *ContextManager) Select(ctx context.Context, name string) error {
	if !m.change.TryLock() {
		return errors.New("A context switch is already in progress. Retry shortly.")
	}
	defer m.change.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	defer cancel()
	defer stop()
	if err := m.Refresh(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed || !slices.Contains(m.info.Contexts, name) {
		m.mu.Unlock()
		return errors.New("Select a context from the current kubectl context list.")
	}
	m.disconnectLocked()
	m.info.Current, m.info.Generation, m.info.Status, m.info.Message = name, rand.Text(), "starting", "Starting the read-only proxy…"
	m.mu.Unlock()
	process, err := m.runner.start(ctx, name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.info.Status, m.info.Message = "error", err.Error()
		return err
	}
	if m.closed || ctx.Err() != nil {
		process.stop()
		m.info.Status, m.info.Message = "stopped", "Context selection was cancelled. Choose a context to reconnect."
		return errors.New("Context manager is shutting down.")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	process.client.Assessment = m.Assessment
	m.session = &contextSession{process, lifetime, cancel, Handler(process.client, m.assets)}
	go func() {
		select {
		case <-process.done:
			cancel()
		case <-lifetime.Done():
		}
	}()
	m.info.Status, m.info.Message = "ready", ""
	return nil
}

func (m *ContextManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.cancel()
	m.disconnectLocked()
}

func (m *ContextManager) selectRequest(w http.ResponseWriter, r *http.Request) {
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Header.Get("Origin") != "http://"+r.Host || r.Header.Get("X-Peeker-Action") != "select-context" || media != "application/json" {
		problem(w, 403, "Context selection requires a same-origin JSON request.")
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || input.Name == "" || len(input.Name) > 1024 {
		problem(w, 400, "Invalid context selection")
		return
	}
	if err := m.Select(r.Context(), input.Name); err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error(), "state": m.Info()})
		return
	}
	writeJSON(w, 200, m.Info())
}

func (m *ContextManager) serveCluster(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	session, generation := m.session, m.info.Generation
	m.mu.RUnlock()
	if session == nil {
		if !strings.HasPrefix(r.URL.Path, "/api/") && m.assets != nil {
			frontendHandler(m.assets).ServeHTTP(w, r)
			return
		}
		problem(w, 503, "Select or reconnect a Kubernetes context first.")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-Peeker-Context") != generation {
		problem(w, 409, "The selected context changed. Refresh before reading cluster data.")
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(session.ctx, cancel)
	defer stop()
	defer cancel()
	w.Header().Set("X-Peeker-Context", generation)
	session.handler.ServeHTTP(w, r.WithContext(ctx))
}

func (m *ContextManager) Handler() http.Handler {
	return localBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/contexts":
			info := m.Info()
			if r.URL.Query().Get("refresh") == "true" || len(info.Contexts) == 0 {
				if err := m.Refresh(r.Context()); err != nil {
					info.Status, info.Message = "error", err.Error()
					writeJSON(w, 200, info)
					return
				}
			}
			writeJSON(w, 200, m.Info())
		case r.Method == "POST" && r.URL.Path == "/api/context":
			m.selectRequest(w, r)
		case r.URL.Path == "/api/health":
			writeJSON(w, 200, map[string]string{"status": "running", "storage": "memory only"})
		default:
			m.serveCluster(w, r)
		}
	}), "/api/context")
}
