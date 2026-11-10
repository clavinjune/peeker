package explorer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureRunner struct {
	urls    map[string]string
	startFn func(context.Context, string) (*proxyProcess, error)
}

func (f fixtureRunner) names(context.Context) ([]string, error) {
	return []string{"one", "two", "broken"}, nil
}

func (f fixtureRunner) start(ctx context.Context, name string) (*proxyProcess, error) {
	if f.startFn != nil {
		return f.startFn(ctx, name)
	}
	if name == "broken" {
		return nil, errors.New("fixture startup failed")
	}
	client, err := NewClient(f.urls[name])
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	var once sync.Once
	return &proxyProcess{client, func() { once.Do(func() { close(done) }) }, done}, nil
}

func contextRequest(manager *ContextManager, method, path, body, generation string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Peeker-Action", "select-context")
	r.Header.Set("X-Peeker-Context", generation)
	w := httptest.NewRecorder()
	manager.Handler().ServeHTTP(w, r)
	return w
}

func TestContextSelectionBoundary(t *testing.T) {
	manager := NewContextManager(nil)
	defer manager.Close()
	manager.runner = fixtureRunner{urls: map[string]string{"one": "http://127.0.0.1:1"}}
	for _, test := range []struct {
		origin, action, media, body string
		status                      int
	}{
		{"", "select-context", "application/json", `{"name":"one"}`, 403},
		{"http://attacker.invalid", "select-context", "application/json", `{"name":"one"}`, 403},
		{"http://127.0.0.1:8080", "", "application/json", `{"name":"one"}`, 403},
		{"http://127.0.0.1:8080", "select-context", "text/plain", `{"name":"one"}`, 403},
		{"http://127.0.0.1:8080", "select-context", "application/json", `{"name":"one","extra":true}`, 400},
		{"http://127.0.0.1:8080", "select-context", "application/json", `{"name":"one"}{}`, 400},
		{"http://127.0.0.1:8080", "select-context", "application/json", `{"name":"` + strings.Repeat("x", 2048) + `"}`, 400},
		{"http://127.0.0.1:8080", "select-context", "application/json", `{"name":"--server=evil"}`, 409},
	} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/context", strings.NewReader(test.body))
		r.Header.Set("Origin", test.origin)
		r.Header.Set("X-Peeker-Action", test.action)
		r.Header.Set("Content-Type", test.media)
		w := httptest.NewRecorder()
		manager.Handler().ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("got %d want %d: %s", w.Code, test.status, w.Body.String())
		}
	}
	if manager.Info().Generation != "" {
		t.Fatal("rejected selection changed context")
	}
	if w := contextRequest(manager, "POST", "/api/context", `{"name":"one"}`, ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		if w := contextRequest(manager, method, "/api/pods", "", manager.Info().Generation); w.Code != 405 {
			t.Fatal(method, w.Code)
		}
	}
}

func TestContextSwitchCancelsReadsAndRejectsOldGeneration(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"groups":[{"name":"cilium.io"}]}`)) }))
	defer second.Close()
	manager := NewContextManager(nil)
	defer manager.Close()
	manager.runner = fixtureRunner{urls: map[string]string{"one": first.URL, "two": second.URL}}
	if err := manager.Select(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}
	old := manager.Info().Generation
	readDone := make(chan struct{})
	go func() { contextRequest(manager, "GET", "/api/capabilities", "", old); close(readDone) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("read never started")
	}
	if err := manager.Select(context.Background(), "two"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("old upstream read not cancelled")
	}
	<-readDone
	for _, generation := range []string{"", old} {
		if w := contextRequest(manager, "GET", "/api/capabilities", "", generation); w.Code != 409 {
			t.Fatal(w.Code)
		}
	}
	current := manager.Info()
	w := contextRequest(manager, "GET", "/api/capabilities", "", current.Generation)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"cilium":"detected"`) || current.Generation == old {
		t.Fatal(w.Body.String(), current)
	}
	manager.session.process.stop()
	if manager.Info().Status != "disconnected" {
		t.Fatal(manager.Info())
	}
	if err := manager.Select(context.Background(), "broken"); err == nil || manager.Info().Status != "error" {
		t.Fatal("startup failure lost")
	}
	if w := contextRequest(manager, "GET", "/api/capabilities", "", current.Generation); w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestContextShutdownCancelsStartup(t *testing.T) {
	manager := NewContextManager(nil)
	started, done := make(chan struct{}), make(chan struct{})
	manager.runner = fixtureRunner{startFn: func(ctx context.Context, _ string) (*proxyProcess, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	go func() { manager.Select(context.Background(), "one"); close(done) }()
	<-started
	if err := manager.Select(context.Background(), "two"); err == nil {
		t.Fatal("concurrent switch accepted")
	}
	manager.Close()
	manager.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("startup not cancelled")
	}
	if err := manager.Select(context.Background(), "one"); err == nil {
		t.Fatal("closed manager restarted")
	}
}

func TestCapabilityDiscoveryStates(t *testing.T) {
	for _, test := range []struct {
		body          string
		status        int
		istio, cilium string
	}{
		{`{"groups":[{"name":"networking.istio.io"},{"name":"cilium.io"}]}`, 200, "detected", "detected"},
		{`{"groups":[]}`, 200, "not-detected", "not-detected"},
		{`{}`, 200, "unknown", "unknown"},
		{`sensitive upstream error`, 403, "unknown", "unknown"},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.URL.Path != "/apis" {
				t.Error(r.Method, r.URL)
			}
			w.WriteHeader(test.status)
			w.Write([]byte(test.body))
		}))
		client, _ := NewClient(server.URL)
		w := httptest.NewRecorder()
		capabilityHandler(client)(w, httptest.NewRequest("GET", "/api/capabilities", nil))
		server.Close()
		var result map[string]string
		json.Unmarshal(w.Body.Bytes(), &result)
		if result["istio"] != test.istio || result["cilium"] != test.cilium || strings.Contains(w.Body.String(), "sensitive") {
			t.Fatal(result)
		}
	}
}
