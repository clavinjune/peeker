package explorer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type mcpResponseWriter struct{ http.ResponseWriter }

func (w mcpResponseWriter) WriteHeader(status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.ResponseWriter.WriteHeader(status)
}

func (w mcpResponseWriter) Write(data []byte) (int, error) {
	w.Header().Set("Cache-Control", "no-store")
	return w.ResponseWriter.Write(data)
}

func (w mcpResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func mcpHTTPHandler(api, transport http.Handler) http.Handler {
	slots := make(chan struct{}, 4)
	return localBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			api.ServeHTTP(w, r)
			return
		}
		w = mcpResponseWriter{w}
		defer w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			problem(w, http.StatusMethodNotAllowed, "MCP requires POST")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			problem(w, 429, "Too many concurrent MCP requests")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
		if err != nil {
			problem(w, http.StatusRequestEntityTooLarge, "MCP request body unavailable or exceeds limit")
			return
		}
		var request map[string]json.RawMessage
		if json.Unmarshal(body, &request) != nil {
			problem(w, http.StatusBadRequest, "A single MCP request object is required; batches are unsupported")
			return
		}
		var method string
		if json.Unmarshal(request["method"], &method) != nil {
			problem(w, http.StatusBadRequest, "MCP method must be a string")
			return
		}
		switch method {
		case "initialize", "ping", "server/discover", "tools/list", "tools/call", "notifications/initialized", "notifications/cancelled":
		default:
			problem(w, http.StatusBadRequest, "Unsupported MCP method")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		transport.ServeHTTP(w, r.WithContext(context.WithValue(ctx, mcpRequestLifetime{}, ctx)))
	}), "/api/context", "/api/pods/query", "/mcp")
}
