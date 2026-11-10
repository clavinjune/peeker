package explorer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPClientReadToolsAndGeneration(t *testing.T) {
	manager := NewContextManager(nil)
	defer manager.Close()
	manager.runner = fixtureRunner{urls: map[string]string{"one": "http://127.0.0.1:1"}}
	if err := manager.Select(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}
	manager.session.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("MCP mutated upstream")
		}
		switch r.URL.Path {
		case "/api/pods":
			pods := []PodView{{Ref: Ref{Kind: "Pod", Namespace: "demo", Name: "first"}}, {Ref: Ref{Kind: "Pod", Namespace: "demo", Name: "second"}}}
			writeJSON(w, 200, map[string]any{"pods": pods, "namespaces": []string{"demo"}, "states": []State{}})
		case "/api/pods/demo/first":
			writeJSON(w, 200, map[string]string{"evidence": "fixture"})
		case "/api/capabilities":
			writeJSON(w, 200, map[string]string{"cilium": "detected"})
		default:
			t.Error("unexpected read", r.URL)
			problem(w, 404, "unexpected")
		}
	})
	server := httptest.NewServer(MCPHandler(manager.Handler()))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 4 {
		t.Fatal(tools, err)
	}
	for _, tool := range tools.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatal("tool not read-only", tool.Name)
		}
	}
	for _, call := range []struct {
		name      string
		args      map[string]any
		wantError bool
	}{
		{"cluster_status", map[string]any{}, false},
		{"cluster_capabilities", map[string]any{"generation": manager.Info().Generation}, false},
		{"list_pods", map[string]any{"generation": manager.Info().Generation, "limit": 1}, false},
		{"get_pod", map[string]any{"generation": manager.Info().Generation, "namespace": "demo", "name": "first"}, false},
		{"get_pod", map[string]any{"generation": "stale", "namespace": "demo", "name": "first"}, true},
		{"get_pod", map[string]any{"generation": manager.Info().Generation, "namespace": "demo", "name": "../secrets"}, true},
		{"list_pods", map[string]any{"generation": manager.Info().Generation, "limit": 101}, true},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil || result.IsError != call.wantError {
			t.Fatal(call.name, result, err)
		}
		if call.name == "list_pods" && !call.wantError {
			raw, _ := json.Marshal(result.StructuredContent)
			if !strings.Contains(string(raw), `"hasMore":true`) || strings.Contains(string(raw), `"name":"second"`) {
				t.Fatal(string(raw))
			}
		}
	}
}

func TestMCPHTTPBoundaryAndBounds(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:1")
	handler := MCPHandler(Handler(client, nil))
	for _, test := range []struct {
		method, host, origin, body string
		want                       int
	}{
		{"POST", "attacker.invalid", "", `{}`, 403},
		{"POST", "127.0.0.1", "http://attacker.invalid", `{}`, 403},
		{"GET", "127.0.0.1", "", "", 405},
		{"DELETE", "127.0.0.1", "", "", 405},
		{"POST", "127.0.0.1", "", strings.Repeat(" ", 17*1024), 413},
	} {
		r := httptest.NewRequest(test.method, "http://"+test.host+"/mcp", strings.NewReader(test.body))
		r.Header.Set("Origin", test.origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.want {
			t.Fatal(test.method, w.Code, w.Body.String())
		}
	}
}
