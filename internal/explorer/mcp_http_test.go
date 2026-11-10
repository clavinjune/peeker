package explorer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mcpRequest(body string) *http.Request {
	r := httptest.NewRequest("POST", "http://127.0.0.1/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	return r
}

func TestMCPRejectsBatchesSubscriptionsAndCaches(t *testing.T) {
	handler := MCPHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected API read") }))
	for _, body := range []string{
		`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`,
		`{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","Method":"ping","params":{"notifications":{}}}`,
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, mcpRequest(body))
		if w.Code != 400 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code, w.Header(), w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
	if w.Code != 200 || w.Result().Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatal(w.Code, w.Header(), w.Body.String())
	}
	var response struct {
		Result struct{ Capabilities map[string]json.RawMessage }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Result.Capabilities) != 1 || string(response.Result.Capabilities["tools"]) != "{}" {
		t.Fatal(response.Result.Capabilities)
	}
}

func TestMCPImplicitResponseIsNotCacheable(t *testing.T) {
	handler := mcpHTTPHandler(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-transform")
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, mcpRequest(`{"method":"ping"}`))
	if w.Result().Header.Get("Cache-Control") != "no-store" {
		t.Fatal(w.Result().Header)
	}
}

func TestMCPSDKCancellationReleasesReads(t *testing.T) {
	for _, protocol := range []string{"2025-06-18", "2026-07-28"} {
		t.Run(protocol, func(t *testing.T) {
			entered, stopped, finished := make(chan struct{}, 4), make(chan struct{}, 4), make(chan struct{}, 4)
			served := make(chan struct{}, 4)
			handler := MCPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				<-r.Context().Done()
				stopped <- struct{}{}
			}))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.ServeHTTP(w, r)
				served <- struct{}{}
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for range 4 {
				go func() {
					body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}},"name":"cluster_status","arguments":{}}}`, protocol)
					r, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/mcp", strings.NewReader(body))
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Accept", "application/json, text/event-stream")
					r.Header.Set("MCP-Protocol-Version", protocol)
					r.Header.Set("Mcp-Method", "tools/call")
					r.Header.Set("Mcp-Name", "cluster_status")
					response, err := server.Client().Do(r)
					if response != nil {
						if ctx.Err() == nil {
							body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
							t.Errorf("SDK returned before cancellation: %d %s", response.StatusCode, body)
						}
						response.Body.Close()
					}
					if err != nil && ctx.Err() == nil {
						t.Error(err)
					}
					finished <- struct{}{}
				}()
			}
			for range 4 {
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("SDK did not dispatch read")
				}
			}
			cancel()
			for range 4 {
				select {
				case <-stopped:
				case <-time.After(2 * time.Second):
					t.Fatal("SDK lost read cancellation")
				}
			}
			for range 4 {
				select {
				case <-finished:
				case <-time.After(2 * time.Second):
					t.Fatal("SDK request did not finish")
				}
			}
			for range 4 {
				select {
				case <-served:
				case <-time.After(2 * time.Second):
					t.Fatal("SDK handler did not release its slot")
				}
			}
		})
	}
}

func TestMCPOuterLifetimeAndCapacity(t *testing.T) {
	entered := make(chan struct{}, 4)
	finished := make(chan struct{}, 4)
	handler := mcpHTTPHandler(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 45*time.Second {
			t.Error("missing outer deadline")
		}
		entered <- struct{}{}
		<-r.Context().Done()
		w.WriteHeader(503)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range 4 {
		go func() {
			handler.ServeHTTP(httptest.NewRecorder(), mcpRequest(`{"method":"ping"}`).WithContext(ctx))
			finished <- struct{}{}
		}()
	}
	for range 4 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("request did not enter")
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, mcpRequest(`{"method":"ping"}`))
	if w.Code != 429 {
		t.Fatal("capacity bound ignored", w.Code)
	}
	cancel()
	for range 4 {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("request cancellation did not release slot")
		}
	}
}
