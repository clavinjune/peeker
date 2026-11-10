package explorer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionHandlerServesAssetsAndKeepsAPIBoundary(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{"index.html": "<html>Peeker</html>", "assets/app.js": "console.log('Peeker')"} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	client, err := NewClient("http://127.0.0.1:8001")
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler(client, dir)
	for _, test := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/", "Peeker", 200},
		{"GET", "/pods/demo/web", "Peeker", 200},
		{"GET", "/assets/app.js", "console.log", 200},
		{"GET", "/api/health", "memory only", 200},
		{"GET", "/api/secrets", "Unsupported", 404},
		{"POST", "/api/pods", "Read-only", 405},
		{"GET", "/go.mod", "404", 404},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(test.method, "http://127.0.0.1:8080"+test.path, nil))
		if w.Code != test.status || !strings.Contains(w.Body.String(), test.body) {
			t.Fatalf("%s %s: %d %s", test.method, test.path, w.Code, w.Body.String())
		}
	}
}

func TestAPIRejectsMutationsPassthroughAndInvalidIdentifiers(t *testing.T) {
	calls := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		t.Errorf("unexpected upstream request %s %s", r.Method, r.URL.Path)
	}))
	defer proxy.Close()
	client, _ := NewClient(proxy.URL)
	handler := Handler(client, "")
	tests := []struct {
		method, path string
		status       int
	}{
		{"POST", "/api/pods", 405}, {"PATCH", "/api/pods/demo/web", 405}, {"DELETE", "/api/pods/demo/web", 405}, {"PUT", "/api/pods", 405},
		{"GET", "/api/v1/secrets", 404}, {"GET", "/api/proxy", 404}, {"GET", "/api/pods/demo/web/exec", 404}, {"GET", "/api/pods?namespace=..", 400}, {"GET", "/api/pods/demo/Bad_Name", 400},
	}
	for _, test := range tests {
		req := httptest.NewRequest(test.method, "http://127.0.0.1:8080"+test.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != test.status {
			t.Fatalf("%s %s: %d", test.method, test.path, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal(calls)
	}
}
func TestDiscoveryDistinguishesMissingDeniedAndResourceErrors(t *testing.T) {
	for _, code := range []int{403, 404, 503} {
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		client, _ := NewClient(proxy.URL)
		c := client.list(context.Background(), resource{"x", "example.io", "things", "Thing", []string{"v1"}, true}, "")
		want := map[int]string{403: "denied", 404: "missing-api", 503: "error"}[code]
		if c.State.Status != want {
			t.Fatal(code, c.State)
		}
		proxy.Close()
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/example.io/v1" {
			w.Write([]byte(`{"resources":[{"name":"things"}]}`))
			return
		}
		w.WriteHeader(404)
	}))
	client, _ := NewClient(proxy.URL)
	if got := client.list(context.Background(), resource{"x", "example.io", "things", "Thing", []string{"v1"}, true}, ""); got.State.Status != "error" {
		t.Fatal(got.State)
	}
	proxy.Close()
	if got := client.list(context.Background(), resources[0], ""); got.State.Status != "error" || !strings.Contains(got.State.Message, "kubectl proxy") {
		t.Fatal(got.State)
	}
}
func TestLoopbackOriginAndCredentialRedaction(t *testing.T) {
	for _, u := range []string{"http://example.com", "http://127.0.0.1:8001/api", "http://user:secret@127.0.0.1", "https://127.0.0.1", "http://169.254.169.254"} {
		if _, err := NewClient(u); err == nil {
			t.Fatal("unsafe URL accepted", u)
		}
	}
	client, _ := NewClient("http://127.0.0.1:8001")
	handler := Handler(client, "")
	request := httptest.NewRequest("GET", "http://malicious.example/api/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	request = httptest.NewRequest("GET", "http://127.0.0.1:8080/api/health", nil)
	request.Header.Set("Origin", "http://evil.example")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	pod := samplePod(t)
	pod["spec"] = map[string]any{"containers": []any{map[string]any{"name": "web", "env": []any{map[string]any{"name": "PASSWORD", "value": "sensitive-value"}}}}}
	if strings.Contains(jsonText(podView(pod, Snapshot{})), "sensitive-value") {
		t.Fatal("container credentials leaked")
	}
}
