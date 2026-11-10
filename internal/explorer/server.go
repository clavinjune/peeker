package explorer

import (
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func frontendHandler(assets fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/pods/") {
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFileFS(w, r, assets, "index.html")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if !strings.HasPrefix(path, "assets/") || !fs.ValidPath(path) {
			http.NotFound(w, r)
			return
		}
		info, err := fs.Stat(assets, path)
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeFileFS(w, r, assets, path)
	})
}

func Handler(client *Client, assets fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/pods/{namespace}/{name}/traffic", trafficHandler(client))
	inventory := inventoryHandler(client)
	mux.HandleFunc("GET /api/namespaces", namespaceHandler(client))
	mux.HandleFunc("GET /api/pods", inventory)
	mux.HandleFunc("POST /api/pods/query", inventory)
	mux.HandleFunc("GET /api/pods/{namespace}/{name}", func(w http.ResponseWriter, r *http.Request) {
		ns, n := r.PathValue("namespace"), r.PathValue("name")
		if !validName(ns, true) || !validName(n, false) {
			problem(w, 400, "Invalid namespace or pod identifier")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		if r.URL.Query().Get("refresh") == "true" {
			client.invalidate()
		}
		s := client.snapshot(ctx, "", true)
		if !s.available("pods") {
			writeJSON(w, 502, map[string]any{"error": s["pods"].State.Message, "states": s.states()})
			return
		}
		p, found := s.find("pods", ns, n)
		if !found {
			problem(w, 404, "Pod not found in the successfully read pod inventory. It may have been replaced; refresh the list.")
			return
		}
		security := assessPod(p, s, client.Assessment)
		view := podView(p, s)
		view.Risk = security.Risk
		writeJSON(w, 200, map[string]any{"pod": view, "security": security, "permissions": podPermissions(p, s), "policies": networkPolicies(p, s), "routing": routing(p, s), "states": s.states(), "capturedAt": time.Now().UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "running", "storage": "memory only"})
	})
	mux.HandleFunc("GET /api/contexts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, ContextInfo{Mode: "external", Current: "External proxy", Generation: "external", Status: "ready", Contexts: []string{}})
	})
	mux.HandleFunc("GET /api/capabilities", capabilityHandler(client))
	mux.HandleFunc("GET /api/", func(w http.ResponseWriter, r *http.Request) { problem(w, 404, "Unsupported read endpoint") })
	if assets != nil {
		mux.Handle("GET /", frontendHandler(assets))
	}
	return localBoundary(mux, "/api/pods/query")
}

func localBoundary(next http.Handler, postPaths ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			problem(w, 403, "Only loopback Host headers are accepted")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host || u.Scheme != "http" {
				problem(w, 403, "Cross-origin requests are not accepted")
				return
			}
		}
		if r.Method != http.MethodGet && !(r.Method == http.MethodPost && slices.Contains(postPaths, r.URL.Path)) {
			w.Header().Set("Allow", "GET")
			problem(w, 405, "Read-only explorer: only GET is supported")
			return
		}
		next.ServeHTTP(w, r)
	})
}
