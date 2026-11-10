package explorer

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
func Handler(client *Client, staticDir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/pods", func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		if ns != "" && !validName(ns, true) {
			problem(w, 400, "Invalid namespace identifier")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		s := client.snapshot(ctx, ns, false)
		if !s.available("pods") {
			writeJSON(w, 502, map[string]any{"error": s["pods"].State.Message, "states": s.states()})
			return
		}
		pods := []PodView{}
		names := []string{}
		for _, p := range s.items("pods") {
			if strings.Contains(name(p), r.URL.Query().Get("name")) {
				pods = append(pods, podView(p, s))
			}
		}
		for _, n := range s.items("namespaces") {
			names = append(names, name(n))
		}
		sort.Strings(names)
		sort.Slice(pods, func(i, j int) bool { return pods[i].Namespace+"/"+pods[i].Name < pods[j].Namespace+"/"+pods[j].Name })
		writeJSON(w, 200, map[string]any{"pods": pods, "namespaces": names, "states": s.states()})
	})
	mux.HandleFunc("GET /api/pods/{namespace}/{name}", func(w http.ResponseWriter, r *http.Request) {
		ns, n := r.PathValue("namespace"), r.PathValue("name")
		if !validName(ns, true) || !validName(n, false) {
			problem(w, 400, "Invalid namespace or pod identifier")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
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
		writeJSON(w, 200, map[string]any{"pod": podView(p, s), "policies": networkPolicies(p, s), "routing": routing(p, s), "states": s.states(), "capturedAt": time.Now().UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "running", "storage": "memory only", "context": "rancher-desktop (proxy must target this context)"})
	})
	mux.HandleFunc("GET /api/", func(w http.ResponseWriter, r *http.Request) { problem(w, 404, "Unsupported read endpoint") })
	if staticDir != "" {
		files := http.FileServer(http.Dir(staticDir))
		mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/pods/") {
				http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
				return
			}
			if !strings.HasPrefix(r.URL.Path, "/assets/") {
				http.NotFound(w, r)
				return
			}
			if _, err := os.Stat(filepath.Join(staticDir, filepath.Clean(r.URL.Path))); err != nil {
				http.NotFound(w, r)
				return
			}
			files.ServeHTTP(w, r)
		})
	}
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
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			problem(w, 405, "Read-only explorer: only GET is supported")
			return
		}
		mux.ServeHTTP(w, r)
	})
}
