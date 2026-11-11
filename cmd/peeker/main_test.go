package main

import (
	"io/fs"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/clavinjune/peeker/internal/explorer"
	"github.com/clavinjune/peeker/web"
)

func TestEmbeddedPrerenderedFrontend(t *testing.T) {
	assets, err := fs.Sub(web.Assets, "dist")
	if err != nil {
		t.Fatal(err)
	}
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	if !strings.Contains(html, ">KUBERNETES SECURITY<") || strings.Contains(html, `<div id="root"></div>`) {
		t.Fatal("embedded index must contain prerendered application HTML")
	}
	links := regexp.MustCompile(`(?:src|href)="(/assets/[^\"]+)"`).FindAllStringSubmatch(html, -1)
	if len(links) < 2 {
		t.Fatal("expected built JavaScript and CSS links")
	}
	paths := []string{"/", "/pods/demo/web", "/explore", "/explore/pods/demo/web", "/registry", "/registry/Deployment/demo/web/uid", "/registry/sbom/example"}
	for _, link := range links {
		paths = append(paths, link[1])
	}
	client, err := explorer.NewClient("http://127.0.0.1:8001")
	if err != nil {
		t.Fatal(err)
	}
	handler := explorer.Handler(client, assets)
	for _, path := range paths {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:8080"+path, nil))
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("embedded %s: status %d, size %d", path, w.Code, w.Body.Len())
		}
		if !strings.HasPrefix(path, "/assets/") && w.Body.String() != html {
			t.Fatalf("%s must serve the prerendered shell", path)
		}
	}
}
