package explorer

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestTrivyImageClassificationIntegration(t *testing.T) {
	if os.Getenv("PEEKER_VERIFY_IMAGES") != "1" {
		t.Skip("set PEEKER_VERIFY_IMAGES=1 to scan public images with the installed Trivy")
	}
	for _, test := range []struct{ image, status string }{
		{"alpine:3.22", "not-distroless"},
		{"gcr.io/distroless/static-debian12:nonroot", "distroless-consistent"},
	} {
		t.Run(test.image, func(t *testing.T) {
			bom, err := scanImage(context.Background(), test.image)
			if err != nil {
				t.Fatal(err)
			}
			got := classifyImage(bom, "linux/"+runtime.GOARCH)
			t.Logf("image=%s evidence=%s", test.image, jsonText(got))
			if got.Status != test.status || got.Digest == "" || got.OSPackages == 0 || got.Architecture != runtime.GOARCH {
				t.Fatalf("unexpected real-image evidence: %+v", got)
			}
		})
	}
}

func TestImageClassificationUsesPackageEvidence(t *testing.T) {
	digest := "example/image@sha256:" + strings.Repeat("a", 64)
	component := func(name, kind string) Object {
		return Object{"name": name, "version": "1", "properties": []any{Object{"name": "aquasecurity:trivy:PkgType", "value": kind}}}
	}
	for _, test := range []struct {
		name         string
		packages     []Object
		status       string
		count, tools int
	}{
		{"ordinary-alpine", []Object{component("busybox", "alpine"), component("apk-tools", "alpine")}, "not-distroless", 2, 2},
		{"distroless-package-inventory", []Object{component("base-files", "debian"), component("ca-certificates", "debian"), component("tzdata", "debian")}, "distroless-consistent", 3, 0},
		{"debug-shell-overrides-name", []Object{component("base-files", "debian"), component("busybox", "debian")}, "not-distroless", 2, 1},
		{"empty-is-not-distroless-proof", nil, "unknown", 0, 0},
		{"language-package-is-not-a-shell", []Object{component("bash", "npm")}, "unknown", 0, 0},
		{"unknown-ecosystem", []Object{component("libc", "unsupported")}, "unknown", 0, 0},
		{"duplicates", []Object{component("dash", "debian"), component("dash", "debian")}, "not-distroless", 1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			bom, err := json.Marshal(Object{"bomFormat": "CycloneDX", "metadata": Object{"component": Object{"name": "distroless-name-is-not-evidence", "properties": []any{Object{"name": "aquasecurity:trivy:RepoDigest", "value": digest}}}}, "components": test.packages})
			if err != nil {
				t.Fatal(err)
			}
			got := classifyImage(bom, "linux/arm64")
			if got.Status != test.status || got.OSPackages != test.count || len(got.Tools) != test.tools || got.Digest != digest || got.Platform != "linux/arm64" || got.Limitations == "" {
				t.Fatalf("unexpected evidence: %+v", got)
			}
		})
	}
	for _, invalid := range []string{`{`, `{"bomFormat":"not-CycloneDX"}`, `{}`} {
		if got := classifyImage(json.RawMessage(invalid), "linux/arm64"); got.Status != "unknown" {
			t.Fatalf("invalid report classified: %+v", got)
		}
	}
}
