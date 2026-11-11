package explorer

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var digestImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-fA-F0-9]{64}$`)
var imageReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,999}$`)

type imageScan struct {
	ID             string               `json:"id"`
	UID            string               `json:"uid"`
	Image          string               `json:"image"`
	Status         string               `json:"status"`
	Message        string               `json:"message"`
	StartedAt      string               `json:"startedAt"`
	SBOM           json.RawMessage      `json:"sbom,omitempty"`
	Classification *imageClassification `json:"classification,omitempty"`
}

func workloadImages(o Object, s Snapshot) map[string]bool {
	result := map[string]bool{}
	pods := []Object{workloadTemplate(o)}
	for _, p := range s.items("pods") {
		if ownedBy(p, o, s) {
			pods = append(pods, p)
		}
	}
	for _, p := range pods {
		for _, c := range containerEvidence(p) {
			result[text(c["image"])] = true
			if image := text(c["observedImage"]); image != "" {
				result[image] = true
			}
		}
	}
	return result
}

func scanImage(ctx context.Context, image string) (json.RawMessage, error) {
	if !imageReference.MatchString(image) || strings.Contains(image, "://") {
		return nil, errors.New("Invalid image reference")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "trivy", "image", "--quiet", "--config", "", "--ignorefile", "", "--disable-telemetry", "--skip-version-check", "--timeout", "4m", "--scanners", "vuln", "--format", "cyclonedx", "--list-all-pkgs=true", "--platform", "linux/"+runtime.GOARCH, "--image-src", "remote", "--cache-backend", "memory", "--max-image-size", "1GB", "--parallel", "2", "--exit-code", "0", "--", image)
	output := &boundedOutput{limit: 8 * 1024 * 1024}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = output, io.Discard, time.Second
	if err := cmd.Run(); err != nil {
		return nil, errors.New("Trivy failed or exceeded its time/output limit. Check Trivy, registry access and vulnerability database connectivity locally.")
	}
	var document struct {
		BOMFormat string `json:"bomFormat"`
	}
	if json.Unmarshal(output.Bytes(), &document) != nil || document.BOMFormat != "CycloneDX" {
		return nil, errors.New("Trivy returned an invalid CycloneDX SBOM")
	}
	return append(json.RawMessage{}, output.Bytes()...), nil
}

func (store *registryStore) startScan(w http.ResponseWriter, ctx context.Context, input registryRequest, o Object) {
	s := store.client.snapshot(ctx, namespace(o), false)
	if !workloadImages(o, s)[input.Image] || !imageReference.MatchString(input.Image) {
		problem(w, 400, "Select an image from this workload template or its UID-owned Pods")
		return
	}
	if _, err := exec.LookPath("trivy"); err != nil {
		problem(w, 503, "Trivy is not installed on the Peeker host. Install trivy and retry.")
		return
	}
	store.mu.Lock()
	if store.scanRunning || len(store.scans) >= 8 {
		store.mu.Unlock()
		problem(w, 429, "One scan may run at a time; at most eight results are retained per context session")
		return
	}
	scan := &imageScan{ID: rand.Text(), UID: input.UID, Image: input.Image, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339), Message: "Scanning registry image. Tags may move; prefer an observed digest. Multi-platform references use the Peeker host platform. Results stay in this context session."}
	store.scans[scan.ID] = scan
	store.scanRunning = true
	response := *scan
	store.mu.Unlock()
	go func() {
		bom, err := scanImage(store.client.ctx, input.Image)
		store.mu.Lock()
		defer store.mu.Unlock()
		store.scanRunning = false
		if err != nil {
			scan.Status, scan.Message = "error", err.Error()
			return
		}
		scan.Status, scan.Message, scan.SBOM = "complete", "Trivy CycloneDX SBOM with vulnerability evidence. Review fixed versions and rebuild affected images.", bom
		classification := classifyImage(bom, "linux/"+runtime.GOARCH)
		scan.Classification = &classification
	}()
	writeJSON(w, 202, response)
}

func (store *registryStore) scanResult(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	defer store.mu.Unlock()
	scan := store.scans[r.URL.Query().Get("id")]
	if scan == nil {
		problem(w, 404, "Scan not found in this context session")
		return
	}
	writeJSON(w, 200, scan)
}
