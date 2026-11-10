package explorer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const trafficLifetime = 5 * time.Minute
const maxTrafficBytes = 16 * 1024 * 1024
const maxTrafficLines = 100000

func sidecarState(pod Object) (string, string) {
	if !podView(pod, Snapshot{}).Sidecar {
		return "absent", "istio-proxy isn't there. Live traffic is unavailable for this pod."
	}
	for _, key := range []string{"containerStatuses", "initContainerStatuses"} {
		for _, value := range arr(at(pod, "status", key)) {
			status := obj(value)
			if status["name"] == "istio-proxy" && at(status, "state", "running") != nil {
				return "", ""
			}
		}
	}
	return "unavailable", "istio-proxy is not running. Refresh after the sidecar starts."
}

func trafficReadFailure(w http.ResponseWriter, err error) {
	status, message := "unavailable", "Cannot read the pod or sidecar stream. Check the read-only proxy and refresh."
	var read readError
	if errors.As(err, &read) {
		switch read.status {
		case 401, 403:
			status, message = "denied", "Access denied. The reader needs get permission on pods and pods/log."
		case 404:
			status, message = "unavailable", "Pod or sidecar logs are no longer available. Refresh the pod inventory."
		}
	}
	writeJSON(w, 200, trafficView{Status: status, Message: message})
}

func (c *Client) openTrafficLog(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path+"/log?container=istio-proxy&follow=true&tailLines=0&limitBytes=16777216", nil)
	if err != nil {
		return nil, err
	}
	streamClient := *c.http
	streamClient.Timeout = 0
	response, err := streamClient.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, readError{status: response.StatusCode}
	}
	return response.Body, nil
}

func trafficHandler(client *Client) http.HandlerFunc {
	slots := make(chan struct{}, 4)
	return func(w http.ResponseWriter, r *http.Request) {
		ns, n := r.PathValue("namespace"), r.PathValue("name")
		if !validName(ns, true) || !validName(n, false) {
			problem(w, 400, "Invalid namespace or pod identifier")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			writeJSON(w, 429, trafficView{Status: "busy", Message: "Four traffic views are already open. Close one and retry."})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), trafficLifetime)
		defer cancel()
		path := "/api/v1/namespaces/" + ns + "/pods/" + n
		pod, err := client.get(ctx, path)
		if err != nil {
			trafficReadFailure(w, err)
			return
		}
		if expected := r.URL.Query().Get("uid"); expected == "" || expected != uid(pod) {
			writeJSON(w, 200, trafficView{Status: "replaced", Message: "The pod identity changed. Refresh the pod details before opening traffic."})
			return
		}
		if status, message := sidecarState(pod); status != "" {
			writeJSON(w, 200, trafficView{Status: status, Message: message})
			return
		}
		peers := client.list(ctx, resources[1], "")
		timer := time.AfterFunc(10*time.Second, cancel)
		body, err := client.openTrafficLog(ctx, path)
		timer.Stop()
		if err != nil {
			trafficReadFailure(w, err)
			return
		}
		defer body.Close()
		streamTraffic(ctx, w, body, newTrafficAggregate(pod, peers.Items))
	}
}

type trafficLine struct {
	record accessRecord
	valid  bool
	end    string
}

func readTrafficLines(ctx context.Context, body io.Reader, lines chan<- trafficLine) {
	defer close(lines)
	reader := &io.LimitedReader{R: body, N: maxTrafficBytes}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 16*1024)
	count := 0
	for count < maxTrafficLines && scanner.Scan() {
		count++
		record, valid := parseAccessRecord(scanner.Bytes())
		select {
		case lines <- trafficLine{record: record, valid: valid}:
		case <-ctx.Done():
			return
		}
	}
	end := "disconnected"
	if reader.N == 0 || count == maxTrafficLines || scanner.Err() != nil {
		end = "limited"
	}
	select {
	case lines <- trafficLine{end: end}:
	case <-ctx.Done():
	}
}

func writeTrafficEvent(w http.ResponseWriter, view trafficView) bool {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return false
	}
	data, err := json.Marshal(view)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return false
	}
	return controller.Flush() == nil
}

func streamTraffic(ctx context.Context, w http.ResponseWriter, body io.Reader, aggregate *trafficAggregate) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	lines := make(chan trafficLine, 32)
	go readTrafficLines(ctx, body, lines)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	idle := "Listening for new structured HTTP access logs. No requests observed yet; logging may be disabled or traffic may be idle."
	if !writeTrafficEvent(w, aggregate.snapshot("listening", idle)) {
		return
	}
	for {
		select {
		case <-ctx.Done():
			writeTrafficEvent(w, aggregate.snapshot("ended", "The five-minute session ended. Start a new session to keep observing."))
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			if line.end != "" {
				writeTrafficEvent(w, aggregate.snapshot(line.end, "The sidecar stream ended or reached its read limit. Start a new session to retry."))
				return
			}
			if line.valid {
				aggregate.add(line.record)
			} else {
				aggregate.view.Ignored++
			}
		case <-ticker.C:
			status, message := "listening", idle
			if aggregate.view.Requests > 0 {
				status, message = "live", "Observing completed HTTP requests involving this pod."
			}
			if !writeTrafficEvent(w, aggregate.snapshot(status, message)) {
				return
			}
		}
	}
}
