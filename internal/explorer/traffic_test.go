package explorer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func trafficPod(name, ip string, native bool) Object {
	containers := []any{map[string]any{"name": "app"}}
	sidecar := map[string]any{"name": "istio-proxy", "restartPolicy": "Always"}
	spec := Object{"containers": containers}
	status := Object{"podIP": ip}
	key, statusKey := "containers", "containerStatuses"
	if native {
		key, statusKey = "initContainers", "initContainerStatuses"
	}
	spec[key] = append(arr(spec[key]), sidecar)
	status[statusKey] = []any{map[string]any{"name": "istio-proxy", "state": map[string]any{"running": map[string]any{}}}}
	return Object{"kind": "Pod", "metadata": map[string]any{"name": name, "namespace": "demo", "uid": name + "-uid"}, "spec": spec, "status": status}
}

func TestAccessLogParsingAndRedaction(t *testing.T) {
	valid := `{"start_time":"2026-11-10T12:00:00.001Z","upstream_cluster":"outbound|80||peer.demo.svc.cluster.local","upstream_host":"10.0.0.2:80","downstream_direct_remote_address":"10.0.0.1:1234","protocol":"HTTP/2","response_code":503,"response_flags":"UF","duration":12.5,"path":"/secret?token=sensitive-value","authorization":"Bearer sensitive-value"}`
	record, ok := parseAccessRecord([]byte(valid))
	if !ok || record.Code != 503 || record.Duration != 12.5 {
		t.Fatal(record, ok)
	}
	a := newTrafficAggregate(trafficPod("selected", "10.0.0.1", true), []Object{trafficPod("peer", "10.0.0.2", false)})
	a.add(record)
	view := a.snapshot("live", "")
	if view.Requests != 1 || view.Errors != 1 || len(view.Graph.Edges) != 1 || strings.Contains(jsonText(view), "sensitive-value") || strings.Contains(jsonText(view), "authorization") {
		t.Fatal(view)
	}
	for _, line := range []string{"startup", `{}`, `{"level":"info"}`, strings.Replace(valid, "HTTP/2", "TCP", 1), strings.Replace(valid, "12.5", "-1", 1), strings.Replace(valid, "12.5", "1e999", 1), strings.Replace(valid, "outbound|", "PassthroughCluster", 1), strings.Replace(valid, "503", `"503"`, 1), strings.Replace(valid, `"duration":12.5,`, "", 1), strings.Replace(valid, "503", "null", 1)} {
		if _, ok := parseAccessRecord([]byte(line)); ok {
			t.Fatalf("accepted unsupported record: %s", line)
		}
	}
}

func TestTrafficAttributionDirectionAndBounds(t *testing.T) {
	selected := trafficPod("selected", "10.0.0.1", true)
	peers := []Object{trafficPod("caller", "2001:db8::2", false), trafficPod("shared-a", "10.0.0.3", false), trafficPod("shared-b", "10.0.0.3", false)}
	for i := 1; i <= 70; i++ {
		peers = append(peers, trafficPod(fmt.Sprintf("peer-%d", i), fmt.Sprintf("10.1.0.%d", i), false))
	}
	a := newTrafficAggregate(selected, peers)
	a.add(accessRecord{Cluster: "inbound|80||", Remote: "[2001:db8::2]:1234", Code: 200, Duration: 4})
	a.add(accessRecord{Cluster: "outbound|80||", Upstream: "10.0.0.3:80", Code: 404})
	a.add(accessRecord{Cluster: "outbound|80||", Upstream: "untrusted.example:80", Code: 200})
	view := a.snapshot("live", "")
	if len(view.Graph.Edges) != 2 || !strings.Contains(jsonText(view), `"from":"Pod/demo/caller"`) || strings.Contains(jsonText(view), "shared-a") || strings.Contains(jsonText(view), "untrusted.example") {
		t.Fatal(jsonText(view))
	}
	for i := 1; i <= 70; i++ {
		a.add(accessRecord{Cluster: "outbound|80||", Upstream: fmt.Sprintf("10.1.0.%d:80", i), Code: 200})
	}
	if len(a.edges) != maxTrafficEdges || a.view.Dropped != 8 || len(a.snapshot("live", "").Graph.Nodes) > maxTrafficEdges+1 {
		t.Fatal(len(a.edges), a.view.Dropped)
	}
}

func TestSidecarAvailability(t *testing.T) {
	for _, native := range []bool{true, false} {
		pod := trafficPod("selected", "10.0.0.1", native)
		if state, _ := sidecarState(pod); state != "" {
			t.Fatal(native, state)
		}
		pod["status"] = Object{}
		if state, _ := sidecarState(pod); state != "unavailable" {
			t.Fatal(state)
		}
	}
	pod := trafficPod("selected", "10.0.0.1", true)
	pod["spec"] = Object{"containers": []any{map[string]any{"name": "app"}}, "initContainers": []any{map[string]any{"name": "istio-proxy"}}}
	if state, message := sidecarState(pod); state != "absent" || !strings.Contains(message, "isn't there") {
		t.Fatal(state, message)
	}
}

func TestTrafficPreflightAndReadOnlyPath(t *testing.T) {
	for _, test := range []struct{ mode, want string }{{"absent", "absent"}, {"waiting", "unavailable"}, {"deleted", "unavailable"}, {"denied", "denied"}, {"replaced", "replaced"}, {"logs-denied", "denied"}} {
		t.Run(test.mode, func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("mutating request")
				}
				switch r.URL.Path {
				case "/api/v1/namespaces/demo/pods/selected":
					if test.mode == "deleted" {
						w.WriteHeader(404)
						return
					}
					if test.mode == "denied" {
						w.WriteHeader(403)
						w.Write([]byte("sensitive-value"))
						return
					}
					pod := trafficPod("selected", "10.0.0.1", true)
					if test.mode == "absent" {
						pod["spec"] = Object{}
					}
					if test.mode == "waiting" {
						pod["status"] = Object{}
					}
					if test.mode == "replaced" {
						obj(pod["metadata"])["uid"] = "new-uid"
					}
					json.NewEncoder(w).Encode(pod)
				case "/api/v1":
					w.Write([]byte(`{"resources":[{"name":"pods"}]}`))
				case "/api/v1/pods":
					w.Write([]byte(`{"items":[]}`))
				case "/api/v1/namespaces/demo/pods/selected/log":
					if test.mode != "logs-denied" || r.URL.Query().Get("container") != "istio-proxy" || r.URL.Query().Get("tailLines") != "0" {
						t.Error("unexpected log request", r.URL)
					}
					w.WriteHeader(403)
				default:
					t.Error("unexpected path", r.URL)
				}
			}))
			defer proxy.Close()
			client, _ := NewClient(proxy.URL)
			w := httptest.NewRecorder()
			Handler(client, nil).ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/pods/demo/selected/traffic?uid=selected-uid", nil))
			var result trafficView
			json.Unmarshal(w.Body.Bytes(), &result)
			if result.Status != test.want || strings.Contains(w.Body.String(), "sensitive-value") {
				t.Fatal(w.Body.String())
			}
		})
	}
}

func TestTrafficStreamCancellationAndCapacity(t *testing.T) {
	var streams atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/demo/pods/selected":
			json.NewEncoder(w).Encode(trafficPod("selected", "10.0.0.1", true))
		case "/api/v1":
			w.Write([]byte(`{"resources":[{"name":"pods"}]}`))
		case "/api/v1/pods":
			w.Write([]byte(`{"items":[]}`))
		case "/api/v1/namespaces/demo/pods/selected/log":
			streams.Add(1)
			defer streams.Add(-1)
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			t.Error(r.URL)
		}
	}))
	defer proxy.Close()
	client, _ := NewClient(proxy.URL)
	server := httptest.NewServer(Handler(client, nil))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bodies := []io.ReadCloser{}
	for i := 0; i < 4; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/pods/demo/selected/traffic?uid=selected-uid", nil)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, response.Body)
		defer response.Body.Close()
		line, err := bufio.NewReader(response.Body).ReadString('\n')
		if err != nil || !strings.Contains(line, `"status":"listening"`) {
			t.Fatal(line, err)
		}
	}
	response, err := http.Get(server.URL + "/api/pods/demo/selected/traffic?uid=selected-uid")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 429 || streams.Load() != 4 {
		t.Fatal(response.StatusCode, streams.Load())
	}
	for _, body := range bodies {
		body.Close()
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for streams.Load() != 0 {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("upstream logs not canceled")
		}
	}
}

func TestTrafficScannerLimitsAndFinalAggregate(t *testing.T) {
	for _, input := range []string{strings.Repeat("x", 17*1024), strings.Repeat("{}\n", maxTrafficLines+1)} {
		lines := make(chan trafficLine, 32)
		go readTrafficLines(context.Background(), strings.NewReader(input), lines)
		last := trafficLine{}
		for line := range lines {
			last = line
		}
		if last.end != "limited" {
			t.Fatal(last)
		}
	}
	w := httptest.NewRecorder()
	a := newTrafficAggregate(trafficPod("selected", "10.0.0.1", true), nil)
	record := accessRecord{Start: "2026-11-10T12:00:00Z", Cluster: "inbound|80||", Protocol: "HTTP/1.1", Code: 200}
	streamTraffic(context.Background(), w, strings.NewReader(jsonText(record)+"\n"), a)
	if !strings.Contains(w.Body.String(), `"requests":1`) || !strings.Contains(w.Body.String(), `"status":"disconnected"`) {
		t.Fatal(w.Body.String())
	}
}
