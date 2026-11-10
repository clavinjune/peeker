package explorer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func inventoryFixture(t *testing.T, count int) (*Client, *atomic.Int64, *sync.Map) {
	t.Helper()
	version := &atomic.Int64{}
	paths := &sync.Map{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("upstream mutation", r.Method)
		}
		hits, _ := paths.LoadOrStore(r.URL.Path, &atomic.Int64{})
		hits.(*atomic.Int64).Add(1)
		if strings.HasSuffix(r.URL.Path, "/v1") || strings.HasSuffix(r.URL.Path, "/v2") {
			entries := []any{}
			for _, resource := range resources {
				entries = append(entries, map[string]string{"name": resource.plural})
			}
			writeJSON(w, 200, map[string]any{"resources": entries})
			return
		}
		items := []any{}
		if strings.HasSuffix(r.URL.Path, "/pods") {
			for i := 0; i < count; i++ {
				items = append(items, Object{"metadata": Object{"name": fmt.Sprintf("pod-%03d-v%d", i, version.Load()), "namespace": "default", "uid": fmt.Sprintf("uid-%d", i)}, "spec": Object{"containers": []any{Object{"name": "app", "securityContext": Object{"privileged": i == count-1}}}}})
			}
		}
		if r.URL.Path == "/api/v1/namespaces" {
			items = append(items, Object{"metadata": Object{"name": "default"}})
		}
		writeJSON(w, 200, map[string]any{"items": items})
	}))
	t.Cleanup(proxy.Close)
	client, err := NewClient(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, version, paths
}

func inventoryRequest(t *testing.T, handler http.Handler, query string) inventoryPage {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/pods?"+query, nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var page inventoryPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func completedInventory(t *testing.T, handler http.Handler, page inventoryPage) inventoryPage {
	t.Helper()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for page.Status != "complete" {
		if page.Status == "error" {
			t.Fatal(page.Message)
		}
		select {
		case <-deadline:
			t.Fatal("inventory did not complete")
		case <-tick.C:
		}
		page = inventoryRequest(t, handler, "snapshot="+page.Snapshot+"&limit=100")
	}
	return page
}

func TestInventoryStablePagesRefreshAndHiddenSummaries(t *testing.T) {
	client, version, paths := inventoryFixture(t, 130)
	handler := MCPHandler(Handler(client, nil))
	first := completedInventory(t, handler, inventoryRequest(t, handler, ""))
	if first.Total != 130 || len(first.Pods) != 100 || first.Pods[0].Risk.Level != "critical" || first.Summary.Critical != 1 {
		t.Fatalf("bad first page: %+v", first.Summary)
	}
	second := inventoryRequest(t, handler, "snapshot="+first.Snapshot+"&offset=100")
	seen := map[string]bool{}
	for _, p := range append(first.Pods, second.Pods...) {
		if seen[p.Name] {
			t.Fatal("duplicate page row", p.Name)
		}
		seen[p.Name] = true
	}
	if len(seen) != 130 || second.HasMore {
		t.Fatal("incomplete traversal", len(seen))
	}
	if _, found := paths.Load("/api/v1/pods"); found {
		t.Fatal("default inventory read all namespaces")
	}
	reads, _ := paths.Load("/api/v1/namespaces/default/pods")
	if reads.(*atomic.Int64).Load() != 1 {
		t.Fatal("pages refetched inventory")
	}
	q := inventoryQuery{Namespace: "default", Snapshot: first.Snapshot, Hidden: []string{workloadKey(first.Pods[0])}, Limit: 100}
	body, _ := json.Marshal(q)
	r := httptest.NewRequest("POST", "http://127.0.0.1/api/pods/query", strings.NewReader(string(body)))
	r.Header.Set("Origin", "http://127.0.0.1")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Peeker-Action", "query-pods")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var hidden inventoryPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &hidden) != nil || hidden.Total != 129 || hidden.Summary.Critical != 0 || hidden.Hidden != 1 {
		t.Fatal("hidden summary", w.Code, w.Body.String())
	}
	version.Store(1)
	fresh := completedInventory(t, handler, inventoryRequest(t, handler, "refresh=true"))
	if fresh.Snapshot == first.Snapshot || !strings.HasSuffix(fresh.Pods[0].Name, "-v1") {
		t.Fatal("refresh reused stale snapshot")
	}
	old := inventoryRequest(t, handler, "snapshot="+first.Snapshot)
	if !reflect.DeepEqual(first.Pods, old.Pods) {
		t.Fatal("refresh changed a pinned snapshot")
	}
	other := Handler(mustClient(t, "http://127.0.0.1:1"), nil)
	w = httptest.NewRecorder()
	other.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/pods?snapshot="+first.Snapshot, nil))
	if w.Code != 410 {
		t.Fatal("snapshot crossed client/context boundary", w.Code)
	}
}

func mustClient(t *testing.T, proxy string) *Client {
	t.Helper()
	client, err := NewClient(proxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestPendingAssessmentAndQueryBoundaries(t *testing.T) {
	s := securitySnapshot()
	s["pods"] = available(hardenedPod(t))
	job := &inventoryJob{}
	job.prepare(s)
	pending := job.page(inventoryQuery{Limit: 100})
	if pending.Summary.Pending != 1 || pending.Pods[0].Risk.Level != "pending" || pending.Status != "assessing" {
		t.Fatal("pending represented as assessed", pending)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	job.assess(ctx, s, AssessmentOptions{ExpectIstio: true})
	if job.page(inventoryQuery{Limit: 100}).Status != "error" {
		t.Fatal("cancellation marked complete")
	}
	handler := Handler(mustClient(t, "http://127.0.0.1:1"), nil)
	for _, query := range []string{"offset=1", "limit=501", "offset=-1", "namespace=..", "namespace=default&all=true", "snapshot=old&refresh=true", "limit=oops"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/pods?"+query, nil))
		if w.Code != 400 {
			t.Fatal(query, w.Code)
		}
	}
	q, err := parseInventoryQuery(httptest.NewRecorder(), httptest.NewRequest("GET", "http://127.0.0.1/api/pods?all=true", nil))
	if err != nil || q.Namespace != "" || !q.All {
		t.Fatal("explicit all scope", q, err)
	}
}

func TestCollectionDeduplicationCancellationAndExpiry(t *testing.T) {
	client, _, paths := inventoryFixture(t, 1)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			c := client.cachedList(context.Background(), resources[1], "default")
			if c.State.Status != "available" {
				t.Error(c.State)
			}
		})
	}
	wg.Wait()
	reads, _ := paths.Load("/api/v1/namespaces/default/pods")
	if reads.(*atomic.Int64).Load() != 1 {
		t.Fatal("concurrent cache misses were not deduplicated")
	}
	client.cacheMu.Lock()
	client.cache["pods/default"].expires = time.Now().Add(-time.Second)
	client.cacheMu.Unlock()
	client.cachedList(context.Background(), resources[1], "default")
	if reads.(*atomic.Int64).Load() != 2 {
		t.Fatal("expired entry reused")
	}
	client.Close()
	if c := client.cachedList(context.Background(), resources[1], "other"); c.State.Status == "available" {
		t.Fatal("closed context admitted new reads")
	}
}

func TestIndexesPreserveRBACAndScopedPeerUncertainty(t *testing.T) {
	pod, s := hardenedPod(t), securitySnapshot()
	s["namespaces"] = available(Object{"metadata": Object{"name": "demo"}})
	s["pods"] = indexCollection(available(pod), "demo")
	s["roles"] = available(fixture(t, `{"kind":"Role","metadata":{"namespace":"other","name":"reader"},"rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]}`))
	s["rolebindings"] = available(fixture(t, `{"kind":"RoleBinding","metadata":{"namespace":"other","name":"binding"},"subjects":[{"kind":"ServiceAccount","name":"app","namespace":"demo"},{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"system:authenticated"}],"roleRef":{"kind":"Role","apiGroup":"rbac.authorization.k8s.io","name":"reader"}}`))
	before := assessPod(pod, s)
	s = indexedSnapshot(s)
	if after := assessPod(pod, s); !reflect.DeepEqual(before, after) {
		t.Fatal("index changed assessment")
	}
	_, description, err := cachedPeerDescription(Object{"namespaceSelector": Object{}}, "demo", s)
	if err == nil || !strings.Contains(description, "cross-namespace") {
		t.Fatal("scoped inventory claimed complete peers", description)
	}
	if _, _, err = cachedPeerDescription(Object{"podSelector": Object{}}, "demo", s); err != nil {
		t.Fatal("namespace-local peer was made unknown", err)
	}
	if value, ok := s.find("roles", "other", "reader"); !ok || name(value) != "reader" {
		t.Fatal("indexed lookup failed")
	}
}

func TestInventoryOrderingAcrossPages(t *testing.T) {
	job := &inventoryJob{status: "complete", pods: []PodView{
		{Ref: Ref{Namespace: "demo", Name: "clean"}, Risk: RiskSummary{Level: "none"}},
		{Ref: Ref{Namespace: "demo", Name: "partial"}, Risk: RiskSummary{Level: "unknown", Unknown: 6}},
		{Ref: Ref{Namespace: "demo", Name: "high"}, Risk: RiskSummary{Level: "high", Score: 55}},
		{Ref: Ref{Namespace: "demo", Name: "critical"}, Risk: RiskSummary{Level: "critical", Score: 80}},
	}}
	for mode, want := range map[string][]string{
		"risk":   {"critical", "high", "partial", "clean"},
		"review": {"partial", "critical", "high", "clean"},
		"name":   {"clean", "critical", "high", "partial"},
	} {
		got := []string{}
		for offset := 0; offset < 4; offset += 2 {
			page := job.page(inventoryQuery{Sort: mode, Offset: offset, Limit: 2})
			for _, p := range page.Pods {
				got = append(got, p.Name)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal(mode, got, want)
		}
	}
	if job.pods[0].Name != "clean" {
		t.Fatal("sorting mutated the snapshot")
	}
}

func TestInventorySnapshotExpiryEvictionAndScope(t *testing.T) {
	client, _, _ := inventoryFixture(t, 0)
	store := &inventoryStore{client: client, jobs: map[string]*inventoryJob{}}
	for i := range 4 {
		id := fmt.Sprint(i)
		store.jobs[id] = &inventoryJob{id: id, namespace: "default", status: "loading", created: time.Now().Add(time.Duration(i-4) * time.Second), expires: time.Now().Add(time.Minute), cancel: func() {}}
	}
	if _, code, _ := store.job(inventoryQuery{Namespace: "other"}); code != 429 {
		t.Fatal("active job cap", code)
	}
	store.jobs["0"].status = "complete"
	job, code, err := store.job(inventoryQuery{Namespace: "other"})
	if code != 200 || err != nil {
		t.Fatal(code, err)
	}
	t.Cleanup(func() { job.cancel(); job.timer.Stop() })
	if len(store.jobs) != 4 || store.jobs["0"] != nil {
		t.Fatal("oldest completed snapshot was not evicted")
	}
	for _, q := range []inventoryQuery{{Namespace: "default", Snapshot: "0"}, {Namespace: "other", Snapshot: "1"}} {
		if _, code, _ := store.job(q); code != 410 {
			t.Fatal("evicted or wrong scope accepted", q, code)
		}
	}
	store.jobs["1"].expires = time.Now().Add(-time.Second)
	if _, code, _ := store.job(inventoryQuery{Namespace: "default", Snapshot: "1"}); code != 410 {
		t.Fatal("expired snapshot accepted", code)
	}
	client.Close()
	if _, code, _ := store.job(inventoryQuery{Namespace: "other"}); code != 503 {
		t.Fatal("closed client accepted a job", code)
	}
}
