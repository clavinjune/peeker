package explorer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type registryWrite struct {
	method, path string
	body         json.RawMessage
}

func registryFixture(t *testing.T) (Object, Snapshot) {
	t.Helper()
	workload := fixture(t, `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web","namespace":"demo","uid":"workload-1","resourceVersion":"1"},"spec":{"template":{"metadata":{"labels":{"app":"web"}},"spec":{"serviceAccountName":"app","containers":[{"name":"app","image":"alpine:3.22","env":[{"name":"PRIVATE","value":"synthetic-do-not-export"},{"name":"TOKEN","valueFrom":{"secretKeyRef":{"name":"app-secret","key":"token"}}}],"envFrom":[{"configMapRef":{"name":"settings"}}]}]}}}}`)
	rs := fixture(t, `{"kind":"ReplicaSet","metadata":{"name":"web-rs","namespace":"demo","uid":"rs-1","resourceVersion":"1","ownerReferences":[{"kind":"Deployment","name":"web","uid":"workload-1","controller":true}]},"spec":{"template":{"spec":{"serviceAccountName":"app"}}}}`)
	pod := fixture(t, `{"kind":"Pod","metadata":{"name":"web-pod","namespace":"demo","uid":"pod-1","resourceVersion":"1","labels":{"app":"web"},"ownerReferences":[{"kind":"ReplicaSet","name":"web-rs","uid":"rs-1","controller":true}]},"spec":{"serviceAccountName":"app","containers":[{"name":"app","image":"alpine:3.22","securityContext":{"privileged":true}},{"name":"istio-proxy","image":"proxy:1"}]}}`)
	cep := fixture(t, `{"kind":"CiliumEndpoint","metadata":{"name":"web-pod","namespace":"demo","ownerReferences":[{"kind":"Pod","uid":"pod-1"}]}}`)
	role := fixture(t, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"app-role","namespace":"demo","uid":"role-1","resourceVersion":"1"},"rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["get"]}]}`)
	binding := fixture(t, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"app-binding","namespace":"demo","uid":"binding-1","resourceVersion":"1"},"subjects":[{"kind":"ServiceAccount","name":"app","namespace":"demo"}],"roleRef":{"kind":"Role","name":"app-role","apiGroup":"rbac.authorization.k8s.io"}}`)
	s := Snapshot{}
	for _, r := range resources {
		s[r.key] = Collection{State: State{r.key, "available", ""}, Items: []Object{}}
	}
	s["deployments"], s["replicasets"], s["pods"], s["ciliumendpoints"], s["roles"], s["rolebindings"] = available(workload), available(rs), available(pod), available(cep), available(role), available(binding)
	return workload, s
}

func registryProxy(t *testing.T, s Snapshot, onWrite func(registryWrite) int) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			var body json.RawMessage
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid write body")
			}
			status := 200
			if onWrite != nil {
				status = onWrite(registryWrite{r.Method, r.URL.Path, body})
			}
			writeJSON(w, status, Object{})
			return
		}
		for _, res := range resources {
			base := resourcePath(res, "demo", "")
			if r.URL.Path == base || r.URL.Path == strings.Replace(base, "/namespaces/demo", "", 1) {
				writeJSON(w, 200, Object{"items": s.items(res.key)})
				return
			}
			for _, o := range s.items(res.key) {
				if r.URL.Path == resourcePath(res, namespace(o), name(o)) {
					writeJSON(w, 200, o)
					return
				}
			}
		}
		if strings.HasSuffix(r.URL.Path, "/v1") || strings.HasSuffix(r.URL.Path, "/v2") {
			list := []Object{}
			for _, res := range resources {
				list = append(list, Object{"name": res.plural})
			}
			writeJSON(w, 200, Object{"resources": list})
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(server.Close)
	c, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func registryHTTPRequest(handler http.Handler, body, generation string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/registry/change", strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Peeker-Action", "registry")
	r.Header.Set("X-Peeker-Context", generation)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestRegistryRegistrationUIDBoundaryAndIsolation(t *testing.T) {
	o, s := registryFixture(t)
	c := registryProxy(t, s, func(registryWrite) int { t.Error("registration mutated Kubernetes"); return 500 })
	store := newRegistry(c)
	mux := http.NewServeMux()
	store.mount(mux)
	handler := MCPHandler(localBoundary(mux, "/api/registry/change"))
	input := registryRequest{Operation: "register", Kind: "Deployment", Namespace: "demo", Name: "web", UID: uid(o)}
	for _, test := range []struct {
		change     func(*registryRequest)
		generation string
		status     int
	}{
		{func(*registryRequest) {}, "", 403},
		{func(i *registryRequest) { i.Kind = "Pod" }, "external", 409},
		{func(i *registryRequest) { i.UID = "old-uid" }, "external", 409},
		{func(i *registryRequest) { i.Name = "../web" }, "external", 409},
		{func(*registryRequest) {}, "external", 200},
	} {
		v := input
		test.change(&v)
		w := registryHTTPRequest(handler, jsonText(v), test.generation)
		if w.Code != test.status {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
	}
	if len(store.entries) != 1 || len(newRegistry(c).entries) != 0 {
		t.Fatal("registration not session-local")
	}
	input.Operation = "kill"
	if w := registryHTTPRequest(handler, jsonText(input), "external"); w.Code != 403 {
		t.Fatalf("external proxy accepted action: %d %s", w.Code, w.Body.String())
	}
	request := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/registry/change", strings.NewReader(jsonText(input)))
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 403 {
		t.Fatal("missing Origin accepted")
	}
}

func TestRegistryContextSwitchRejectsStaleChanges(t *testing.T) {
	_, s := registryFixture(t)
	c := registryProxy(t, s, nil)
	m := NewContextManager(nil)
	defer m.Close()
	m.runner = fixtureRunner{urls: map[string]string{"one": c.base, "two": c.base}}
	if err := m.Select(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}
	generation := m.Info().Generation
	body := `{"operation":"register","kind":"Deployment","namespace":"demo","name":"web","uid":"workload-1"}`
	if w := registryHTTPRequest(m.Handler(), body, generation); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if err := m.Select(context.Background(), "two"); err != nil {
		t.Fatal(err)
	}
	if w := registryHTTPRequest(m.Handler(), body, generation); w.Code != 409 {
		t.Fatal("stale context accepted", w.Code)
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/registry?namespace=demo", nil)
	r.Header.Set("X-Peeker-Context", m.Info().Generation)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"registered":false`) {
		t.Fatal("registration leaked across contexts", w.Body.String())
	}
}

func TestRegistryEvidenceSeparatesAdmissionAndRedactsValues(t *testing.T) {
	o, s := registryFixture(t)
	report := workloadReport(o, s, AssessmentOptions{}, true, false)
	encoded := jsonText(report)
	if strings.Contains(encoded, "synthetic-do-not-export") || !strings.Contains(encoded, "app-secret") || !strings.Contains(encoded, "settings") {
		t.Fatal("reference curation failed")
	}
	pods := report["pods"].([]Object)
	if len(pods) != 1 || !pods[0]["pod"].(PodView).Sidecar || obj(report["template"])["pod"].(PodView).Sidecar {
		t.Fatal("template and live Pod evidence conflated")
	}
	obj(at(s.items("pods")[0], "metadata"))["ownerReferences"] = []any{Object{"kind": "ReplicaSet", "name": "web-rs", "uid": "stale", "controller": true}}
	if len(workloadReport(o, s, AssessmentOptions{}, true, false)["pods"].([]Object)) != 0 {
		t.Fatal("stale owner accepted")
	}
}

func TestContainmentCurrentPodsAndBackupBeforeMutations(t *testing.T) {
	o, s := registryFixture(t)
	var writes []registryWrite
	var mu sync.Mutex
	var store *registryStore
	c := registryProxy(t, s, func(write registryWrite) int {
		store.mu.Lock()
		count := len(store.backups)
		store.mu.Unlock()
		if count != 1 {
			t.Error("mutation occurred before backup")
		}
		mu.Lock()
		writes = append(writes, write)
		mu.Unlock()
		return 200
	})
	store = newRegistry(c)
	result := actionResult{Steps: []string{}}
	if err := store.contain(context.Background(), c, o, &result); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 3 || writes[0].method != "POST" || writes[1].method != "PATCH" || writes[2].method != "DELETE" || !strings.HasSuffix(writes[2].path, "rolebindings/app-binding") {
		t.Fatalf("unexpected mutations: %+v", writes)
	}
	var policy Object
	json.Unmarshal(writes[0].body, &policy)
	token := text(at(policy, "spec", "endpointSelector", "matchLabels", "peeker.dev/containment"))
	if token == "" || !strings.Contains(string(writes[0].body), "ingressDeny") || !strings.Contains(string(writes[0].body), "egressDeny") {
		t.Fatal("deny policy missing")
	}
	patch := string(writes[1].body)
	if !strings.Contains(patch, token) || !strings.Contains(patch, "/metadata/uid") || !strings.Contains(patch, "/metadata/resourceVersion") || strings.Contains(patch, `"/spec`) {
		t.Fatal("Pod patch must only change labels with identity checks", patch)
	}
	backup := store.backups[result.Backup]
	if !strings.Contains(backup, `"kind": "Role"`) || !strings.Contains(backup, `"kind": "RoleBinding"`) {
		t.Fatal("RBAC YAML incomplete", backup)
	}
}

func TestContainmentRefusesIncompleteUnsupportedAndHostNetwork(t *testing.T) {
	for _, scenario := range []string{"missing-cilium", "stale-endpoint", "host-network", "incomplete-rbac"} {
		t.Run(scenario, func(t *testing.T) {
			o, s := registryFixture(t)
			switch scenario {
			case "missing-cilium":
				s["ciliumendpoints"] = Collection{State: State{Status: "missing-api"}}
			case "stale-endpoint":
				obj(at(s.items("ciliumendpoints")[0], "metadata"))["ownerReferences"] = []any{}
			case "host-network":
				obj(at(s.items("pods")[0], "spec"))["hostNetwork"] = true
			case "incomplete-rbac":
				s["clusterrolebindings"] = Collection{State: State{Status: "denied"}}
			}
			if _, err := containmentPods(o, s); err == nil {
				t.Fatal("unsafe containment accepted")
			}
		})
	}
}

func TestRevocationPreservesSharedIdentitiesAndSubjects(t *testing.T) {
	for _, scenario := range []string{"shared-pod", "shared-controller", "mixed-subjects", "group"} {
		t.Run(scenario, func(t *testing.T) {
			o, s := registryFixture(t)
			binding := s.items("rolebindings")[0]
			switch scenario {
			case "shared-pod":
				s["pods"] = available(append(s.items("pods"), fixture(t, `{"kind":"Pod","metadata":{"name":"other","namespace":"demo","uid":"other"},"spec":{"serviceAccountName":"app"}}`))...)
			case "shared-controller":
				s["statefulsets"] = available(fixture(t, `{"kind":"StatefulSet","metadata":{"name":"other","namespace":"demo","uid":"other"},"spec":{"template":{"spec":{"serviceAccountName":"app"}}}}`))
			case "mixed-subjects":
				binding["subjects"] = append(arr(binding["subjects"]), Object{"kind": "ServiceAccount", "name": "other", "namespace": "demo"})
			case "group":
				binding["subjects"] = []any{Object{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"}}
			}
			writes := []registryWrite{}
			c := registryProxy(t, s, func(w registryWrite) int { writes = append(writes, w); return 200 })
			result := actionResult{}
			if err := revokeDirectBindings(context.Background(), c, o, s, &result); err != nil {
				t.Fatal(err)
			}
			if scenario == "mixed-subjects" {
				if len(writes) != 1 || writes[0].method != "PATCH" || !strings.Contains(string(writes[0].body), `"name":"other"`) {
					t.Fatal("other subject lost", writes)
				}
			} else if len(writes) != 0 {
				t.Fatal("shared permission revoked", writes)
			}
		})
	}
}

func TestDeletionPreconditionsAndOrphanControllerChain(t *testing.T) {
	o, s := registryFixture(t)
	writes := []registryWrite{}
	c := registryProxy(t, s, func(w registryWrite) int { writes = append(writes, w); return 200 })
	store := newRegistry(c)
	result := actionResult{}
	if err := store.orphan(context.Background(), c, o, &result); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 2 || !strings.HasSuffix(writes[0].path, "deployments/web") || !strings.HasSuffix(writes[1].path, "replicasets/web-rs") {
		t.Fatal("incomplete controller chain", writes)
	}
	for _, w := range writes {
		if !strings.Contains(string(w.body), `"propagationPolicy":"Orphan"`) || !strings.Contains(string(w.body), `"resourceVersion":"1"`) {
			t.Fatal("missing orphan/identity preconditions")
		}
	}
	obj(o["metadata"])["resourceVersion"] = ""
	if err := deleteObject(context.Background(), c, o, "Foreground"); err == nil || len(writes) != 2 {
		t.Fatal("unchecked deletion")
	}
	obj(o["metadata"])["resourceVersion"] = "1"
	if err := deleteObject(context.Background(), c, o, "Foreground"); err != nil || len(writes) != 3 || !strings.Contains(string(writes[2].body), `"propagationPolicy":"Foreground"`) {
		t.Fatal("kill-switch did not request foreground garbage collection", err)
	}
}

func TestRegistryControllerKindsAndCronJobOrphan(t *testing.T) {
	o, s := registryFixture(t)
	for _, kind := range registryKinds {
		copy := fixture(t, jsonText(o))
		copy["kind"] = kind
		if kind == "CronJob" {
			copy["spec"] = Object{"jobTemplate": Object{"spec": Object{"template": at(o, "spec", "template")}}}
		}
		if len(containerEvidence(workloadTemplate(copy))) != 1 {
			t.Fatal("template not recognized", kind)
		}
		if _, ok := registryResource(kind); !ok {
			t.Fatal("controller not registrable", kind)
		}
	}
	cron := fixture(t, `{"kind":"CronJob","metadata":{"name":"daily","namespace":"demo","uid":"cron-1","resourceVersion":"1"}}`)
	job := fixture(t, `{"kind":"Job","metadata":{"name":"run","namespace":"demo","uid":"job-1","resourceVersion":"1","ownerReferences":[{"kind":"CronJob","name":"daily","uid":"cron-1","controller":true}]}}`)
	s["cronjobs"], s["jobs"] = available(cron), available(job)
	writes := []registryWrite{}
	c := registryProxy(t, s, func(w registryWrite) int { writes = append(writes, w); return 200 })
	if err := newRegistry(c).orphan(context.Background(), c, cron, &actionResult{}); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 2 || !strings.HasSuffix(writes[1].path, "jobs/run") {
		t.Fatal("CronJob left an intermediate Job", writes)
	}
}

func TestContainmentRetryKeepsExistingSelectionAndTargetsReplacement(t *testing.T) {
	_, s := registryFixture(t)
	existing := s.items("pods")[0]
	obj(at(existing, "metadata", "labels"))["peeker.dev/containment"] = "existing"
	s["ciliumnetworkpolicies"] = available(Object{"kind": "CiliumNetworkPolicy", "metadata": Object{"name": "peeker-contain-existing", "namespace": "demo"}, "spec": containmentSpec("existing")})
	replacement := fixture(t, jsonText(existing))
	obj(at(replacement, "metadata"))["uid"] = "replacement"
	obj(at(replacement, "metadata"))["labels"] = Object{"app": "web"}
	remaining, err := uncontainedPods([]Object{existing, replacement}, s)
	if err != nil || len(remaining) != 1 || uid(remaining[0]) != "replacement" {
		t.Fatal("reapply did not isolate the new Pod set", err)
	}
	s["ciliumnetworkpolicies"] = available()
	if _, err := uncontainedPods([]Object{existing}, s); err == nil {
		t.Fatal("missing existing deny policy was accepted")
	}
}

func TestRegistryBacksUpClusterAndAdmissionIdentities(t *testing.T) {
	o, s := registryFixture(t)
	obj(s.items("pods")[0]["spec"])["serviceAccountName"] = "injected"
	role := fixture(t, `{"kind":"ClusterRole","metadata":{"name":"global","uid":"global-role"},"rules":[]}`)
	binding := fixture(t, `{"kind":"ClusterRoleBinding","metadata":{"name":"global","uid":"global-binding"},"subjects":[{"kind":"ServiceAccount","namespace":"demo","name":"injected"}],"roleRef":{"kind":"ClusterRole","name":"global","apiGroup":"rbac.authorization.k8s.io"}}`)
	s["clusterroles"], s["clusterrolebindings"] = available(role), available(binding)
	backup := jsonText(rbacBackupObjects(o, s))
	for _, kind := range []string{"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"} {
		if !strings.Contains(backup, `"kind":"`+kind+`"`) {
			t.Fatal("backup missing", kind, backup)
		}
	}
	if !workloadImages(o, s)["proxy:1"] {
		t.Fatal("injected sidecar image unavailable for scanning")
	}
}

func TestContainmentPartialFailureRetainsBackup(t *testing.T) {
	o, s := registryFixture(t)
	writes := 0
	c := registryProxy(t, s, func(w registryWrite) int {
		writes++
		if w.method == "PATCH" {
			return 409
		}
		return 200
	})
	store := newRegistry(c)
	result := actionResult{}
	if err := store.contain(context.Background(), c, o, &result); err == nil {
		t.Fatal("conflict hidden")
	}
	if writes != 2 || result.Backup == "" || store.backups[result.Backup] == "" {
		t.Fatal("missing partial failure backup or continued RBAC writes")
	}
}

func TestTrivyArgumentBoundaryAndCycloneDX(t *testing.T) {
	dir := t.TempDir()
	program := `#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "--disable-telemetry" ]; then telemetry=off; fi
  if [ "$arg" = "--list-all-pkgs=true" ]; then packages=all; fi
  if [ "$previous" = "--platform" ]; then platform="$arg"; fi
  previous="$arg"
done
if [ "$telemetry" != off ] || [ "$packages" != all ]; then exit 2; fi
case "$platform" in linux/*) ;; *) exit 2;; esac
printf '{"bomFormat":"CycloneDX","components":[{"name":"example","version":"1","type":"library"}]}'
`
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(program), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, image := range []string{"--output=private", "alpine;id", "https://registry/image", "$(id)", "image\n--input=/etc/passwd"} {
		if _, err := scanImage(context.Background(), image); err == nil {
			t.Fatal("unsafe image", image)
		}
	}
	bom, err := scanImage(context.Background(), "alpine:3.22")
	if err != nil || !strings.Contains(string(bom), `"bomFormat":"CycloneDX"`) {
		t.Fatal("scan failed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanImage(ctx, "alpine:3.22"); err == nil {
		t.Fatal("scan ignored cancellation")
	}
}
