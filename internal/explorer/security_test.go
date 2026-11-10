package explorer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func hardenedPod(t *testing.T) Object {
	pod := fixture(t, `{"kind":"Pod","metadata":{"name":"web","namespace":"demo","uid":"p1"},"spec":{"serviceAccountName":"app","automountServiceAccountToken":false,"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"istio-proxy","securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}`)
	return pod
}

func securitySnapshot() Snapshot {
	deny := Object{"kind": "NetworkPolicy", "metadata": Object{"name": "deny-default", "namespace": "demo"}, "spec": Object{"podSelector": Object{}, "policyTypes": []any{"Ingress", "Egress"}}}
	return Snapshot{"roles": available(), "rolebindings": available(), "clusterroles": available(), "clusterrolebindings": available(), "serviceaccounts": available(), "networkpolicies": available(deny), "ciliumnetworkpolicies": available(), "ciliumclusterwidenetworkpolicies": available()}
}

func finding(report SecurityReport, id string) *Finding {
	for _, item := range report.Findings {
		if item.ID == id {
			return &item
		}
	}
	return nil
}

func TestSecurityInheritanceOverridesAndUnknownDefaults(t *testing.T) {
	pod := hardenedPod(t)
	s := securitySnapshot()
	if got := assessPod(pod, s); got.Risk.Score != 0 || got.Risk.Unknown != 0 || got.Risk.Level != "none" {
		t.Fatalf("inherited hardening: %+v", got)
	}
	sc := obj(obj(arr(at(pod, "spec", "containers"))[0])["securityContext"])
	sc["runAsUser"] = float64(0)
	sc["seccompProfile"] = Object{"type": "Unconfined"}
	got := assessPod(pod, s)
	if finding(got, "root") == nil || finding(got, "seccomp") == nil || got.Risk.Level != "high" {
		t.Fatalf("container overrides must win: %+v", got)
	}
	delete(sc, "runAsUser")
	delete(sc, "seccompProfile")
	delete(obj(pod["spec"]), "securityContext")
	got = assessPod(pod, s)
	if got.Risk.Level != "unknown" || got.Risk.Unknown != 2 || got.Risk.Score != 0 {
		t.Fatalf("image UID and node seccomp defaults must remain unknown: %+v", got)
	}
}

func TestSecurityIncludesInitEphemeralAndDeduplicatesScore(t *testing.T) {
	pod := hardenedPod(t)
	privileged := fixture(t, `{"name":"debug","securityContext":{"privileged":true,"allowPrivilegeEscalation":false,"capabilities":{"add":["SYS_ADMIN"],"drop":["ALL"]},"readOnlyRootFilesystem":true}}`)
	obj(pod["spec"])["initContainers"] = []any{privileged}
	first := assessPod(pod, securitySnapshot())
	obj(pod["spec"])["ephemeralContainers"] = []any{privileged}
	second := assessPod(pod, securitySnapshot())
	if first.Risk.Score != second.Risk.Score || second.Risk.Level != "critical" || finding(second, "escalation") == nil {
		t.Fatalf("duplicate containers must not inflate scoring; privileged overrides false escalation: %+v %+v", first.Risk, second.Risk)
	}
	if len(finding(second, "privileged").Evidence) != 2 {
		t.Fatal("both container field paths must be preserved")
	}
}

func TestSecurityTokenOverridesAndMountedProjections(t *testing.T) {
	pod := hardenedPod(t)
	s := securitySnapshot()
	s["serviceaccounts"] = available(fixture(t, `{"kind":"ServiceAccount","metadata":{"name":"app","namespace":"demo"},"automountServiceAccountToken":true,"secrets":[{"name":"private-token-reference"}]}`))
	if finding(assessPod(pod, s), "api-token") != nil {
		t.Fatal("pod automount=false must override ServiceAccount")
	}
	delete(obj(pod["spec"]), "automountServiceAccountToken")
	if finding(assessPod(pod, s), "api-token") == nil {
		t.Fatal("ServiceAccount automount default must be applied")
	}
	obj(pod["spec"])["automountServiceAccountToken"] = false
	obj(pod["spec"])["volumes"] = []any{fixture(t, `{"name":"api","projected":{"sources":[{"serviceAccountToken":{"path":"token"}}]}}`)}
	if finding(assessPod(pod, s), "api-token") != nil {
		t.Fatal("unmounted projection must not be called mounted")
	}
	obj(arr(at(pod, "spec", "containers"))[0])["volumeMounts"] = []any{Object{"name": "api", "mountPath": "/identity"}}
	report := assessPod(pod, s)
	if finding(report, "api-token") == nil || strings.Contains(jsonText(report), "private-token-reference") {
		t.Fatal("explicit mounted tokens must be reported without exposing secret references")
	}
}

func TestSecurityWindowsAndHostMountCoverage(t *testing.T) {
	pod := hardenedPod(t)
	obj(pod["spec"])["os"] = Object{"name": "windows"}
	obj(pod["spec"])["volumes"] = []any{Object{"name": "host", "hostPath": Object{"path": "/private-host-path"}}}
	obj(arr(at(pod, "spec", "containers"))[0])["volumeMounts"] = []any{Object{"name": "host", "mountPath": "/host"}}
	report := assessPod(pod, securitySnapshot())
	if report.Risk.Unknown == 0 || finding(report, "host-path") == nil || strings.Contains(jsonText(report), "/private-host-path") {
		t.Fatalf("Windows hardening must be incomplete and host mount contents withheld: %+v", report)
	}
}

func TestRBACCrossNamespaceGroupsAndClusterScope(t *testing.T) {
	pod, s := hardenedPod(t), securitySnapshot()
	s["clusterroles"] = available(fixture(t, `{"kind":"ClusterRole","metadata":{"name":"admin"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`))
	binding := fixture(t, `{"kind":"RoleBinding","metadata":{"name":"grant","namespace":"other"},"subjects":[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"system:serviceaccounts:demo"}],"roleRef":{"kind":"ClusterRole","apiGroup":"rbac.authorization.k8s.io","name":"admin"}}`)
	s["rolebindings"] = available(binding)
	report := assessPod(pod, s)
	if finding(report, "rbac-secrets") == nil || finding(report, "rbac-admin") != nil || report.Risk.Level != "high" {
		t.Fatalf("cross-namespace RoleBinding must remain namespace-scoped: %+v", report)
	}
	if !strings.Contains(jsonText(finding(report, "rbac-secrets")), "namespace other") {
		t.Fatal("binding scope evidence missing")
	}
	binding["kind"] = "ClusterRoleBinding"
	delete(obj(binding["metadata"]), "namespace")
	s["rolebindings"], s["clusterrolebindings"] = available(), available(binding)
	if got := assessPod(pod, s); finding(got, "rbac-admin") == nil || got.Risk.Level != "critical" {
		t.Fatal("cluster-wide wildcard grant must be critical", got)
	}
	obj(arr(binding["subjects"])[0])["name"] = "system:serviceaccounts:unrelated"
	if got := assessPod(pod, s); got.Risk.Score != 0 {
		t.Fatal("unrelated group must not grant permissions", got)
	}
}

func TestRBACConstraintsMissingRolesAndDenials(t *testing.T) {
	rule := fixture(t, `{"apiGroups":[""],"resources":["pods"],"verbs":["create"],"resourceNames":["named"]}`)
	if ruleAllows(rule, "", "pods", "create") {
		t.Fatal("resourceNames cannot authorize a top-level create")
	}
	rule["resources"] = []any{"pods/*"}
	if ruleAllows(rule, "", "pods/exec", "create") {
		t.Fatal("unsupported partial resource wildcard matched")
	}
	rule["resources"] = []any{"*/exec"}
	if !ruleAllows(rule, "", "pods/exec", "create") {
		t.Fatal("subresource wildcard or named exec was not recognized")
	}
	pod, s := hardenedPod(t), securitySnapshot()
	s["rolebindings"] = available(fixture(t, `{"kind":"RoleBinding","metadata":{"name":"grant","namespace":"demo"},"subjects":[{"kind":"ServiceAccount","name":"app"}],"roleRef":{"kind":"Role","apiGroup":"rbac.authorization.k8s.io","name":"missing"}}`))
	if got := assessPod(pod, s); got.Risk.Level != "unknown" || got.Risk.Unknown < 6 {
		t.Fatal("missing referenced role must remain unknown", got)
	}
	s["rolebindings"] = Collection{State: State{Status: "denied"}}
	if got := assessPod(pod, s); got.Risk.Level != "unknown" || got.Risk.Unknown < 6 {
		t.Fatal("denied RBAC must not produce a clean assessment", got)
	}
}

func TestRiskScoreBandsAndInventoryOrdering(t *testing.T) {
	high := SecurityReport{Findings: []Finding{}, Gaps: []CheckGap{}}
	for id, rule := range findingRules {
		if rule.severity != "critical" {
			high.record(id, "fail")
		}
	}
	high.finish()
	critical := SecurityReport{Findings: []Finding{}, Gaps: []CheckGap{}}
	critical.record("privileged", "fail")
	critical.finish()
	if high.Risk.Score >= critical.Risk.Score || high.Risk.Score > 79 {
		t.Fatal("many lower-severity findings must not outrank a critical finding")
	}
	safe, unsafe := hardenedPod(t), hardenedPod(t)
	obj(unsafe["metadata"])["name"] = "unsafe"
	obj(obj(arr(at(unsafe, "spec", "containers"))[0])["securityContext"])["privileged"] = true
	s := securitySnapshot()
	s["pods"] = available(safe, unsafe)
	views := inventoryPods(s, "")
	if views[0].Name != "unsafe" || views[0].Risk.Level != "critical" || views[1].Risk.Score != 0 {
		t.Fatalf("inventory risk ordering: %+v", views)
	}
}

func TestNamespaceInventoryReadsRBACAcrossNamespaces(t *testing.T) {
	var mu sync.Mutex
	paths := map[string]bool{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path] = true
		mu.Unlock()
		entries := []any{}
		for _, resource := range resources {
			entries = append(entries, Object{"name": resource.plural})
		}
		writeJSON(w, 200, Object{"resources": entries, "items": []any{}})
	}))
	defer proxy.Close()
	client, _ := NewClient(proxy.URL)
	client.snapshot(context.Background(), "demo", false)
	for _, resource := range []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"} {
		if !paths["/apis/rbac.authorization.k8s.io/v1/"+resource] {
			t.Fatal("RBAC was incorrectly restricted to selected pod namespace", resource)
		}
	}
	if !paths["/api/v1/namespaces/demo/pods"] || !paths["/api/v1/namespaces/demo/serviceaccounts"] || !paths["/apis/networking.k8s.io/v1/namespaces/demo/networkpolicies"] {
		t.Fatal("pod, ServiceAccount and NetworkPolicy reads should retain their namespace filter")
	}
}

func TestRBACDelegationScopeAndSubresourceWrites(t *testing.T) {
	for _, test := range []struct {
		group, resource, verb, risk string
		cluster, want               bool
	}{
		{"rbac.authorization.k8s.io", "clusterroles", "bind", "rbac-delegation", false, true},
		{"rbac.authorization.k8s.io", "clusterroles", "escalate", "rbac-delegation", false, false},
		{"rbac.authorization.k8s.io", "clusterroles", "escalate", "rbac-delegation", true, true},
		{"", "users", "impersonate", "rbac-delegation", false, false},
		{"", "users", "impersonate", "rbac-delegation", true, true},
		{"", "serviceaccounts/token", "create", "rbac-delegation", false, true},
		{"", "pods/ephemeralcontainers", "patch", "rbac-workloads", false, true},
		{"", "replicationcontrollers", "update", "rbac-workloads", false, true},
		{"", "secrets", "get", "rbac-secrets", false, true},
		{"", "pods", "create", "rbac-workloads", false, false},
	} {
		rule := Object{"apiGroups": []any{test.group}, "resources": []any{test.resource}, "verbs": []any{test.verb}, "resourceNames": []any{"named"}}
		matched := false
		for _, risk := range grantRisks(permissionGrant{rule: rule, cluster: test.cluster}) {
			matched = matched || risk == test.risk
		}
		if matched != test.want {
			t.Errorf("%s/%s %s cluster=%t: got %t, want %t", test.group, test.resource, test.verb, test.cluster, matched, test.want)
		}
	}
}
