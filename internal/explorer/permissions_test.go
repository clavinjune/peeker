package explorer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPermissionReportScopesConstraintsAndGaps(t *testing.T) {
	pod, s := hardenedPod(t), securitySnapshot()
	s["serviceaccounts"] = available(fixture(t, `{"kind":"ServiceAccount","apiVersion":"v1","metadata":{"namespace":"demo","name":"app","uid":"sa1"},"secrets":[{"name":"never-export"}]}`))
	s["roles"] = available(fixture(t, `{"kind":"Role","metadata":{"namespace":"other","name":"reader"},"rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["get"],"resourceNames":["settings"],"extra":"never-export"}]}`))
	s["rolebindings"] = available(fixture(t, `{"kind":"RoleBinding","metadata":{"namespace":"other","name":"read-settings"},"subjects":[{"kind":"ServiceAccount","namespace":"demo","name":"app"}],"roleRef":{"kind":"Role","apiGroup":"rbac.authorization.k8s.io","name":"reader"}}`))
	s["clusterroles"] = available(fixture(t, `{"kind":"ClusterRole","metadata":{"name":"health"},"rules":[{"nonResourceURLs":["/healthz"],"verbs":["get"]}]}`))
	s["clusterrolebindings"] = available(fixture(t, `{"kind":"ClusterRoleBinding","metadata":{"name":"health"},"subjects":[{"kind":"Group","name":"system:authenticated","apiGroup":"rbac.authorization.k8s.io"}],"roleRef":{"kind":"ClusterRole","apiGroup":"rbac.authorization.k8s.io","name":"health"}}`))
	s = indexedSnapshot(s)
	report := podPermissions(pod, s)
	if report.Identity != "system:serviceaccount:demo:app" || report.ServiceAccount.UID != "sa1" || len(report.Gaps) != 0 || len(report.Grants) != 2 {
		t.Fatalf("bad permission report: %+v", report)
	}
	if report.Grants[0].Scope != "namespace other" || report.Grants[0].Binding.Name != "read-settings" || report.Grants[0].Role.Name != "reader" || report.Grants[0].Rule["resourceNames"].([]string)[0] != "settings" {
		t.Fatal("namespace/constraint lost", report.Grants[0])
	}
	if report.Grants[1].Scope != "cluster-wide" || report.Grants[1].Rule["nonResourceURLs"].([]string)[0] != "/healthz" {
		t.Fatal("cluster URL grant lost", report.Grants[1])
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "never-export") {
		t.Fatal("unallowlisted fields escaped")
	}
	s["serviceaccounts"] = Collection{State: State{Status: "denied"}}
	s["rolebindings"] = Collection{State: State{Status: "denied"}}
	s["clusterrolebindings"] = Collection{State: State{Status: "denied"}}
	report = podPermissions(pod, s)
	if report.Status != "unresolved" || len(report.Gaps) < 3 || len(report.Grants) != 0 {
		t.Fatal("denied inventory appears complete", report)
	}
	delete(obj(pod["spec"]), "serviceAccountName")
	if got := podPermissions(pod, s).Identity; got != "system:serviceaccount:demo:default" {
		t.Fatal("default account not resolved", got)
	}
}
