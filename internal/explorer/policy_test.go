package explorer

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixture(t *testing.T, raw string) Object {
	t.Helper()
	var o Object
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		t.Fatal(err)
	}
	return o
}
func available(items ...Object) Collection { return Collection{items, State{Status: "available"}} }
func samplePod(t *testing.T) Object {
	return fixture(t, `{"kind":"Pod","metadata":{"name":"web","namespace":"demo","uid":"pod-1","labels":{"app":"web","version":"v1"}}}`)
}

func TestPolicyAdditivityAndDirectionIsolation(t *testing.T) {
	pod := samplePod(t)
	deny := fixture(t, `{"kind":"NetworkPolicy","metadata":{"name":"isolate","namespace":"demo","uid":"a"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[],"egress":[]}}`)
	allow := fixture(t, `{"kind":"NetworkPolicy","metadata":{"name":"allow-http","namespace":"demo","uid":"b"},"spec":{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"ports":[{"port":8080}]}]}}`)
	second := fixture(t, `{"kind":"NetworkPolicy","metadata":{"name":"allow-udp","namespace":"demo","uid":"c"},"spec":{"podSelector":{},"ingress":[{"ports":[{"protocol":"UDP","port":53}]}]}}`)
	s := Snapshot{"networkpolicies": available(deny, allow, second)}
	a := networkPolicies(pod, s)
	if a.Ingress.Status != "allowed" || a.Egress.Status != "denied" {
		t.Fatalf("ingress=%+v egress=%+v", a.Ingress, a.Egress)
	}
	allowEdges := 0
	for _, edge := range a.Graph.Edges {
		if edge.Status == "allowed" {
			allowEdges++
			if len(edge.Evidence) == 0 {
				t.Fatal("allow without evidence")
			}
		}
	}
	if allowEdges != 2 {
		t.Fatalf("expected both additive allowances, got %d", allowEdges)
	}
	s["networkpolicies"] = available(deny)
	if got := networkPolicies(pod, s); got.Ingress.Status != "denied" || got.Egress.Status != "denied" {
		t.Fatal(got)
	}
}
func TestPolicyTypesDefaulting(t *testing.T) {
	cases := []struct {
		spec            string
		ingress, egress bool
	}{
		{`{"podSelector":{}}`, true, false},
		{`{"podSelector":{},"egress":[]}`, true, false},
		{`{"podSelector":{},"egress":[{}]}`, true, true},
		{`{"podSelector":{},"policyTypes":["Egress"]}`, false, true},
	}
	for _, test := range cases {
		in, out, err := policyTypes(fixture(t, test.spec))
		if err != nil || in != test.ingress || out != test.egress {
			t.Fatalf("%s => %v %v %v", test.spec, in, out, err)
		}
	}
}
func TestSelectorExpressions(t *testing.T) {
	cases := []struct {
		selector string
		want     bool
		unknown  bool
	}{
		{`{}`, true, false},
		{`{"matchLabels":{"app":"web"}}`, true, false},
		{`{"matchLabels":{"app":"other"}}`, false, false},
		{`{"matchExpressions":[{"key":"app","operator":"In","values":["web"]},{"key":"other","operator":"DoesNotExist"}]}`, true, false},
		{`{"matchExpressions":[{"key":"missing","operator":"NotIn","values":["x"]}]}`, true, false},
		{`{"matchExpressions":[{"key":"missing","operator":"Exists"}]}`, false, false},
		{`{"matchExpressions":[{"key":"app","operator":"GreaterThan","values":["0"]}]}`, false, true},
	}
	for _, test := range cases {
		got, err := matches(fixture(t, test.selector), Object{"app": "web"})
		if got != test.want || (err != nil) != test.unknown {
			t.Fatalf("%s => %v %v", test.selector, got, err)
		}
	}
}
func TestCombinedPeerSelectorsAndNamespaceScope(t *testing.T) {
	local := samplePod(t)
	remote := samplePod(t)
	obj(remote["metadata"])["namespace"] = "other"
	s := Snapshot{"pods": available(local, remote), "namespaces": available(fixture(t, `{"metadata":{"name":"demo","labels":{"team":"blue"}}}`), fixture(t, `{"metadata":{"name":"other","labels":{"team":"red"}}}`))}
	combined := fixture(t, `{"namespaceSelector":{"matchLabels":{"team":"red"}},"podSelector":{"matchLabels":{"app":"web"}}}`)
	if ok, _ := peerMatches(combined, "demo", local, s); ok {
		t.Fatal("selectors must be AND, not OR")
	}
	if ok, err := peerMatches(combined, "demo", remote, s); !ok || err != nil {
		t.Fatal(ok, err)
	}
	podsOnly := fixture(t, `{"podSelector":{}}`)
	if ok, _ := peerMatches(podsOnly, "demo", remote, s); ok {
		t.Fatal("podSelector alone is policy-namespace scoped")
	}
	allNamespaces := fixture(t, `{"namespaceSelector":{},"podSelector":{}}`)
	if ok, err := peerMatches(allNamespaces, "demo", remote, s); !ok || err != nil {
		t.Fatal(ok, err)
	}
	s["namespaces"] = Collection{State: State{Status: "denied"}}
	if _, err := peerMatches(allNamespaces, "demo", remote, s); err == nil {
		t.Fatal("denied namespace read must be unknown")
	}
}
func TestCIDRExceptionsAndPorts(t *testing.T) {
	peer := fixture(t, `{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.1.0.0/16"]}}`)
	_, description, err := peerDescription(peer, "demo", Snapshot{})
	if err != nil || !strings.Contains(description, "10.1.0.0/16") {
		t.Fatal(description, err)
	}
	invalid := fixture(t, `{"ipBlock":{"cidr":"10.0.0.0/8","except":["192.168.0.0/16"]}}`)
	if _, _, err := peerDescription(invalid, "demo", Snapshot{}); err == nil {
		t.Fatal("invalid exception accepted")
	}
	ports := fixture(t, `{"ports":[{"port":8000,"endPort":8080},{"port":"dns","protocol":"UDP"}]}`)
	summary, err := portSummary(ports["ports"])
	if err != nil || !strings.Contains(summary, "TCP 8000–8080") || !strings.Contains(summary, "UDP named dns") {
		t.Fatal(summary, err)
	}
}
func TestUnknownNeverBecomesUnrestricted(t *testing.T) {
	pod := samplePod(t)
	for _, state := range []string{"denied", "error", "missing-api"} {
		a := networkPolicies(pod, Snapshot{"networkpolicies": Collection{State: State{Status: state}}})
		if a.Ingress.Status != "unknown" || a.Egress.Status != "unknown" {
			t.Fatal(a)
		}
	}
	s := Snapshot{"networkpolicies": available()}
	a := networkPolicies(pod, s)
	if a.Ingress.Status != "unrestricted" || !strings.Contains(a.Ingress.Evidence[0].Description, "does not establish internet reachability") {
		t.Fatal(a)
	}
	for _, node := range a.Graph.Nodes {
		if strings.Contains(strings.ToLower(node.Label), "world") {
			t.Fatal("invented world node")
		}
	}
	s["networkpolicies"] = available(fixture(t, `{"metadata":{"name":"bad","namespace":"demo"},"spec":{"podSelector":{"unknown":true}}}`))
	if a := networkPolicies(pod, s); a.Ingress.Status != "unknown" {
		t.Fatal(a)
	}
}
func TestCiliumDenyCannotBecomeAllow(t *testing.T) {
	policy := fixture(t, `{"kind":"CiliumNetworkPolicy","metadata":{"namespace":"demo","name":"deny","uid":"cilium"},"spec":{"endpointSelector":{"matchLabels":{"k8s:app":"web"}},"egress":[{"toEntities":["world"]}],"egressDeny":[{"toEntities":["world"]}]}}`)
	a := networkPolicies(samplePod(t), Snapshot{"networkpolicies": available(), "ciliumnetworkpolicies": available(policy)})
	deny, partial := false, false
	for _, e := range a.Graph.Edges {
		if e.Label == "Cilium deny" {
			deny = e.Status == "denied"
		}
		if e.Label == "Cilium allow" {
			partial = e.Status == "unknown"
		}
	}
	if !deny || !partial {
		t.Fatal(a.Graph)
	}
}
