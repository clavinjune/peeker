package explorer

import "testing"

func TestServicesUseSelectorsAndEndpointUIDs(t *testing.T) {
	pod := samplePod(t)
	matching := fixture(t, `{"kind":"Service","metadata":{"name":"totally-different-name","namespace":"demo"},"spec":{"selector":{"app":"web"},"ports":[{"port":80,"targetPort":8080}]}}`)
	similar := fixture(t, `{"kind":"Service","metadata":{"name":"web","namespace":"demo"},"spec":{"selector":{"app":"not-web"}}}`)
	s := Snapshot{"services": available(matching, similar)}
	if got := selectedServices(pod, s); len(got) != 1 || name(got[0].service) != "totally-different-name" {
		t.Fatal(got)
	}
	obj(matching["spec"])["selector"] = nil
	s["endpointslices"] = available(fixture(t, `{"kind":"EndpointSlice","metadata":{"name":"slice","namespace":"demo","labels":{"kubernetes.io/service-name":"totally-different-name"}},"endpoints":[{"targetRef":{"kind":"Pod","name":"web","namespace":"demo","uid":"pod-1"},"conditions":{"ready":false}}]}`))
	if got := selectedServices(pod, s); len(got) != 1 {
		t.Fatal(got)
	}
	obj(pod["metadata"])["uid"] = "replaced"
	if got := selectedServices(pod, s); len(got) != 0 {
		t.Fatal("stale endpoint UID", got)
	}
}
func TestCrossNamespaceGrantAndAcceptance(t *testing.T) {
	route := fixture(t, `{"kind":"HTTPRoute","metadata":{"name":"route","namespace":"edge","generation":2},"spec":{"parentRefs":[{"name":"gateway"}]},"status":{"parents":[{"parentRef":{"name":"gateway"},"conditions":[{"type":"Accepted","status":"True","observedGeneration":1},{"type":"ResolvedRefs","status":"True","observedGeneration":1}]}]}}`)
	s := Snapshot{"referencegrants": available()}
	if got, _ := granted(route, "demo", "web", s); got != "forbidden" {
		t.Fatal(got)
	}
	grant := fixture(t, `{"kind":"ReferenceGrant","metadata":{"namespace":"demo","name":"allow"},"spec":{"from":[{"group":"gateway.networking.k8s.io","kind":"HTTPRoute","namespace":"edge"}],"to":[{"group":"","kind":"Service","name":"web"}]}}`)
	s["referencegrants"] = available(grant)
	if got, evidence := granted(route, "demo", "web", s); got != "permitted" || len(evidence) != 1 {
		t.Fatal(got, evidence)
	}
	if got, _ := granted(route, "demo", "other", s); got != "forbidden" {
		t.Fatal(got)
	}
	if routeStatus(route) != "configured" {
		t.Fatal("stale status accepted")
	}
	obj(route["metadata"])["generation"] = float64(1)
	if routeStatus(route) != "accepted" {
		t.Fatal("current status not accepted")
	}
}
func TestIstioSubsetsAndServicePorts(t *testing.T) {
	pod := samplePod(t)
	service := fixture(t, `{"metadata":{"namespace":"demo","name":"web"},"spec":{"ports":[{"name":"http","port":80,"targetPort":8080}]}}`)
	vs := fixture(t, `{"metadata":{"namespace":"demo","name":"route"}}`)
	dr := fixture(t, `{"kind":"DestinationRule","metadata":{"namespace":"demo","name":"versions"},"spec":{"host":"web","subsets":[{"name":"v2","labels":{"version":"v2"}}]}}`)
	s := Snapshot{"destinationrules": available(dr)}
	if got, _, _ := subsetMatches(pod, vs, service, Object{"subset": "v2"}, s); got {
		t.Fatal("subset mismatch connected")
	}
	if got, reason, _ := subsetMatches(pod, vs, service, Object{"subset": "missing"}, s); !got || reason == "" {
		t.Fatal("missing subset should be unknown")
	}
	if ok, _ := servicePort(service, float64(80)); !ok {
		t.Fatal("service port missing")
	}
	if ok, _ := servicePort(service, float64(8080)); ok {
		t.Fatal("targetPort confused with service port")
	}
}
