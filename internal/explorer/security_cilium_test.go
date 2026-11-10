package explorer

import "testing"

func TestCiliumDefaultDenyBaseline(t *testing.T) {
	for _, test := range []struct {
		name, spec      string
		ingress, egress bool
	}{
		{"explicit-deny", `{"endpointSelector":{},"enableDefaultDeny":{"ingress":true,"egress":true}}`, false, false},
		{"empty-is-not-deny", `{"endpointSelector":{},"ingress":[],"egress":[]}`, true, true},
		{"direction-default", `{"endpointSelector":{},"ingress":[{"fromEndpoints":[{"matchLabels":{"app":"client"}}]}]}`, false, true},
		{"disabled", `{"endpointSelector":{},"enableDefaultDeny":{"ingress":false},"ingress":[{"fromEndpoints":[{}]}]}`, true, true},
		{"broad-world", `{"endpointSelector":{},"enableDefaultDeny":{"ingress":true},"egress":[{"toEntities":["world"]}]}`, false, true},
		{"broad-all", `{"endpointSelector":{},"ingress":[{"fromEntities":["all"],"toPorts":[]}],"egressDeny":[{}]}`, true, false},
		{"empty-ports", `{"endpointSelector":{},"ingress":[{"toPorts":[]}],"egressDeny":[{"toPorts":[]}]}`, true, false},
		{"cidrset-world", `{"endpointSelector":{},"enableDefaultDeny":{"ingress":true},"egress":[{"toCIDRSet":[{"cidr":"0.0.0.0/0"}]}]}`, false, true},
		{"dns-restricted", `{"endpointSelector":{},"enableDefaultDeny":{"ingress":true},"egress":[{"toPorts":[{"ports":[{"port":"53","protocol":"UDP"}],"rules":{"dns":[{"matchPattern":"*"}]}}]}]}`, false, false},
		{"unselected", `{"endpointSelector":{"matchLabels":{"app":"other"}},"enableDefaultDeny":{"ingress":true,"egress":true}}`, true, true},
		{"host-policy", `{"nodeSelector":{},"enableDefaultDeny":{"ingress":true,"egress":true}}`, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pod, s := hardenedPod(t), securitySnapshot()
			s["networkpolicies"] = available()
			s["ciliumnetworkpolicies"] = available(Object{"kind": "CiliumNetworkPolicy", "metadata": Object{"name": "baseline", "namespace": "demo"}, "spec": fixture(t, test.spec)})
			report := assessPod(pod, s)
			if (finding(report, "netpol-ingress") != nil) != test.ingress || (finding(report, "netpol-egress") != nil) != test.egress || report.Risk.Unknown != 0 {
				t.Fatalf("%+v", report)
			}
		})
	}
}

func TestCiliumUnionDenyPrecedenceAndCoverage(t *testing.T) {
	pod, s := hardenedPod(t), securitySnapshot()
	s["networkpolicies"] = available(fixture(t, `{"kind":"NetworkPolicy","metadata":{"name":"allow","namespace":"demo"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[{}],"egress":[{}]}}`))
	deny := fixture(t, `{"kind":"CiliumClusterwideNetworkPolicy","metadata":{"name":"deny"},"specs":[{"endpointSelector":{},"ingressDeny":[{"fromEntities":["world","all"]}],"egressDeny":[{}]}]}`)
	s["ciliumclusterwidenetworkpolicies"] = available(deny)
	if got := assessPod(pod, s); got.Risk.Score != 0 || got.Risk.Unknown != 0 {
		t.Fatal("deny-all must override broad Kubernetes allows", got)
	}
	obj(arr(deny["specs"])[0])["ingressDeny"] = []any{Object{"fromEntities": []any{"world"}}}
	if got := assessPod(pod, s); got.Risk.Unknown != 1 || finding(got, "netpol-ingress") != nil {
		t.Fatal("partial deny overlap needs review", got)
	}
	s["ciliumclusterwidenetworkpolicies"] = Collection{State: State{Status: "denied"}}
	if got := assessPod(pod, s); got.Risk.Unknown != 2 {
		t.Fatal("unreadable Cilium must not imply missing protection", got)
	}
	s["ciliumclusterwidenetworkpolicies"], s["ciliumnetworkpolicies"] = Collection{State: State{Status: "missing-api"}}, Collection{State: State{Status: "missing-api"}}
	if got := assessPod(pod, s); len(got.Findings) != 2 {
		t.Fatal("absent Cilium must not suppress Kubernetes findings", got)
	}
	s = securitySnapshot()
	s["networkpolicies"] = available()
	s["ciliumnetworkpolicies"] = available(fixture(t, `{"kind":"CiliumNetworkPolicy","metadata":{"name":"other","namespace":"other"},"spec":{"endpointSelector":{},"enableDefaultDeny":{"ingress":true,"egress":true}}}`))
	if got := assessPod(pod, s); len(got.Findings) != 2 {
		t.Fatal("namespaced Cilium policy crossed namespace", got)
	}
	s["ciliumclusterwidenetworkpolicies"] = available(fixture(t, `{"kind":"CiliumClusterwideNetworkPolicy","metadata":{"name":"global"},"specs":[{"endpointSelector":{},"enableDefaultDeny":{"ingress":true,"egress":true}},{"endpointSelector":{},"enableDefaultDeny":{"ingress":false,"egress":false}}]}`))
	if got := assessPod(pod, s); got.Risk.Score != 0 {
		t.Fatal("false cannot override another policy's true default-deny", got)
	}
}

func TestIstioExpectation(t *testing.T) {
	pod, s := hardenedPod(t), securitySnapshot()
	obj(arr(at(pod, "spec", "containers"))[0])["name"] = "app"
	if finding(assessPod(pod, s), "istio-sidecar") == nil {
		t.Fatal("missing proxy not reported")
	}
	if finding(assessPod(pod, s, AssessmentOptions{}), "istio-sidecar") != nil {
		t.Fatal("disabled expectation ignored")
	}
	sidecar := Object{"name": "istio-proxy", "restartPolicy": "Always"}
	obj(pod["spec"])["initContainers"] = []any{sidecar}
	if finding(assessPod(pod, s), "istio-sidecar") != nil {
		t.Fatal("native sidecar not recognized")
	}
	delete(sidecar, "restartPolicy")
	if finding(assessPod(pod, s), "istio-sidecar") == nil {
		t.Fatal("one-shot init treated as sidecar")
	}
}
