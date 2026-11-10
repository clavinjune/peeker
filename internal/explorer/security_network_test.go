package explorer

import (
	"context"
	"reflect"
	"testing"
)

func TestNetworkBaselineIsolationAndAdditiveAllowAll(t *testing.T) {
	for _, test := range []struct {
		name, spec      string
		ingress, egress bool
	}{
		{"both-denied", `{"podSelector":{},"policyTypes":["Ingress","Egress"]}`, false, false},
		{"default-ingress-only", `{"podSelector":{}}`, false, true},
		{"egress-only", `{"podSelector":{},"policyTypes":["Egress"]}`, true, false},
		{"default-egress-from-rule", `{"podSelector":{},"egress":[{"ports":[{"port":53,"protocol":"UDP"}]}]}`, false, false},
		{"narrow-exceptions", `{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[{"from":[{"podSelector":{"matchLabels":{"app":"client"}}}]}],"egress":[{"ports":[{"port":443}]}]}`, false, false},
		{"allow-all", `{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[{}],"egress":[{"to":[],"ports":[]}]}`, true, true},
		{"protocol-only", `{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[{"ports":[{"protocol":"TCP"},{"protocol":"UDP"},{"protocol":"SCTP"}]}],"egress":[{"ports":[{}]}]}`, true, true},
		{"full-port-range", `{"podSelector":{},"policyTypes":["Ingress","Egress"],"egress":[{"ports":[{"protocol":"TCP","port":1,"endPort":65535}]}]}`, false, true},
		{"protocol-narrow-peer", `{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[{"from":[{"podSelector":{"matchLabels":{"app":"client"}}}],"ports":[{"protocol":"TCP"}]}]}`, false, false},
		{"empty-peer", `{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[{"from":[{}]}]}`, true, false},
		{"universal-cidr", `{"podSelector":{},"policyTypes":["Ingress","Egress"],"egress":[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}]}]}`, false, true},
		{"universal-ipv6", `{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[{"from":[{"ipBlock":{"cidr":"::/0"}}]}]}`, true, false},
		{"cidr-with-exception", `{"podSelector":{},"policyTypes":["Ingress","Egress"],"egress":[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0","except":["10.0.0.0/8"]}}]}]}`, false, false},
		{"unselected", `{"podSelector":{"matchLabels":{"app":"other"}},"policyTypes":["Ingress","Egress"]}`, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pod, s := hardenedPod(t), securitySnapshot()
			policy := Object{"kind": "NetworkPolicy", "metadata": Object{"name": "baseline", "namespace": "demo", "uid": "np1"}, "spec": fixture(t, test.spec)}
			s["networkpolicies"] = available(policy)
			s["pods"] = available(pod)
			report := assessPod(pod, s)
			if (finding(report, "netpol-ingress") != nil) != test.ingress || (finding(report, "netpol-egress") != nil) != test.egress || report.Risk.Unknown != 0 {
				t.Fatalf("unexpected network baseline: %+v", report)
			}
			for _, f := range report.Findings {
				if len(f.Evidence) == 0 || f.Remediation == "" {
					t.Fatal("missing actionable evidence", f)
				}
			}
			s["pods"] = available(pod)
			job := &inventoryJob{}
			job.prepare(s)
			job.assess(context.Background(), s, AssessmentOptions{ExpectIstio: true})
			if !reflect.DeepEqual(job.page(inventoryQuery{Limit: 100}).Pods[0].Risk, report.Risk) {
				t.Fatal("inventory/detail score mismatch")
			}
		})
	}
	pod, s := hardenedPod(t), securitySnapshot()
	allow := fixture(t, `{"kind":"NetworkPolicy","metadata":{"name":"allow-all","namespace":"demo"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[{}],"egress":[{}]}}`)
	s["networkpolicies"] = available(append(s.items("networkpolicies"), allow, allow)...)
	report := assessPod(pod, s)
	if len(report.Findings) != 2 || report.Risk.Score != 24 {
		t.Fatalf("deny policy cannot override additive allows, nor duplicates inflate score: %+v", report)
	}
}

func TestNetworkBaselineUnknownAndNamespaceScope(t *testing.T) {
	pod, s := hardenedPod(t), securitySnapshot()
	for _, status := range []string{"denied", "error", "missing-api"} {
		s["networkpolicies"] = Collection{State: State{Status: status}}
		report := assessPod(pod, s)
		if report.Risk.Score != 0 || report.Risk.Unknown != 2 || report.Risk.Level != "unknown" {
			t.Fatal(status, report)
		}
	}
	s = securitySnapshot()
	obj(s.items("networkpolicies")[0]["metadata"])["namespace"] = "other"
	if report := assessPod(pod, s); len(report.Findings) != 2 {
		t.Fatal("other namespace incorrectly isolated pod", report)
	}
	s = securitySnapshot()
	obj(s.items("networkpolicies")[0]["spec"])["podSelector"] = Object{"unsupported": true}
	if report := assessPod(pod, s); report.Risk.Unknown != 2 || report.Risk.Score != 0 {
		t.Fatal("unknown selector treated as absent", report)
	}
	obj(pod["spec"])["hostNetwork"] = true
	report := assessPod(pod, securitySnapshot())
	if finding(report, "netpol-ingress") != nil || finding(report, "netpol-egress") != nil || report.Risk.Unknown != 2 {
		t.Fatal("host networking inferred as enforced", report)
	}
}
