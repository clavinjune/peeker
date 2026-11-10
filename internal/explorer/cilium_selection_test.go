package explorer

import "testing"

func TestCiliumIdentityLabelsAndUnavailableNamespace(t *testing.T) {
	pod := hardenedPod(t)
	obj(pod["metadata"])["labels"] = Object{"io.kubernetes.pod.namespace": "spoof", "io.cilium.k8s.policy.serviceaccount": "spoof", "io.cilium.k8s.namespace.labels.fake": "spoof"}
	s := securitySnapshot()
	s["namespaces"] = available(fixture(t, `{"kind":"Namespace","metadata":{"name":"demo","labels":{"team":"platform"}}}`))
	for _, prefix := range []string{"", "k8s:", "any:"} {
		selector := Object{"matchLabels": Object{prefix + "io.kubernetes.pod.namespace": "demo", prefix + "io.cilium.k8s.policy.serviceaccount": "app", prefix + "io.cilium.k8s.namespace.labels.team": "platform"}}
		if selected, err := ciliumSelection(selector, pod, s); !selected || err != nil {
			t.Fatal(prefix, selected, err)
		}
		spoof := Object{"matchLabels": Object{prefix + "io.cilium.k8s.namespace.labels.fake": "spoof"}}
		if selected, err := ciliumSelection(spoof, pod, s); selected || err != nil {
			t.Fatal("pod label fabricated namespace identity", prefix, selected, err)
		}
		unavailable := securitySnapshot()
		unavailable["namespaces"] = Collection{State: State{Status: "denied"}}
		if selected, err := ciliumSelection(selector, pod, unavailable); selected || err == nil {
			t.Fatal("unavailable identity did not remain unknown", prefix, selected, err)
		}
	}
}
