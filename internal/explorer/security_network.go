package explorer

import "net/netip"

func (d *Direction) recordOpenRule(rule, peer Object, state string, evidence Evidence) {
	if state != "allowed" || len(arr(rule["ports"])) != 0 || peer == nil {
		return
	}
	if len(peer) == 0 {
		d.OpenRules = append(d.OpenRules, evidence)
		return
	}
	block := obj(peer["ipBlock"])
	prefix, err := netip.ParsePrefix(text(block["cidr"]))
	if len(peer) == 1 && err == nil && prefix.Bits() == 0 && len(arr(block["except"])) == 0 {
		d.OpenRules = append(d.OpenRules, evidence)
	}
}

func assessNetworkBaseline(report *SecurityReport, pod Object, s Snapshot) {
	for _, direction := range []string{"ingress", "egress"} {
		id := "netpol-" + direction
		if at(pod, "spec", "hostNetwork") == true {
			report.record(id, "unknown", Evidence{ref(pod), "spec.hostNetwork", "NetworkPolicy treatment of host-network pods is implementation-specific; deny-by-default cannot be established from these resources."})
			continue
		}
		graph := Graph{}
		result := evaluateDirection(direction, pod, s, &graph, ref(pod).ID())
		cilium := ciliumBaseline(direction, pod, s)
		evidence := append(result.Evidence, cilium.evidence...)
		open := append(result.OpenRules, cilium.open...)
		switch {
		case cilium.denyAll:
			report.record(id, "pass")
		case len(cilium.gaps) > 0 || result.Status == "unknown":
			report.record(id, "unknown", append(evidence, cilium.gaps...)...)
		case len(open) > 0 && cilium.denies:
			report.record(id, "unknown", append(open, Evidence{ref(pod), "Cilium deny precedence", "Selecting Cilium deny rules may constrain broad allows; effective overlap is outside this baseline check."})...)
		case len(open) > 0:
			report.record(id, "fail", open...)
		case result.Status == "unrestricted" && !cilium.isolated:
			report.record(id, "fail", append(evidence, Evidence{ref(pod), "Network policy baseline", "No selecting Kubernetes or readable Cilium policy enables default-deny for this direction."})...)
		default:
			report.record(id, "pass")
		}
	}
}
