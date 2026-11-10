package explorer

import (
	"fmt"
	"maps"
	"net/netip"
)

type ciliumBaselineResult struct {
	isolated, denyAll, denies bool
	open, evidence, gaps      []Evidence
}

func ciliumRuleBreadth(rule Object, direction string) string {
	if rule == nil {
		return "unknown"
	}
	if len(rule) == 0 {
		return "all"
	}
	rule = maps.Clone(rule)
	if value, ok := rule["toPorts"]; ok && len(arr(value)) == 0 {
		delete(rule, "toPorts")
	}
	if len(rule) == 0 {
		return "all"
	}
	prefix := "from"
	if direction == "egress" {
		prefix = "to"
	}
	if len(rule) != 1 {
		return "restricted"
	}
	for _, entity := range arr(rule[prefix+"Entities"]) {
		if entity == "all" {
			return "all"
		}
	}
	for _, entity := range arr(rule[prefix+"Entities"]) {
		if entity == "world" || entity == "world-ipv4" || entity == "world-ipv6" {
			return "world"
		}
	}
	for _, value := range arr(rule[prefix+"CIDR"]) {
		prefix, err := netip.ParsePrefix(text(value))
		if err == nil && prefix.Bits() == 0 {
			return "world"
		}
	}
	for _, value := range arr(rule[prefix+"CIDRSet"]) {
		block := obj(value)
		prefix, err := netip.ParsePrefix(text(block["cidr"]))
		if err == nil && prefix.Bits() == 0 && len(arr(block["except"])) == 0 {
			return "world"
		}
	}
	return "restricted"
}

func (result *ciliumBaselineResult) add(r selectedRule, direction string) {
	if r.selection != "selects pod" {
		result.gaps = append(result.gaps, Evidence{ref(r.policy), r.field + ".endpointSelector", "Cilium policy selection is unresolved."})
		return
	}
	allow, deny := arr(r.spec[direction]), arr(r.spec[direction+"Deny"])
	enabled := len(allow)+len(deny) > 0
	if value, exists := obj(r.spec["enableDefaultDeny"])[direction]; exists {
		var ok bool
		enabled, ok = value.(bool)
		if !ok {
			result.gaps = append(result.gaps, Evidence{ref(r.policy), r.field + ".enableDefaultDeny." + direction, "Unrecognized default-deny value."})
		}
	}
	result.isolated = result.isolated || enabled
	result.denies = result.denies || len(deny) > 0
	result.evidence = append(result.evidence, Evidence{ref(r.policy), r.field + ".enableDefaultDeny." + direction, fmt.Sprintf("Selecting Cilium policy requests default-deny=%t; %d allow and %d deny rules. Default-deny is enabled if any selecting policy requests it.", enabled, len(allow), len(deny))})
	for i, value := range allow {
		breadth := ciliumRuleBreadth(obj(value), direction)
		if breadth == "all" || breadth == "world" {
			result.open = append(result.open, Evidence{ref(r.policy), fmt.Sprintf("%s.%s[%d]", r.field, direction, i), "Cilium " + breadth + " allowance has no port restrictions. Configured broad access is outside the expected narrow-exception baseline."})
		}
		if breadth == "unknown" {
			result.gaps = append(result.gaps, Evidence{ref(r.policy), r.field + "." + direction, "Unrecognized Cilium rule."})
		}
	}
	for _, value := range deny {
		result.denyAll = result.denyAll || ciliumRuleBreadth(obj(value), direction) == "all"
	}
}

func ciliumBaseline(direction string, pod Object, s Snapshot) ciliumBaselineResult {
	result := ciliumBaselineResult{}
	for _, key := range []string{"ciliumnetworkpolicies", "ciliumclusterwidenetworkpolicies"} {
		if !s.available(key) && s[key].State.Status != "missing-api" {
			result.gaps = append(result.gaps, Evidence{ref(pod), key + " inventory", "Cilium policy discovery or reads are unavailable; this is not evidence of missing protection."})
		}
	}
	for _, rule := range selectedCiliumRules(pod, s) {
		result.add(rule, direction)
	}
	return result
}
