package explorer

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

func matches(selector any, values Object) (bool, error) {
	s := obj(selector)
	if s == nil {
		return false, fmt.Errorf("missing or invalid selector")
	}
	for key := range s {
		if key != "matchLabels" && key != "matchExpressions" {
			return false, fmt.Errorf("unsupported selector field %s", key)
		}
	}
	for k, v := range obj(s["matchLabels"]) {
		if _, ok := v.(string); !ok {
			return false, fmt.Errorf("invalid label value")
		}
		if values[k] != v {
			return false, nil
		}
	}
	for _, v := range arr(s["matchExpressions"]) {
		e := obj(v)
		key := text(e["key"])
		operation := text(e["operator"])
		if key == "" {
			return false, fmt.Errorf("expression without key")
		}
		value, exists := values[key]
		in := false
		for _, candidate := range arr(e["values"]) {
			if candidate == value {
				in = true
			}
		}
		switch operation {
		case "In":
			if len(arr(e["values"])) == 0 {
				return false, fmt.Errorf("In requires values")
			}
			if !exists || !in {
				return false, nil
			}
		case "NotIn":
			if len(arr(e["values"])) == 0 {
				return false, fmt.Errorf("NotIn requires values")
			}
			if exists && in {
				return false, nil
			}
		case "Exists":
			if len(arr(e["values"])) > 0 {
				return false, fmt.Errorf("Exists takes no values")
			}
			if !exists {
				return false, nil
			}
		case "DoesNotExist":
			if len(arr(e["values"])) > 0 {
				return false, fmt.Errorf("DoesNotExist takes no values")
			}
			if exists {
				return false, nil
			}
		default:
			return false, fmt.Errorf("unsupported selector operator %q", operation)
		}
	}
	return true, nil
}

type Direction struct {
	Status    string     `json:"status"`
	Summary   string     `json:"summary"`
	Evidence  []Evidence `json:"evidence"`
	OpenRules []Evidence `json:"-"`
}
type PolicyView struct {
	Resource  Ref        `json:"resource"`
	Selection string     `json:"selection"`
	Selector  any        `json:"selector"`
	Rules     []RuleView `json:"rules"`
	Notes     []string   `json:"notes"`
}
type RuleView struct {
	Field        string `json:"field"`
	Action       string `json:"action"`
	Peers        any    `json:"peers"`
	Ports        any    `json:"ports"`
	Restrictions any    `json:"restrictions,omitempty"`
}
type PolicyAnalysis struct {
	Ingress  Direction    `json:"ingress"`
	Egress   Direction    `json:"egress"`
	Policies []PolicyView `json:"policies"`
	Graph    Graph        `json:"graph"`
}

func policyTypes(spec Object) (bool, bool, error) {
	types := arr(spec["policyTypes"])
	if len(types) == 0 {
		return true, len(arr(spec["egress"])) > 0, nil
	}
	in, out := false, false
	for _, v := range types {
		switch v {
		case "Ingress":
			in = true
		case "Egress":
			out = true
		default:
			return false, false, fmt.Errorf("unknown policyType")
		}
	}
	return in, out, nil
}
func portSummary(value any) (string, error) {
	ports := arr(value)
	if len(ports) == 0 {
		return "all ports and protocols", nil
	}
	var result []string
	for _, v := range ports {
		p := obj(v)
		protocol := text(p["protocol"])
		if protocol == "" {
			protocol = "TCP"
		}
		if protocol != "TCP" && protocol != "UDP" && protocol != "SCTP" {
			return "unknown ports", fmt.Errorf("unsupported protocol")
		}
		port := "all ports"
		switch x := p["port"].(type) {
		case nil:
		case string:
			if x == "" {
				return "unknown ports", fmt.Errorf("empty named port")
			}
			port = "named " + x + " (destination pod port)"
		case float64:
			if x < 1 || x > 65535 || x != float64(int(x)) {
				return "unknown ports", fmt.Errorf("invalid port")
			}
			port = fmt.Sprintf("%.0f", x)
		default:
			return "unknown ports", fmt.Errorf("invalid port")
		}
		if end, ok := p["endPort"]; ok {
			start, numeric := p["port"].(float64)
			n, valid := end.(float64)
			if !numeric || !valid || n < start || n > 65535 {
				return "unknown ports", fmt.Errorf("invalid port range")
			}
			port += fmt.Sprintf("–%.0f", n)
		}
		result = append(result, protocol+" "+port)
	}
	return strings.Join(result, ", "), nil
}
func peerMatches(peer Object, policyNS string, pod Object, s Snapshot) (bool, error) {
	ps, hasPS := peer["podSelector"]
	ns, hasNS := peer["namespaceSelector"]
	if _, hasIP := peer["ipBlock"]; hasIP {
		return false, fmt.Errorf("IP blocks are not resolved to workloads because NAT order and CNI behavior vary")
	}
	if !hasPS && !hasNS {
		return true, nil
	}
	if hasNS {
		if !s.available("namespaces") {
			return false, fmt.Errorf("namespace labels unavailable")
		}
		n, found := s.find("namespaces", "", namespace(pod))
		if !found {
			return false, fmt.Errorf("namespace not found")
		}
		matched, err := matches(ns, labels(n))
		if err != nil || !matched {
			return matched, err
		}
	} else if namespace(pod) != policyNS {
		return false, nil
	}
	if hasPS {
		return matches(ps, labels(pod))
	}
	return true, nil
}
func peerDescription(peer Object, policyNS string, s Snapshot) (string, string, error) {
	for key := range peer {
		if key != "podSelector" && key != "namespaceSelector" && key != "ipBlock" {
			return "Unknown peer", "", fmt.Errorf("unsupported peer field %s", key)
		}
	}
	if block, ok := peer["ipBlock"]; ok {
		if len(peer) != 1 {
			return "Unknown peer", "", fmt.Errorf("ipBlock cannot combine with selectors")
		}
		b := obj(block)
		cidr, err := netip.ParsePrefix(text(b["cidr"]))
		if err != nil {
			return "Invalid CIDR", "", err
		}
		for _, v := range arr(b["except"]) {
			excluded, err := netip.ParsePrefix(text(v))
			if err != nil || !cidr.Contains(excluded.Addr()) || excluded.Bits() < cidr.Bits() {
				return "Invalid CIDR exception", "", fmt.Errorf("invalid IP block exception")
			}
		}
		return "CIDR " + cidr.String(), "IP block " + jsonText(block) + "; packet addresses can differ before/after NAT", nil
	}
	parts := []string{}
	if ns, ok := peer["namespaceSelector"]; ok {
		if _, err := matches(ns, Object{}); err != nil {
			return "Unknown namespace selector", "", err
		}
		parts = append(parts, "namespaces "+jsonText(ns))
	}
	if ps, ok := peer["podSelector"]; ok {
		if _, err := matches(ps, Object{}); err != nil {
			return "Unknown pod selector", "", err
		}
		if _, hasNS := peer["namespaceSelector"]; !hasNS {
			parts = append(parts, "namespace "+policyNS)
		}
		parts = append(parts, "pods "+jsonText(ps))
	}
	if len(parts) == 0 {
		return "All peers", "Empty peer permits all sources/destinations for this rule's ports", nil
	}
	matched := []string{}
	var evaluationError error
	if !s.available("pods") {
		evaluationError = fmt.Errorf("pods unavailable")
	}
	if x := s["pods"].index; x != nil && x.scope != "" {
		if _, crossNamespace := peer["namespaceSelector"]; crossNamespace {
			evaluationError = fmt.Errorf("pod inventory covers namespace %s only; cross-namespace matches are not enumerated", x.scope)
		}
	}
	for _, p := range s.items("pods") {
		ok, err := peerMatches(peer, policyNS, p, s)
		if err != nil {
			evaluationError = err
		}
		if ok {
			matched = append(matched, namespace(p)+"/"+name(p))
		}
	}
	sort.Strings(matched)
	shown := matched
	if len(shown) > 8 {
		shown = shown[:8]
	}
	description := fmt.Sprintf("%d matching current pods: %s. Selector is a configuration allowance, including future matches.", len(matched), strings.Join(shown, ", "))
	if evaluationError != nil {
		description = "Current matching pods unknown: " + evaluationError.Error()
	}
	return strings.Join(parts, " AND "), description, evaluationError
}

func networkPolicies(pod Object, s Snapshot) PolicyAnalysis {
	a := PolicyAnalysis{Policies: []PolicyView{}, Graph: Graph{Nodes: []Node{}, Edges: []Edge{}}}
	id := a.Graph.resource(ref(pod))
	a.Ingress = evaluateDirection("ingress", pod, s, &a.Graph, id)
	a.Egress = evaluateDirection("egress", pod, s, &a.Graph, id)
	for _, p := range s.inNamespace("networkpolicies", namespace(pod)) {
		if namespace(p) != namespace(pod) {
			continue
		}
		spec := obj(p["spec"])
		selected, err := matches(spec["podSelector"], labels(pod))
		if !selected && err == nil {
			continue
		}
		selection := "selects pod"
		notes := []string{}
		if err != nil {
			selection = "unknown"
			notes = append(notes, err.Error())
		}
		view := PolicyView{ref(p), selection, spec["podSelector"], []RuleView{}, notes}
		for _, direction := range []string{"ingress", "egress"} {
			peerKey := "from"
			if direction == "egress" {
				peerKey = "to"
			}
			for i, v := range arr(spec[direction]) {
				rule := obj(v)
				view.Rules = append(view.Rules, RuleView{fmt.Sprintf("spec.%s[%d]", direction, i), "allow", rule[peerKey], rule["ports"], nil})
			}
		}
		a.Policies = append(a.Policies, view)
	}
	addCilium(pod, s, &a)
	return a
}
func evaluateDirection(direction string, pod Object, s Snapshot, g *Graph, id string) Direction {
	d := Direction{Status: "unrestricted", Summary: "Not isolated by Kubernetes NetworkPolicy", Evidence: []Evidence{}}
	if !s.available("networkpolicies") {
		d.Status = "unknown"
		d.Summary = "NetworkPolicy inventory unavailable: " + s["networkpolicies"].State.Status
		d.Evidence = append(d.Evidence, Evidence{ref(pod), "NetworkPolicy inventory", d.Summary + "; no policy verdict is possible"})
		return directionNode(direction, id, g, d)
	}
	isolated, allowed, uncertain := false, false, false
	for _, p := range s.inNamespace("networkpolicies", namespace(pod)) {
		if namespace(p) != namespace(pod) {
			continue
		}
		spec := obj(p["spec"])
		selected, err := matches(spec["podSelector"], labels(pod))
		if err != nil {
			uncertain = true
			d.Evidence = append(d.Evidence, Evidence{ref(p), "spec.podSelector", err.Error()})
			continue
		}
		if !selected {
			continue
		}
		in, out, err := policyTypes(spec)
		if err != nil {
			uncertain = true
			d.Evidence = append(d.Evidence, Evidence{ref(p), "spec.policyTypes", err.Error()})
			continue
		}
		if (direction == "ingress" && !in) || (direction == "egress" && !out) {
			continue
		}
		isolated = true
		rules := arr(spec[direction])
		d.Evidence = append(d.Evidence, Evidence{ref(p), "spec." + direction, fmt.Sprintf("Selecting policy isolates %s; %d additive allow rules", direction, len(rules))})
		for i, v := range rules {
			allowed = true
			rule := obj(v)
			ports, portErr := portSummary(rule["ports"])
			key := "from"
			if direction == "egress" {
				key = "to"
			}
			peers := arr(rule[key])
			if len(peers) == 0 {
				peers = []any{map[string]any{}}
			}
			for j, v := range peers {
				label, description, peerErr := cachedPeerDescription(obj(v), namespace(p), s)
				state := "allowed"
				if portErr != nil || peerErr != nil {
					state = "unknown"
					uncertain = true
				}
				peerID := g.node(fmt.Sprintf("np:%s:%s:%d:%d", uid(p), direction, i, j), label, "peer", nil)
				field := fmt.Sprintf("spec.%s[%d]", direction, i)
				evidence := Evidence{ref(p), field, description + "; " + ports + ". Kubernetes NetworkPolicy allowance only; other enforcement is not evaluated here."}
				d.recordOpenRule(rule, obj(v), state, evidence)
				if direction == "ingress" {
					g.edge(peerID, id, state, ports, evidence)
				} else {
					g.edge(id, peerID, state, ports, evidence)
				}
			}
		}
	}
	if isolated {
		d.Status = "denied"
		d.Summary = "Isolated with no allowed traffic in this direction"
		if allowed {
			d.Status = "allowed"
			d.Summary = "Isolated with additive allow rules (peer rules are unioned across policies)"
		}
	}
	if uncertain {
		d.Status = "unknown"
		d.Summary = "Unknown or partially evaluated; inspect policy evidence and API availability"
	}
	if !isolated && !uncertain {
		d.Evidence = append(d.Evidence, Evidence{ref(pod), "metadata.labels", "Complete namespace NetworkPolicy inventory has no selecting policy isolating " + direction + ". This does not establish internet reachability or absence of other enforcement."})
	}
	if !allowed || uncertain {
		return directionNode(direction, id, g, d)
	}
	return d
}
func directionNode(direction, id string, g *Graph, d Direction) Direction {
	n := g.node("direction:"+direction, direction+": "+d.Summary, "direction", nil)
	if direction == "ingress" {
		g.edge(n, id, d.Status, "Kubernetes NetworkPolicy", d.Evidence...)
	} else {
		g.edge(id, n, d.Status, "Kubernetes NetworkPolicy", d.Evidence...)
	}
	return d
}

func ciliumLabels(pod Object, s Snapshot) Object {
	result := Object{"k8s:io.kubernetes.pod.namespace": namespace(pod), "io.kubernetes.pod.namespace": namespace(pod)}
	sa := text(at(pod, "spec", "serviceAccountName"))
	if sa == "" {
		sa = "default"
	}
	for k, v := range labels(pod) {
		if strings.HasPrefix(k, "io.cilium.k8s.namespace.labels.") {
			continue
		}
		result[k] = v
		result["k8s:"+k] = v
		result["any:"+k] = v
	}
	result["k8s:io.cilium.k8s.policy.serviceaccount"], result["io.cilium.k8s.policy.serviceaccount"], result["any:io.cilium.k8s.policy.serviceaccount"] = sa, sa, sa
	result["k8s:io.kubernetes.pod.namespace"], result["io.kubernetes.pod.namespace"], result["any:io.kubernetes.pod.namespace"] = namespace(pod), namespace(pod), namespace(pod)
	if n, ok := s.find("namespaces", "", namespace(pod)); ok {
		for k, v := range labels(n) {
			result["k8s:io.cilium.k8s.namespace.labels."+k] = v
			result["io.cilium.k8s.namespace.labels."+k] = v
			result["any:io.cilium.k8s.namespace.labels."+k] = v
		}
	}
	return result
}

type selectedRule struct {
	policy    Object
	spec      Object
	field     string
	selection string
}

func selectedCiliumRules(pod Object, s Snapshot) []selectedRule {
	selected := []selectedRule{}
	for _, key := range []string{"ciliumnetworkpolicies", "ciliumclusterwidenetworkpolicies"} {
		for _, p := range s.items(key) {
			if namespace(p) != "" && namespace(p) != namespace(pod) {
				continue
			}
			specs := append([]any{}, arr(p["specs"])...)
			fields := []string{}
			for i := range specs {
				fields = append(fields, fmt.Sprintf("specs[%d]", i))
			}
			if spec, ok := p["spec"]; ok {
				specs = append(specs, spec)
				fields = append(fields, "spec")
			}
			for i, v := range specs {
				spec := obj(v)
				if _, host := spec["nodeSelector"]; host {
					continue
				}
				ok, err := ciliumSelection(spec["endpointSelector"], pod, s)
				if !ok && err == nil {
					continue
				}
				selection := "selects pod"
				if err != nil {
					selection = "unknown"
				}
				selected = append(selected, selectedRule{p, spec, fields[i], selection})
			}
		}
	}
	return selected
}

func addCilium(pod Object, s Snapshot, a *PolicyAnalysis) {
	selected := selectedCiliumRules(pod, s)
	denyPresent := map[string]bool{}
	for _, r := range selected {
		for _, d := range []string{"ingress", "egress"} {
			if len(arr(r.spec[d+"Deny"])) > 0 {
				denyPresent[d] = true
			}
		}
	}
	for _, r := range selected {
		view := PolicyView{ref(r.policy), r.selection, r.spec["endpointSelector"], []RuleView{}, []string{"Partial Cilium rule inventory, not a complete effective-policy verdict. Deny rules take precedence over Cilium and Kubernetes allow rules. Identity resolution, node policies, DNS/FQDN state, services, L7, authentication and enforcement mode require runtime evaluation."}}
		view.Notes = append(view.Notes, "Default-deny configuration: "+jsonText(r.spec["enableDefaultDeny"])+"; omitted directions default to enabled only when that direction has allow or deny rules. Any selecting policy can enable default-deny.")
		for _, field := range []string{"ingress", "egress", "ingressDeny", "egressDeny"} {
			direction := strings.TrimSuffix(field, "Deny")
			action := "allow"
			if strings.HasSuffix(field, "Deny") {
				action = "deny"
			}
			for i, v := range arr(r.spec[field]) {
				rule := obj(v)
				peers := Object{}
				restrictions := Object{}
				for k, v := range rule {
					if strings.HasPrefix(k, "from") || strings.HasPrefix(k, "to") && k != "toPorts" {
						peers[k] = v
					} else if k != "toPorts" {
						restrictions[k] = v
					}
				}
				ports := []any{}
				for _, v := range arr(rule["toPorts"]) {
					p := obj(v)
					ports = append(ports, p["ports"])
					if l7, ok := p["rules"]; ok {
						kinds := []string{}
						for kind := range obj(l7) {
							kinds = append(kinds, kind)
						}
						sort.Strings(kinds)
						restrictions["L7"] = kinds
						restrictions["L7 details"] = "Restrictions are displayed, not evaluated. Header values, credentials and secret references are withheld."
						for _, kind := range kinds {
							rows := []Object{}
							for _, value := range arr(obj(l7)[kind]) {
								row := Object{}
								for _, key := range []string{"method", "path", "host", "matchName", "matchPattern", "apiKey", "apiVersion", "topic"} {
									if v, exists := obj(value)[key]; exists {
										row[key] = v
									}
								}
								rows = append(rows, row)
							}
							restrictions[kind] = rows
						}
					}
				}
				path := fmt.Sprintf("%s.%s[%d]", r.field, field, i)
				view.Rules = append(view.Rules, RuleView{path, action, peers, ports, restrictions})
				status := "unknown"
				description := "Configured Cilium " + action + " rule; partial evaluation only"
				if action == "deny" {
					status = "denied"
					description += "; takes precedence over matching allow rules"
				}
				if action == "allow" && denyPresent[direction] {
					description += "; selecting deny rules exist, so this is not an effective allowance"
				}
				peer := a.Graph.node(fmt.Sprintf("cilium:%s:%s", uid(r.policy), path), "Cilium "+action+": "+jsonText(peers), "peer", nil)
				e := Evidence{ref(r.policy), path, description + "; ports " + jsonText(ports) + "; restrictions " + jsonText(restrictions)}
				if direction == "ingress" {
					a.Graph.edge(peer, ref(pod).ID(), status, "Cilium "+action, e)
				} else {
					a.Graph.edge(ref(pod).ID(), peer, status, "Cilium "+action, e)
				}
			}
		}
		a.Policies = append(a.Policies, view)
	}
}
