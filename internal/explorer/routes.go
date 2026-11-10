package explorer

import (
	"fmt"
	"strings"
)

type Relationship struct {
	Route       Ref        `json:"route"`
	Service     Ref        `json:"service"`
	Status      string     `json:"status"`
	Description string     `json:"description"`
	Evidence    []Evidence `json:"evidence"`
}
type Routing struct {
	Relationships []Relationship `json:"relationships"`
	Graph         Graph          `json:"graph"`
}
type serviceMatch struct {
	service  Object
	evidence []Evidence
}

func selectedServices(pod Object, s Snapshot) []serviceMatch {
	result := []serviceMatch{}
	for _, service := range s.items("services") {
		evidence := []Evidence{}
		selector := obj(at(service, "spec", "selector"))
		if namespace(service) == namespace(pod) && len(selector) > 0 {
			ok, err := matches(map[string]any{"matchLabels": map[string]any(selector)}, labels(pod))
			if ok && err == nil {
				evidence = append(evidence, Evidence{ref(service), "spec.selector", "Service selector matches pod labels: " + jsonText(selector)})
			}
		}
		for _, slice := range s.items("endpointslices") {
			if namespace(slice) != namespace(service) || labels(slice)["kubernetes.io/service-name"] != name(service) {
				continue
			}
			for i, v := range arr(slice["endpoints"]) {
				e := obj(v)
				target := obj(e["targetRef"])
				matched := target["kind"] == "Pod" && target["name"] == name(pod) && target["uid"] == uid(pod) && (target["namespace"] == namespace(pod) || target["namespace"] == nil && namespace(slice) == namespace(pod))
				if matched {
					evidence = append(evidence, Evidence{ref(slice), fmt.Sprintf("endpoints[%d].targetRef", i), "EndpointSlice references pod UID; conditions " + jsonText(e["conditions"]) + "; ports " + jsonText(slice["ports"])})
				}
			}
		}
		if len(evidence) > 0 {
			result = append(result, serviceMatch{service, evidence})
		}
	}
	return result
}
func servicePort(service Object, port any) (bool, string) {
	ports := arr(at(service, "spec", "ports"))
	if port == nil && len(ports) == 1 {
		return true, jsonText(ports[0])
	}
	for _, v := range ports {
		p := obj(v)
		if port != nil && (p["port"] == port || p["name"] == port) {
			return true, jsonText(p)
		}
	}
	return false, "Referenced port is missing or ambiguous on Service"
}
func hostService(host, ns string) (string, string, bool) {
	parts := strings.Split(strings.TrimSuffix(host, "."), ".")
	switch len(parts) {
	case 1:
		return ns, parts[0], validName(parts[0], true)
	case 2:
		return parts[1], parts[0], validName(parts[0], true) && validName(parts[1], true)
	case 3:
		return parts[1], parts[0], parts[2] == "svc"
	case 5:
		return parts[1], parts[0], parts[2] == "svc" && parts[3] == "cluster" && parts[4] == "local"
	}
	return "", "", false
}
func exported(resource Object, consumer string) bool {
	values := arr(at(resource, "spec", "exportTo"))
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if v == "*" || v == consumer || v == "." && namespace(resource) == consumer {
			return true
		}
	}
	return false
}
func subsetMatches(pod, vs, service Object, destination Object, s Snapshot) (bool, string, []Evidence) {
	subset := text(destination["subset"])
	if subset == "" {
		return true, "", nil
	}
	if !s.available("destinationrules") {
		return true, "unknown: DestinationRules unavailable", nil
	}
	candidates := []Object{}
	for _, dr := range s.items("destinationrules") {
		ns, n, ok := hostService(text(at(dr, "spec", "host")), namespace(dr))
		if ok && ns == namespace(service) && n == name(service) && exported(dr, namespace(vs)) {
			candidates = append(candidates, dr)
		}
	}
	if len(candidates) != 1 {
		return true, "unknown: DestinationRule resolution missing or ambiguous", nil
	}
	dr := candidates[0]
	for i, v := range arr(at(dr, "spec", "subsets")) {
		sub := obj(v)
		if sub["name"] != subset {
			continue
		}
		ok, err := matches(map[string]any{"matchLabels": sub["labels"]}, labels(pod))
		e := []Evidence{{ref(dr), fmt.Sprintf("spec.subsets[%d]", i), "Destination subset " + subset + " selects labels " + jsonText(sub["labels"])}}
		if err != nil {
			return true, "unknown: invalid subset selector", e
		}
		return ok, "", e
	}
	return true, "unknown: referenced subset is not defined", nil
}
func granted(route Object, targetNS, target string, s Snapshot) (string, []Evidence) {
	if namespace(route) == targetNS {
		return "permitted", nil
	}
	if !s.available("referencegrants") {
		return "unknown", nil
	}
	for _, grant := range s.items("referencegrants") {
		if namespace(grant) != targetNS {
			continue
		}
		fromOK, toOK := false, false
		for _, v := range arr(at(grant, "spec", "from")) {
			f := obj(v)
			if f["group"] == "gateway.networking.k8s.io" && f["kind"] == route["kind"] && f["namespace"] == namespace(route) {
				fromOK = true
			}
		}
		for _, v := range arr(at(grant, "spec", "to")) {
			to := obj(v)
			if to["group"] == "" && to["kind"] == "Service" && (to["name"] == nil || to["name"] == target) {
				toOK = true
			}
		}
		if fromOK && toOK {
			return "permitted", []Evidence{{ref(grant), "spec", "ReferenceGrant authorizes this cross-namespace Service reference"}}
		}
	}
	return "forbidden", nil
}
func condition(o Object, conditions any, kind string) string {
	for _, v := range arr(conditions) {
		c := obj(v)
		if c["type"] == kind {
			if c["observedGeneration"] != at(o, "metadata", "generation") {
				return "stale or unknown"
			}
			return text(c["status"])
		}
	}
	return "unknown"
}
func parentRef(v Object, ns string) (string, string) {
	if target := text(v["namespace"]); target != "" {
		ns = target
	}
	return ns, text(v["name"])
}
func sameParent(a, b Object, ns string) bool {
	an, aa := parentRef(a, ns)
	bn, bb := parentRef(b, ns)
	return an == bn && aa == bb && a["sectionName"] == b["sectionName"] && a["port"] == b["port"]
}
func routeStatus(route Object) string {
	for _, v := range arr(at(route, "status", "parents")) {
		p := obj(v)
		referenced := false
		for _, spec := range arr(at(route, "spec", "parentRefs")) {
			if sameParent(obj(spec), obj(p["parentRef"]), namespace(route)) {
				referenced = true
			}
		}
		if referenced && condition(route, p["conditions"], "Accepted") == "True" && condition(route, p["conditions"], "ResolvedRefs") == "True" {
			return "accepted"
		}
	}
	return "configured"
}
func attachGateway(g *Graph, route Object, s Snapshot) []Evidence {
	evidence := []Evidence{}
	for i, v := range arr(at(route, "spec", "parentRefs")) {
		parent := obj(v)
		if parent["kind"] != nil && parent["kind"] != "Gateway" || parent["group"] != nil && parent["group"] != "gateway.networking.k8s.io" {
			continue
		}
		ns, n := parentRef(parent, namespace(route))
		gateway, found := s.find("gateways", ns, n)
		if !found {
			evidence = append(evidence, Evidence{ref(route), fmt.Sprintf("spec.parentRefs[%d]", i), "Gateway parent unresolved: " + ns + "/" + n})
			continue
		}
		description := "Configured attachment; listener constraints and controller status determine acceptance. Gateway Programmed=" + condition(gateway, at(gateway, "status", "conditions"), "Programmed")
		for j, v := range arr(at(gateway, "spec", "listeners")) {
			l := obj(v)
			if parent["sectionName"] != nil && parent["sectionName"] != l["name"] || parent["port"] != nil && parent["port"] != l["port"] {
				continue
			}
			description += fmt.Sprintf("; listener[%d] name=%s protocol=%s port=%v hostname=%s allowedRoutes=%s", j, text(l["name"]), text(l["protocol"]), l["port"], text(l["hostname"]), jsonText(l["allowedRoutes"]))
		}
		for _, v := range arr(at(route, "status", "parents")) {
			p := obj(v)
			if sameParent(parent, obj(p["parentRef"]), namespace(route)) {
				description += "; Accepted=" + condition(route, p["conditions"], "Accepted") + " ResolvedRefs=" + condition(route, p["conditions"], "ResolvedRefs")
			}
		}
		e := Evidence{ref(route), fmt.Sprintf("spec.parentRefs[%d]", i), description}
		evidence = append(evidence, e)
		g.edge(g.resource(ref(gateway)), g.resource(ref(route)), "unknown", "configured attachment", e, Evidence{ref(gateway), "spec.listeners", "Listener configuration; no external reachability probe"})
	}
	return evidence
}
func addRelationship(result *Routing, route Object, service serviceMatch, field, status, description string, extra ...Evidence) {
	evidence := append([]Evidence{{ref(route), field, description}}, service.evidence...)
	evidence = append(evidence, extra...)
	result.Relationships = append(result.Relationships, Relationship{ref(route), ref(service.service), status, description, evidence})
	result.Graph.edge(result.Graph.resource(ref(route)), result.Graph.resource(ref(service.service)), "unknown", status+" backend reference", evidence...)
}
func routing(pod Object, s Snapshot) Routing {
	r := Routing{Relationships: []Relationship{}, Graph: Graph{Nodes: []Node{}, Edges: []Edge{}}}
	id := r.Graph.resource(ref(pod))
	previous := id
	child := ref(pod)
	for _, owner := range ownership(pod, s).Owners {
		next := r.Graph.resource(owner)
		r.Graph.edge(next, previous, "unknown", "controlling ownerReference", Evidence{child, "metadata.ownerReferences", "Controlling reference to UID " + owner.UID + "; inspect ownership resolution status"})
		previous = next
		child = owner
	}
	services := selectedServices(pod, s)
	for _, service := range services {
		r.Graph.edge(r.Graph.resource(ref(service.service)), id, "unknown", "selects / references pod", service.evidence...)
	}
	for _, ingress := range s.items("ingresses") {
		backends := []struct {
			backend Object
			field   string
		}{}
		if b := obj(at(ingress, "spec", "defaultBackend")); b != nil {
			backends = append(backends, struct {
				backend Object
				field   string
			}{b, "spec.defaultBackend"})
		}
		for i, v := range arr(at(ingress, "spec", "rules")) {
			for j, p := range arr(at(obj(v), "http", "paths")) {
				backends = append(backends, struct {
					backend Object
					field   string
				}{obj(obj(p)["backend"]), fmt.Sprintf("spec.rules[%d].http.paths[%d].backend", i, j)})
			}
		}
		for _, b := range backends {
			for _, service := range services {
				backend := obj(b.backend["service"])
				if namespace(ingress) != namespace(service.service) || backend["name"] != name(service.service) {
					continue
				}
				port := at(backend, "port", "number")
				if port == nil {
					port = at(backend, "port", "name")
				}
				ok, ports := servicePort(service.service, port)
				status := "configured"
				if !ok {
					status = "invalid-port"
				}
				addRelationship(&r, ingress, service, b.field, status, "Ingress configured reference; "+ports+"; loadBalancer status "+jsonText(at(ingress, "status", "loadBalancer"))+". Ingress has no universal accepted condition; external reachability unverified.")
			}
		}
	}
	for _, vs := range s.items("virtualservices") {
		for _, protocol := range []string{"http", "tcp", "tls"} {
			for i, v := range arr(at(vs, "spec", protocol)) {
				rule := obj(v)
				for j, b := range arr(rule["route"]) {
					backend := obj(b)
					destination := obj(backend["destination"])
					ns, n, valid := hostService(text(destination["host"]), namespace(vs))
					if !valid {
						continue
					}
					for _, service := range services {
						if ns != namespace(service.service) || n != name(service.service) {
							continue
						}
						matches, warning, subsetEvidence := subsetMatches(pod, vs, service.service, destination, s)
						if !matches {
							continue
						}
						ok, ports := servicePort(service.service, at(destination, "port", "number"))
						status := "configured"
						if !ok {
							status = "invalid-port"
						}
						if warning != "" {
							status = "unknown"
						}
						if backend["weight"] == float64(0) {
							status = "zero-weight"
						}
						field := fmt.Sprintf("spec.%s[%d].route[%d].destination", protocol, i, j)
						addRelationship(&r, vs, service, field, status, "Istio destination "+text(destination["host"])+"; "+ports+"; "+warning+". Route match predicates, export visibility, mesh authorization and packet delivery are not a reachability verdict.", subsetEvidence...)
						for k, v := range arr(at(vs, "spec", "gateways")) {
							value := text(v)
							if value == "mesh" {
								continue
							}
							gatewayNS := namespace(vs)
							gatewayName := value
							if parts := strings.Split(value, "/"); len(parts) == 2 {
								gatewayNS = parts[0]
								gatewayName = parts[1]
							}
							if gateway, found := s.find("istiogateways", gatewayNS, gatewayName); found {
								r.Graph.edge(r.Graph.resource(ref(gateway)), r.Graph.resource(ref(vs)), "unknown", "configured Istio gateway", Evidence{ref(vs), fmt.Sprintf("spec.gateways[%d]", k), "Explicit gateway reference; exportTo=" + jsonText(at(vs, "spec", "exportTo"))}, Evidence{ref(gateway), "spec", "Gateway selector=" + jsonText(at(gateway, "spec", "selector")) + "; server hosts/ports require matching with VirtualService hosts"})
							}
						}
					}
				}
			}
		}
	}
	for _, key := range []string{"httproutes", "tcproutes"} {
		for _, route := range s.items(key) {
			attached := false
			for i, v := range arr(at(route, "spec", "rules")) {
				for j, b := range arr(obj(v)["backendRefs"]) {
					backend := obj(b)
					if backend["group"] != nil && backend["group"] != "" || backend["kind"] != nil && backend["kind"] != "Service" {
						continue
					}
					ns, n := parentRef(backend, namespace(route))
					for _, service := range services {
						if ns != namespace(service.service) || n != name(service.service) {
							continue
						}
						permission, grantEvidence := granted(route, ns, n, s)
						status := routeStatus(route)
						if permission != "permitted" {
							status = permission
						}
						ok, ports := servicePort(service.service, backend["port"])
						if !ok {
							status = "invalid-port"
						}
						if backend["weight"] == float64(0) {
							status = "zero-weight"
						}
						if !attached {
							attachGateway(&r.Graph, route, s)
							attached = true
						}
						addRelationship(&r, route, service, fmt.Sprintf("spec.rules[%d].backendRefs[%d]", i, j), status, "Backend Service reference; cross-namespace permission="+permission+"; "+ports+". Accepted means current controller Accepted+ResolvedRefs conditions, not verified external reachability. Listener/match constraints still apply.", grantEvidence...)
					}
				}
			}
		}
	}
	return r
}
