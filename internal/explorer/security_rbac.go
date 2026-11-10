package explorer

import (
	"fmt"
	"strings"
)

var rbacCollections = map[string]bool{"roles": true, "rolebindings": true, "clusterroles": true, "clusterrolebindings": true}

type permissionGrant struct {
	rule     Object
	binding  Ref
	role     Ref
	evidence []Evidence
	cluster  bool
}

func boundServiceAccount(binding Object, ns, account string) bool {
	identity := "system:serviceaccount:" + ns + ":" + account
	for _, v := range arr(binding["subjects"]) {
		subject := obj(v)
		switch text(subject["kind"]) {
		case "ServiceAccount":
			subjectNS := text(subject["namespace"])
			if subjectNS == "" {
				subjectNS = namespace(binding)
			}
			if subjectNS == ns && subject["name"] == account && text(subject["apiGroup"]) == "" {
				return true
			}
		case "User":
			if subject["name"] == identity && subject["apiGroup"] == "rbac.authorization.k8s.io" {
				return true
			}
		case "Group":
			group := text(subject["name"])
			if subject["apiGroup"] == "rbac.authorization.k8s.io" && (group == "system:serviceaccounts" || group == "system:serviceaccounts:"+ns || group == "system:authenticated") {
				return true
			}
		}
	}
	return false
}

func accountGrants(ns, account string, s Snapshot) ([]permissionGrant, []Evidence) {
	x := s["rolebindings"].index
	if x == nil || x.grants == nil {
		return collectGrants(ns, account, s)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	key := ns + "/" + account
	if result, ok := x.grants[key]; ok {
		return result.grants, result.gaps
	}
	grants, gaps := collectGrants(ns, account, s)
	if len(x.grants) < 4096 {
		x.grants[key] = grantResult{grants, gaps}
	}
	return grants, gaps
}

func collectGrants(ns, account string, s Snapshot) ([]permissionGrant, []Evidence) {
	grants, gaps := []permissionGrant{}, []Evidence{}
	for _, key := range []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"} {
		if !s.available(key) {
			gaps = append(gaps, Evidence{Ref{Kind: "API", Name: key}, "read", key + " is unavailable; permission coverage is incomplete."})
		}
	}
	for _, key := range []string{"rolebindings", "clusterrolebindings"} {
		for _, binding := range s.bindings(key, ns, account) {
			if !boundServiceAccount(binding, ns, account) {
				continue
			}
			roleRef := obj(binding["roleRef"])
			collection, roleNS := "clusterroles", ""
			if roleRef["kind"] == "Role" && key == "rolebindings" {
				collection, roleNS = "roles", namespace(binding)
			} else if roleRef["kind"] != "ClusterRole" {
				gaps = append(gaps, Evidence{ref(binding), "roleRef", "Unsupported role reference."})
				continue
			}
			role, found := s.find(collection, roleNS, text(roleRef["name"]))
			if !found || !s.available(collection) || roleRef["apiGroup"] != "rbac.authorization.k8s.io" {
				gaps = append(gaps, Evidence{ref(binding), "roleRef", "The referenced role could not be resolved."})
				continue
			}
			if role["aggregationRule"] != nil && len(arr(role["rules"])) == 0 {
				gaps = append(gaps, Evidence{ref(role), "aggregationRule", "Aggregated rules have not been populated."})
			}
			scope := "namespace " + namespace(binding)
			if key == "clusterrolebindings" {
				scope = "cluster-wide"
			}
			for i, rule := range arr(role["rules"]) {
				constraint := ""
				if len(arr(obj(rule)["resourceNames"])) > 0 {
					constraint = "; restricted to named resources"
				}
				grants = append(grants, permissionGrant{rule: obj(rule), cluster: key == "clusterrolebindings", binding: ref(binding), role: ref(role), evidence: []Evidence{
					{ref(binding), "subjects / roleRef", "Service-account identity matches this binding; scope: " + scope + constraint + "."},
					{ref(role), fmt.Sprintf("rules[%d]", i), "API groups " + jsonText(obj(rule)["apiGroups"]) + "; resources " + jsonText(obj(rule)["resources"]) + "; verbs " + jsonText(obj(rule)["verbs"]) + constraint + "."},
				}})
			}
		}
	}
	return grants, gaps
}

func ruleAllows(rule Object, group, resource, verb string) bool {
	if !includes(rule["apiGroups"], group) && !includes(rule["apiGroups"], "*") {
		return false
	}
	if !includes(rule["verbs"], verb) && !includes(rule["verbs"], "*") {
		return false
	}
	if verb == "create" && !strings.Contains(resource, "/") && len(arr(rule["resourceNames"])) > 0 {
		return false
	}
	if includes(rule["resources"], "*") || includes(rule["resources"], resource) {
		return true
	}
	_, subresource, found := strings.Cut(resource, "/")
	return found && includes(rule["resources"], "*/"+subresource)
}

func grantRisks(grant permissionGrant) []string {
	rule := grant.rule
	risks := []string{}
	if grant.cluster && includes(rule["apiGroups"], "*") && includes(rule["resources"], "*") && includes(rule["verbs"], "*") && len(arr(rule["resourceNames"])) == 0 {
		risks = append(risks, "rbac-admin")
	}
	targets := []struct{ id, group, resource, verbs string }{
		{"rbac-secrets", "", "secrets", "get,list,watch"},
		{"rbac-exec", "", "pods/exec", "get,create"},
		{"rbac-exec", "", "pods/attach", "get,create"},
		{"rbac-workloads", "", "pods", "create,update,patch"},
		{"rbac-workloads", "", "pods/ephemeralcontainers", "update,patch"},
		{"rbac-workloads", "", "replicationcontrollers", "create,update,patch"},
		{"rbac-workloads", "apps", "deployments", "create,update,patch"},
		{"rbac-workloads", "apps", "statefulsets", "create,update,patch"},
		{"rbac-workloads", "apps", "daemonsets", "create,update,patch"},
		{"rbac-workloads", "apps", "replicasets", "create,update,patch"},
		{"rbac-workloads", "batch", "jobs", "create,update,patch"},
		{"rbac-workloads", "batch", "cronjobs", "create,update,patch"},
		{"rbac-delegation", "rbac.authorization.k8s.io", "roles", "bind,escalate"},
		{"rbac-delegation", "rbac.authorization.k8s.io", "clusterroles", "bind"},
		{"rbac-delegation", "", "serviceaccounts/token", "create"},
		{"rbac-delegation", "", "serviceaccounts", "impersonate"},
	}
	if grant.cluster {
		targets = append(targets, []struct{ id, group, resource, verbs string }{
			{"rbac-delegation", "rbac.authorization.k8s.io", "clusterroles", "escalate"},
			{"rbac-delegation", "", "users", "impersonate"},
			{"rbac-delegation", "", "groups", "impersonate"},
		}...)
	}
	for _, target := range targets {
		for _, verb := range strings.Split(target.verbs, ",") {
			if ruleAllows(rule, target.group, target.resource, verb) {
				risks = append(risks, target.id)
				break
			}
		}
	}
	if len(risks) > 0 && (includes(rule["apiGroups"], "*") || includes(rule["resources"], "*") || includes(rule["verbs"], "*")) {
		risks = append(risks, "rbac-wildcard")
	}
	return risks
}

func assessRBAC(report *SecurityReport, pod Object, s Snapshot) {
	grants, gaps := accountGrants(namespace(pod), report.ServiceAccount, s)
	findings := map[string][]Evidence{}
	for _, grant := range grants {
		seen := map[string]bool{}
		for _, id := range grantRisks(grant) {
			if !seen[id] {
				findings[id] = append(findings[id], grant.evidence...)
				seen[id] = true
			}
		}
	}
	for _, id := range []string{"rbac-admin", "rbac-wildcard", "rbac-secrets", "rbac-exec", "rbac-workloads", "rbac-delegation"} {
		switch {
		case len(findings[id]) > 0:
			report.record(id, "fail", findings[id]...)
		case len(gaps) > 0:
			report.record(id, "unknown", gaps...)
		default:
			report.record(id, "pass")
		}
	}
	if len(gaps) > 0 && len(findings) == 6 {
		report.record("rbac-coverage", "unknown", gaps...)
	}
}
