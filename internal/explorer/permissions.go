package explorer

type permissionView struct {
	Binding  Ref        `json:"binding"`
	Role     Ref        `json:"role"`
	Scope    string     `json:"scope"`
	Rule     Object     `json:"rule"`
	Evidence []Evidence `json:"evidence"`
}

type permissionReport struct {
	ServiceAccount Ref              `json:"serviceAccount"`
	Identity       string           `json:"identity"`
	Status         string           `json:"status"`
	Grants         []permissionView `json:"grants"`
	Gaps           []Evidence       `json:"gaps"`
}

func podPermissions(pod Object, s Snapshot) permissionReport {
	account := text(at(pod, "spec", "serviceAccountName"))
	if account == "" {
		account = "default"
	}
	ns := namespace(pod)
	grants, gaps := accountGrants(ns, account, s)
	report := permissionReport{ServiceAccount: Ref{Kind: "ServiceAccount", Namespace: ns, Name: account, APIVersion: "v1"}, Identity: "system:serviceaccount:" + ns + ":" + account, Status: "available", Grants: []permissionView{}, Gaps: append([]Evidence{}, gaps...)}
	sa, found := s.find("serviceaccounts", ns, account)
	if !found || !s.available("serviceaccounts") {
		report.Status = "unresolved"
		report.Gaps = append(report.Gaps, Evidence{report.ServiceAccount, "read", "The pod's ServiceAccount object could not be resolved. Listed grants match the declared identity; credential availability is not established."})
	} else {
		report.ServiceAccount = ref(sa)
	}
	for _, grant := range grants {
		scope := "namespace " + grant.binding.Namespace
		if grant.cluster {
			scope = "cluster-wide"
		}
		rule := Object{}
		for _, key := range []string{"apiGroups", "resources", "verbs", "resourceNames", "nonResourceURLs"} {
			values := []string{}
			for _, value := range arr(grant.rule[key]) {
				if text, ok := value.(string); ok {
					values = append(values, text)
				}
			}
			rule[key] = values
		}
		report.Grants = append(report.Grants, permissionView{Binding: grant.binding, Role: grant.role, Scope: scope, Rule: rule, Evidence: grant.evidence})
	}
	return report
}
