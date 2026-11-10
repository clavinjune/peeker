package explorer

import (
	"sort"
	"strings"
)

type RiskSummary struct {
	Score      int    `json:"score"`
	Level      string `json:"level"`
	Findings   int    `json:"findings"`
	Checked    int    `json:"checked"`
	Unknown    int    `json:"unknown"`
	TopFinding string `json:"topFinding"`
}

type Finding struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	Summary     string     `json:"summary"`
	Remediation string     `json:"remediation"`
	Evidence    []Evidence `json:"evidence"`
}

type CheckGap struct {
	ID       string     `json:"id"`
	Evidence []Evidence `json:"evidence"`
}

type SecurityReport struct {
	Risk           RiskSummary `json:"risk"`
	ServiceAccount string      `json:"serviceAccount"`
	Findings       []Finding   `json:"findings"`
	Gaps           []CheckGap  `json:"gaps"`
}

type AssessmentOptions struct {
	ExpectIstio bool `json:"expectIstio"`
}

type findingRule struct {
	title, severity, summary, remediation string
}

var findingRules = map[string]findingRule{
	"istio-sidecar":       {"Istio proxy is missing", "medium", "This pod has no regular or native restartable-init istio-proxy container, while Istio sidecars are expected. Mesh traffic observations are unavailable; this does not prove whether other network controls protect the pod.", "Enable Istio sidecar injection on the intended workload and roll it out after reviewing compatibility. For intentionally sidecar-free or ambient clusters, start Peeker with -expect-istio=false; review infrastructure exceptions in context."},
	"netpol-ingress":      {"Ingress lacks deny-by-default", "medium", "Readable Kubernetes and Cilium policies do not establish ingress isolation, or a supported broad allowance opens peers on all ports. This violates the expected deny-by-default baseline; runtime enforcement and other controls are not proven.", "Select this pod with an ingress default-deny policy, then allow only required peers and ports. With Kubernetes NetworkPolicy, begin with no ingress rules; with Cilium, ensure enableDefaultDeny.ingress is true. Remove broad exceptions from selecting policies and review explicit deny precedence."},
	"netpol-egress":       {"Egress lacks deny-by-default", "medium", "Readable Kubernetes and Cilium policies do not establish egress isolation, or a supported broad allowance opens destinations on all ports. This violates the expected deny-by-default baseline; runtime enforcement and other controls are not proven.", "Select this pod with an egress default-deny policy, then allow required destinations and ports, including DNS where needed. With Kubernetes NetworkPolicy, begin with no egress rules; with Cilium, ensure enableDefaultDeny.egress is true. Remove broad exceptions and review explicit deny precedence."},
	"privileged":          {"Privileged container", "critical", "A container has privileged access to the host.", "Disable privileged mode; isolate workloads that genuinely require host privileges."},
	"root":                {"Root user configured", "high", "A container explicitly requests UID 0. This increases the impact of a compromise.", "Use a non-zero runAsUser and enforce runAsNonRoot."},
	"escalation":          {"Privilege escalation permitted", "medium", "The container does not prevent processes from gaining additional privileges.", "Set allowPrivilegeEscalation: false and remove privileged mode and SYS_ADMIN."},
	"capabilities":        {"Powerful Linux capabilities", "high", "Additional capabilities weaken isolation from the host or other workloads.", "Drop ALL capabilities and add back only the minimum required."},
	"capability-defaults": {"Default capabilities retained", "low", "The workload does not explicitly drop all default Linux capabilities.", "Set capabilities.drop: [ALL], then add narrowly required capabilities."},
	"seccomp":             {"Seccomp explicitly disabled", "medium", "An Unconfined profile removes the seccomp syscall filter.", "Use seccompProfile.type: RuntimeDefault or a reviewed Localhost profile."},
	"writable-root":       {"Writable container filesystem", "low", "The container root filesystem is writable.", "Set readOnlyRootFilesystem: true and mount dedicated writable volumes where needed."},
	"host-namespaces":     {"Host namespaces shared", "high", "The pod shares host networking, processes or IPC.", "Disable hostNetwork, hostPID and hostIPC unless required by reviewed infrastructure workloads."},
	"host-path":           {"Host filesystem mounted", "high", "A container mounts a hostPath volume, exposing host files or sockets.", "Replace hostPath with a scoped volume; review unavoidable host mounts and their permissions."},
	"api-token":           {"API credentials enabled", "low", "Automatic service-account credentials or an explicit projected token are enabled.", "Disable automountServiceAccountToken when API access is unnecessary and review explicit token projections."},
	"rbac-admin":          {"Cluster administrator permissions", "critical", "The service account has unrestricted verbs, API groups and resources through a cluster-wide binding.", "Replace the broad grant with resource-specific permissions and namespace-scoped bindings."},
	"rbac-wildcard":       {"Broad Kubernetes permissions", "high", "A matching RBAC grant uses wildcard permissions.", "Replace wildcards with required API groups, resources and verbs."},
	"rbac-secrets":        {"Can read Secrets", "high", "RBAC permits access to Secret objects in the binding's scope. Secret contents are never read by Peeker.", "Remove unnecessary Secrets reads and narrow any required access to named resources."},
	"rbac-exec":           {"Can access container sessions", "high", "RBAC permits exec or attach in the binding's scope.", "Remove exec and attach permissions from application service accounts."},
	"rbac-workloads":      {"Can change workloads", "high", "RBAC permits creating or modifying workloads. Admission controls may further restrict these actions.", "Limit workload writes to dedicated deployment identities."},
	"rbac-delegation":     {"Can delegate identity or permissions", "high", "RBAC grants bind, escalate, impersonate or service-account token creation. Exploitability depends on targets and other controls.", "Remove unnecessary delegation privileges and constrain permitted targets."},
}

var severityBase = map[string]int{"critical": 80, "high": 50, "medium": 20, "low": 5}

func (report *SecurityReport) record(id, status string, evidence ...Evidence) {
	if status == "unknown" {
		report.Risk.Unknown++
		report.Gaps = append(report.Gaps, CheckGap{id, evidence})
		return
	}
	report.Risk.Checked++
	if status != "fail" {
		return
	}
	for i := range report.Findings {
		if report.Findings[i].ID == id {
			report.Findings[i].Evidence = append(report.Findings[i].Evidence, evidence...)
			return
		}
	}
	rule := findingRules[id]
	report.Findings = append(report.Findings, Finding{id, rule.title, rule.severity, rule.summary, rule.remediation, evidence})
}

func (report *SecurityReport) finish() {
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Severity != b.Severity {
			return severityBase[a.Severity] > severityBase[b.Severity]
		}
		return a.ID < b.ID
	})
	report.Risk.Findings = len(report.Findings)
	report.Risk.Level = "none"
	if len(report.Findings) == 0 {
		if report.Risk.Unknown > 0 {
			report.Risk.Level = "unknown"
		}
		return
	}
	top := report.Findings[0]
	report.Risk.Level, report.Risk.TopFinding = top.Severity, top.Title
	bonus := 0
	for _, f := range report.Findings[1:] {
		bonus += max(1, severityBase[f.Severity]/5)
	}
	ceiling := map[string]int{"critical": 100, "high": 79, "medium": 49, "low": 19}[top.Severity]
	report.Risk.Score = min(ceiling, severityBase[top.Severity]+bonus)
}

func assessPod(pod Object, s Snapshot, options ...AssessmentOptions) SecurityReport {
	sa := text(at(pod, "spec", "serviceAccountName"))
	if sa == "" {
		sa = "default"
	}
	report := SecurityReport{ServiceAccount: sa, Findings: []Finding{}, Gaps: []CheckGap{}}
	assessPodSettings(&report, pod)
	assessToken(&report, pod, s)
	assessRBAC(&report, pod, s)
	assessNetworkBaseline(&report, pod, s)
	expectIstio := len(options) == 0 || options[0].ExpectIstio
	if expectIstio {
		status := "pass"
		if !podView(pod, s).Sidecar {
			status = "fail"
		}
		report.record("istio-sidecar", status, Evidence{ref(pod), "spec.containers / spec.initContainers", "Expected an istio-proxy regular container or restartable init sidecar; presence does not establish health or mesh enforcement."})
	}
	report.finish()
	return report
}

func inventoryPods(s Snapshot, filter string, options ...AssessmentOptions) []PodView {
	pods := []PodView{}
	for _, pod := range s.items("pods") {
		if strings.Contains(name(pod), filter) {
			view := podView(pod, s)
			view.Risk = assessPod(pod, s, options...).Risk
			pods = append(pods, view)
		}
	}
	sort.Slice(pods, func(i, j int) bool {
		a, b := pods[i], pods[j]
		if a.Risk.Score != b.Risk.Score {
			return a.Risk.Score > b.Risk.Score
		}
		if (a.Risk.Unknown > 0) != (b.Risk.Unknown > 0) {
			return a.Risk.Unknown > 0
		}
		return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
	})
	return pods
}
