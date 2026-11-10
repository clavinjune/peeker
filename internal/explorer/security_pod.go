package explorer

import "fmt"

func checkStatus(failed bool) string {
	if failed {
		return "fail"
	}
	return "pass"
}

func includes(values any, wanted string) bool {
	for _, v := range arr(values) {
		if text(v) == wanted {
			return true
		}
	}
	return false
}

func effectiveSetting(pod, container Object, prefix, key string) (any, string) {
	if value := at(container, "securityContext", key); value != nil {
		return value, prefix + ".securityContext." + key
	}
	return at(pod, "spec", "securityContext", key), "spec.securityContext." + key
}

func assessContainer(report *SecurityReport, pod, container Object, prefix string) {
	sc := obj(container["securityContext"])
	evidence := func(field, message string) Evidence {
		return Evidence{ref(pod), field, "Container " + text(container["name"]) + ": " + message}
	}
	report.record("privileged", checkStatus(sc["privileged"] == true), evidence(prefix+".securityContext.privileged", "Privileged mode is enabled."))
	uid, uidField := effectiveSetting(pod, container, prefix, "runAsUser")
	nonroot, _ := effectiveSetting(pod, container, prefix, "runAsNonRoot")
	status := "unknown"
	if uid != nil {
		status = checkStatus(uid == float64(0))
	} else if nonroot == true {
		status = "pass"
	}
	report.record("root", status, evidence(uidField, "Explicit UID is "+jsonText(uid)+"; an unspecified image user is not inferred."))
	added := at(sc, "capabilities", "add")
	dangerous := false
	for _, capability := range []string{"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "SYS_BOOT", "SYS_TIME", "DAC_READ_SEARCH", "DAC_OVERRIDE", "NET_ADMIN", "NET_RAW"} {
		dangerous = dangerous || includes(added, capability)
	}
	report.record("capabilities", checkStatus(dangerous), evidence(prefix+".securityContext.capabilities.add", "Added capabilities: "+jsonText(added)+"."))
	report.record("capability-defaults", checkStatus(!includes(at(sc, "capabilities", "drop"), "ALL")), evidence(prefix+".securityContext.capabilities.drop", "ALL is not explicitly dropped."))
	escalation := sc["allowPrivilegeEscalation"] != false || sc["privileged"] == true || includes(added, "SYS_ADMIN") || includes(added, "ALL")
	report.record("escalation", checkStatus(escalation), evidence(prefix+".securityContext", "Escalation is allowed by default, privileged mode or SYS_ADMIN."))
	profile, profileField := effectiveSetting(pod, container, prefix, "seccompProfile")
	status = "pass"
	switch text(obj(profile)["type"]) {
	case "RuntimeDefault", "Localhost":
	case "Unconfined":
		status = "fail"
	default:
		status = "unknown"
	}
	report.record("seccomp", status, evidence(profileField, "Profile is "+text(obj(profile)["type"])+"; node-level seccomp defaults are not inspected."))
	report.record("writable-root", checkStatus(sc["readOnlyRootFilesystem"] != true), evidence(prefix+".securityContext.readOnlyRootFilesystem", "Read-only root filesystem is not enabled."))
}

func mountedVolumes(pod Object) map[string]bool {
	mounted := map[string]bool{}
	for _, kind := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, c := range arr(at(pod, "spec", kind)) {
			for _, v := range arr(obj(c)["volumeMounts"]) {
				mounted[text(obj(v)["name"])] = true
			}
		}
	}
	return mounted
}

func assessPodSettings(report *SecurityReport, pod Object) {
	for _, field := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		report.record("host-namespaces", checkStatus(at(pod, "spec", field) == true), Evidence{ref(pod), "spec." + field, field + " is enabled."})
	}
	mounted := mountedVolumes(pod)
	hostPaths := []Evidence{}
	for i, v := range arr(at(pod, "spec", "volumes")) {
		if obj(v)["hostPath"] != nil && mounted[text(obj(v)["name"])] {
			hostPaths = append(hostPaths, Evidence{ref(pod), fmt.Sprintf("spec.volumes[%d].hostPath", i), "A hostPath volume is mounted; host file contents are not read."})
		}
	}
	report.record("host-path", checkStatus(len(hostPaths) > 0), hostPaths...)
	if at(pod, "spec", "os", "name") == "windows" || at(pod, "spec", "nodeSelector", "kubernetes.io/os") == "windows" {
		report.record("platform", "unknown", Evidence{ref(pod), "spec.os", "Windows container hardening is outside this assessment."})
		return
	}
	count := 0
	for _, kind := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for i, c := range arr(at(pod, "spec", kind)) {
			assessContainer(report, pod, obj(c), fmt.Sprintf("spec.%s[%d]", kind, i))
			count++
		}
	}
	if count == 0 {
		report.record("containers", "unknown", Evidence{ref(pod), "spec.containers", "No container specification was available."})
	}
}

func assessToken(report *SecurityReport, pod Object, s Snapshot) {
	mounted := mountedVolumes(pod)
	for i, v := range arr(at(pod, "spec", "volumes")) {
		if !mounted[text(obj(v)["name"])] {
			continue
		}
		for _, source := range arr(at(obj(v), "projected", "sources")) {
			if obj(source)["serviceAccountToken"] != nil {
				report.record("api-token", "fail", Evidence{ref(pod), fmt.Sprintf("spec.volumes[%d].projected.sources", i), "An explicit service-account token projection is mounted. Token contents are never read."})
				return
			}
		}
	}
	value, source, field := at(pod, "spec", "automountServiceAccountToken"), pod, "spec.automountServiceAccountToken"
	if value == nil {
		sa, found := s.find("serviceaccounts", namespace(pod), report.ServiceAccount)
		if !s.available("serviceaccounts") || !found {
			report.record("api-token", "unknown", Evidence{ref(pod), "spec.serviceAccountName", "ServiceAccount defaults are unavailable; token mounting is unknown."})
			return
		}
		value, source, field = sa["automountServiceAccountToken"], sa, "automountServiceAccountToken"
	}
	report.record("api-token", checkStatus(value != false), Evidence{ref(source), field, "Automatic token mounting is enabled or defaults to enabled."})
}
