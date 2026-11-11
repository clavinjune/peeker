package explorer

import (
	"strings"
	"time"
)

func curatedSettings(pod, container Object) Object {
	sc := obj(container["securityContext"])
	settings := Object{}
	for _, key := range []string{"privileged", "allowPrivilegeEscalation", "readOnlyRootFilesystem", "capabilities"} {
		settings[key] = sc[key]
	}
	for _, key := range []string{"runAsUser", "runAsGroup", "runAsNonRoot", "seccompProfile", "appArmorProfile"} {
		settings[key], _ = effectiveSetting(pod, container, "", key)
	}
	if settings["appArmorProfile"] == nil {
		settings["appArmorAnnotation"] = at(pod, "metadata", "annotations", "container.apparmor.security.beta.kubernetes.io/"+text(container["name"]))
	}
	return settings
}

func referenceNames(pod Object) []Object {
	result := []Object{}
	seen := map[string]bool{}
	add := func(kind, n, field string) {
		if n != "" && !seen[kind+"/"+n+"/"+field] {
			seen[kind+"/"+n+"/"+field] = true
			result = append(result, Object{"kind": kind, "name": n, "field": field})
		}
	}
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, value := range arr(at(pod, "spec", key)) {
			c := obj(value)
			prefix := key + "/" + text(c["name"])
			for _, v := range arr(c["env"]) {
				e := obj(v)
				add("Secret", text(at(e, "valueFrom", "secretKeyRef", "name")), prefix+"/env")
				add("ConfigMap", text(at(e, "valueFrom", "configMapKeyRef", "name")), prefix+"/env")
			}
			for _, v := range arr(c["envFrom"]) {
				e := obj(v)
				add("Secret", text(at(e, "secretRef", "name")), prefix+"/envFrom")
				add("ConfigMap", text(at(e, "configMapRef", "name")), prefix+"/envFrom")
			}
		}
	}
	for _, v := range arr(at(pod, "spec", "volumes")) {
		volume := obj(v)
		field := "volumes/" + text(volume["name"])
		add("Secret", text(at(volume, "secret", "secretName")), field)
		add("ConfigMap", text(at(volume, "configMap", "name")), field)
		for _, p := range arr(at(volume, "projected", "sources")) {
			add("Secret", text(at(obj(p), "secret", "name")), field)
			add("ConfigMap", text(at(obj(p), "configMap", "name")), field)
		}
		add("Secret", text(at(volume, "csi", "nodePublishSecretRef", "name")), field)
	}
	for _, v := range arr(at(pod, "spec", "imagePullSecrets")) {
		add("Secret", text(obj(v)["name"]), "imagePullSecrets")
	}
	return result
}

func containerEvidence(pod Object) []Object {
	result := []Object{}
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, v := range arr(at(pod, "spec", key)) {
			c := obj(v)
			image := text(c["image"])
			distroless := "Unknown: image contents and provenance must be verified"
			if strings.Contains(strings.ToLower(image), "distroless") {
				distroless = "Image-name hint only; not verified distroless"
			}
			result = append(result, Object{"name": c["name"], "type": key, "image": image, "observedImage": observedImage(pod, text(c["name"])), "digestPinned": digestImage.MatchString(image), "distroless": distroless, "settings": curatedSettings(pod, c)})
		}
	}
	return result
}

func observedImage(pod Object, container string) string {
	for _, key := range []string{"containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"} {
		for _, v := range arr(at(pod, "status", key)) {
			status := obj(v)
			image := strings.TrimPrefix(text(status["imageID"]), "docker-pullable://")
			if status["name"] == container && digestImage.MatchString(image) {
				return image
			}
		}
	}
	return ""
}

func podEvidence(p Object, s Snapshot, options AssessmentOptions) Object {
	security := assessPod(p, s, options)
	view := podView(p, s)
	view.Risk = security.Risk
	host := Object{}
	for _, key := range []string{"hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace", "hostUsers"} {
		host[key] = at(p, "spec", key)
	}
	services := []Object{}
	for _, m := range selectedServices(p, s) {
		services = append(services, Object{"resource": ref(m.service), "type": at(m.service, "spec", "type"), "externalIPs": at(m.service, "spec", "externalIPs"), "loadBalancer": at(m.service, "status", "loadBalancer")})
	}
	return Object{"pod": view, "security": security, "permissions": podPermissions(p, s), "policies": networkPolicies(p, s), "routing": routing(p, s), "containers": containerEvidence(p), "host": host, "references": referenceNames(p), "services": services}
}

func workloadReport(o Object, s Snapshot, options AssessmentOptions, registered, actions bool) Object {
	pods := []Object{}
	count := 0
	for _, p := range s.items("pods") {
		if ownedBy(p, o, s) {
			count++
			if len(pods) < 100 {
				pods = append(pods, podEvidence(p, s, options))
			}
		}
	}
	template := workloadTemplate(o)
	recommendations := []string{"Review the template and every running Pod: admission and image defaults can differ.", "Use a dedicated ServiceAccount with least-privilege grants; disable automatic API credentials when unused.", "Apply least-privilege ingress and egress rules and verify enforcement in the cluster."}
	for _, c := range containerEvidence(template) {
		if c["digestPinned"] != true {
			recommendations = append(recommendations, "Pin "+text(c["name"])+" to an immutable image digest; scan that digest and rebuild for fixable vulnerabilities.")
		}
	}
	recommendations = append(recommendations, "Use a verified minimal/distroless base where compatible; image names alone do not establish contents.", "Set runAsNonRoot, allowPrivilegeEscalation=false, readOnlyRootFilesystem=true, drop ALL capabilities, and use RuntimeDefault seccomp plus an enforced AppArmor profile where supported. Read-only root does not make mounted volumes immutable.")
	return Object{"resource": ref(o), "registered": registered, "actionsAvailable": actions, "template": podEvidence(template, s, options), "pods": pods, "podCount": count, "podsTruncated": count > len(pods), "states": s.states(), "capturedAt": time.Now().UTC().Format(time.RFC3339), "recommendations": recommendations}
}
