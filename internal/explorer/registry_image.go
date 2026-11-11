package explorer

import (
	"encoding/json"
	"net/url"
	"sort"
)

// Classification describes the scanned package inventory, not image provenance or
// a complete filesystem audit. Unpackaged binaries need independent verification.
type imageClassification struct {
	Status       string      `json:"status"`
	Summary      string      `json:"summary"`
	Digest       string      `json:"digest,omitempty"`
	Platform     string      `json:"platform"`
	Architecture string      `json:"architecture,omitempty"`
	OSPackages   int         `json:"osPackages"`
	Tools        []imageTool `json:"tools"`
	Limitations  string      `json:"limitations"`
}

type imageTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

type imageComponent struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	PURL       string `json:"purl"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

func imageProperty(component imageComponent, name string) string {
	for _, property := range component.Properties {
		if property.Name == "aquasecurity:trivy:"+name {
			return property.Value
		}
	}
	return ""
}

func imageToolKind(name string) string {
	switch name {
	case "bash", "dash", "ash", "zsh", "fish", "ksh", "mksh", "yash", "busybox", "busybox-static", "busybox-binsh", "powershell":
		return "shell / command toolbox"
	case "apk-tools", "apt", "dpkg", "dnf", "microdnf", "yum", "rpm", "pacman", "zypper":
		return "package manager"
	}
	return ""
}

func classifyImage(bom json.RawMessage, platform string) imageClassification {
	result := imageClassification{
		Status: "unknown", Summary: "No supported OS package inventory was reported.", Platform: platform, Tools: []imageTool{},
		Limitations: "Trivy package-database evidence, not a filesystem or provenance attestation. Manually copied binaries and incomplete package databases can escape detection. Tags describe scan-time content only; compare the resolved digest and platform with the running image.",
	}
	var document struct {
		BOMFormat string `json:"bomFormat"`
		Metadata  struct {
			Component imageComponent `json:"component"`
		} `json:"metadata"`
		Components []imageComponent `json:"components"`
	}
	if json.Unmarshal(bom, &document) != nil || document.BOMFormat != "CycloneDX" {
		return result
	}
	if digest := imageProperty(document.Metadata.Component, "RepoDigest"); digestImage.MatchString(digest) {
		result.Digest = digest
	}
	if purl, err := url.Parse(document.Metadata.Component.PURL); err == nil && purl.Scheme == "pkg" {
		result.Architecture = purl.Query().Get("arch")
	}
	seen := map[string]bool{}
	for _, component := range document.Components {
		switch imageProperty(component, "PkgType") {
		case "alpine", "debian", "ubuntu", "redhat", "centos", "fedora", "amazon", "oracle", "rocky", "alma", "suse", "opensuse", "wolfi", "chainguard":
		default:
			continue
		}
		key := component.Name + "@" + component.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		result.OSPackages++
		if kind := imageToolKind(component.Name); kind != "" {
			result.Tools = append(result.Tools, imageTool{component.Name, component.Version, kind})
		}
	}
	sort.Slice(result.Tools, func(i, j int) bool { return result.Tools[i].Name < result.Tools[j].Name })
	if len(result.Tools) > 0 {
		result.Status, result.Summary = "not-distroless", "Shell or package-manager packages detected; this inventory is not distroless."
	} else if result.OSPackages > 0 {
		result.Status, result.Summary = "distroless-consistent", "OS package inventory is consistent with distroless: no recognized shell or package-manager packages detected."
	}
	return result
}
