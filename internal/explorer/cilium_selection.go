package explorer

import (
	"errors"
	"strings"
)

func ciliumSelection(selector any, pod Object, s Snapshot) (bool, error) {
	keys := []string{}
	for key := range obj(obj(selector)["matchLabels"]) {
		keys = append(keys, key)
	}
	for _, value := range arr(obj(selector)["matchExpressions"]) {
		keys = append(keys, text(obj(value)["key"]))
	}
	for _, key := range keys {
		plain := strings.TrimPrefix(strings.TrimPrefix(key, "k8s:"), "any:")
		if strings.HasPrefix(plain, "io.cilium.k8s.namespace.labels.") {
			if _, ok := s.find("namespaces", "", namespace(pod)); !s.available("namespaces") || !ok {
				return false, errors.New("namespace identity labels unavailable")
			}
		}
		if strings.HasPrefix(key, "reserved:") || (strings.HasPrefix(plain, "io.cilium.k8s.policy.") && plain != "io.cilium.k8s.policy.serviceaccount") {
			return false, errors.New("Cilium runtime identity is not available")
		}
	}
	return matches(selector, ciliumLabels(pod, s))
}
