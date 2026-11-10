package explorer

import (
	"context"
	"net/http"
	"time"
)

func capabilityHandler(client *Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		result := map[string]string{"istio": "unknown", "cilium": "unknown"}
		result["istioExpectation"] = "optional"
		if client.Assessment.ExpectIstio {
			result["istioExpectation"] = "required"
		}
		groups, err := client.get(ctx, "/apis")
		if err != nil {
			result["message"] = "API discovery unavailable; installed networking cannot be determined."
		} else if values, ok := groups["groups"].([]any); ok {
			result["istio"], result["cilium"] = "not-detected", "not-detected"
			for _, value := range values {
				switch obj(value)["name"] {
				case "networking.istio.io":
					result["istio"] = "detected"
				case "cilium.io":
					result["cilium"] = "detected"
				}
			}
		}
		writeJSON(w, 200, result)
	}
}
