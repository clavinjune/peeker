package explorer

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestOrphanRetriesGarbageCollectorConflictSafely(t *testing.T) {
	for _, test := range []struct {
		name   string
		writes int
		error  string
	}{
		{"detached", 2, ""},
		{"replaced", 1, "replaced"},
		{"adopted", 1, "new owner"},
		{"forbidden", 1, "HTTP 403"},
		{"conflict-limit", 4, "HTTP 409"},
		{"cancelled", 1, "context canceled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			o, s := registryFixture(t)
			child := s.items("replicasets")[0]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writes := 0
			c := registryProxy(t, s, func(w registryWrite) int {
				if !strings.Contains(w.path, "/replicasets/") {
					return 200
				}
				writes++
				if writes > 1 {
					if !strings.Contains(string(w.body), `"resourceVersion":"2"`) || !strings.Contains(string(w.body), `"uid":"rs-1"`) || !strings.Contains(string(w.body), `"propagationPolicy":"Orphan"`) {
						t.Error("retry lost refreshed identity preconditions or propagation", string(w.body))
					}
					if test.name == "conflict-limit" {
						return http.StatusConflict
					}
					return 200
				}
				metadata := obj(child["metadata"])
				metadata["resourceVersion"] = "2"
				delete(metadata, "ownerReferences") // GC detaches the deleted parent after our GET.
				switch test.name {
				case "replaced":
					metadata["uid"] = "replacement"
				case "adopted":
					metadata["ownerReferences"] = []any{Object{"uid": "another-workload", "controller": true}}
				case "forbidden":
					return http.StatusForbidden
				case "cancelled":
					cancel()
				}
				return http.StatusConflict
			})
			err := newRegistry(c).orphan(ctx, c, o, &actionResult{})
			if test.name == "cancelled" {
				// Cancellation can race the HTTP response or interrupt the retry delay.
				if err == nil || ctx.Err() == nil {
					t.Fatalf("cancelled action did not fail: %v", err)
				}
			} else if test.error == "" && err != nil || test.error != "" && (err == nil || !strings.Contains(err.Error(), test.error)) {
				t.Fatalf("unexpected error: %v; want %q", err, test.error)
			}
			if writes != test.writes {
				t.Fatalf("child delete attempts = %d; want %d", writes, test.writes)
			}
		})
	}
}
