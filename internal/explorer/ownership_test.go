package explorer

import "testing"

func TestControllingOwnerUIDChain(t *testing.T) {
	pod := samplePod(t)
	obj(pod["metadata"])["ownerReferences"] = []any{map[string]any{"kind": "Job", "name": "ignore", "uid": "wrong", "controller": false}, map[string]any{"kind": "ReplicaSet", "name": "rs", "uid": "rs-1", "controller": true}}
	rs := fixture(t, `{"metadata":{"namespace":"demo","name":"rs","uid":"rs-1","ownerReferences":[{"kind":"Deployment","name":"deploy","uid":"deploy-1","controller":true}]}}`)
	deployment := fixture(t, `{"metadata":{"namespace":"demo","name":"deploy","uid":"deploy-1"}}`)
	s := Snapshot{"replicasets": available(rs), "deployments": available(deployment)}
	chain := ownership(pod, s)
	if chain.Status != "resolved" || len(chain.Owners) != 2 || chain.Owners[1].Name != "deploy" {
		t.Fatal(chain)
	}
	obj(deployment["metadata"])["uid"] = "recreated"
	if got := ownership(pod, s); got.Status != "unresolved" {
		t.Fatal("UID mismatch", got)
	}
	s["replicasets"] = Collection{State: State{Status: "denied"}}
	if got := ownership(pod, s); got.Status != "unresolved" {
		t.Fatal("denied", got)
	}
}
func TestJobCronJobAndStandalone(t *testing.T) {
	pod := samplePod(t)
	if got := ownership(pod, Snapshot{}); got.Status != "standalone" {
		t.Fatal(got)
	}
	obj(pod["metadata"])["ownerReferences"] = []any{map[string]any{"kind": "Job", "name": "job", "uid": "job-1", "controller": true}}
	job := fixture(t, `{"metadata":{"namespace":"demo","name":"job","uid":"job-1","ownerReferences":[{"kind":"CronJob","name":"schedule","uid":"schedule-1","controller":true}]}}`)
	schedule := fixture(t, `{"metadata":{"namespace":"demo","name":"schedule","uid":"schedule-1"}}`)
	s := Snapshot{"jobs": available(job), "cronjobs": available(schedule)}
	if got := ownership(pod, s); got.Status != "resolved" || got.Owners[1].Kind != "CronJob" {
		t.Fatal(got)
	}
	obj(job["metadata"])["ownerReferences"] = nil
	if got := ownership(pod, s); got.Status != "resolved" || len(got.Owners) != 1 {
		t.Fatal(got)
	}
	obj(job["metadata"])["ownerReferences"] = []any{map[string]any{"kind": "Job", "name": "job", "uid": "job-1", "controller": true}}
	if got := ownership(pod, s); got.Status != "unresolved" {
		t.Fatal("cycle", got)
	}
}
