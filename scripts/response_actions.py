"""Live orphan/kill scenarios for verify-containment.py --actions."""
import time


def template(name):
    return {"metadata": {"labels": {"app": name}, "annotations": {"sidecar.istio.io/inject": "false"}}, "spec": {
        "automountServiceAccountToken": False, "terminationGracePeriodSeconds": 5,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "worker", "image": "busybox:1.37", "imagePullPolicy": "IfNotPresent", "command": ["sleep", "3600"],
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "32Mi"}}}],
    }}


def wait_ready(v, names):
    deadline = time.monotonic() + 180
    while True:
        pods = v.pods()
        if set(pods) == set(names) and all(any(c["type"] == "Ready" and c["status"] == "True"
                                             for c in p["status"].get("conditions", [])) for p in pods.values()):
            return pods
        if time.monotonic() > deadline:
            raise RuntimeError("Disposable Pods did not become ready: " + ", ".join(names))
        time.sleep(1)


def change(v, controller, operation):
    identity = {"kind": controller["kind"], "namespace": v.namespace,
                "name": controller["metadata"]["name"], "uid": controller["metadata"]["uid"]}
    v.api("/api/registry/change", {**identity, "operation": "register"})
    result = v.api("/api/registry/change", {**identity, "operation": operation})
    if result["status"] != "configured":
        raise RuntimeError(str(result))
    return result


def owned_children(v, kind, controller):
    return [o for o in v.get(kind, namespace=v.namespace)["items"]
            if any(owner["uid"] == controller["metadata"]["uid"] for owner in o["metadata"].get("ownerReferences", []))]


def wait_deleted(v, objects):
    for obj in objects:
        v.command("wait", "--for=delete", obj["kind"] + "/" + obj["metadata"]["name"],
                  "-n", v.namespace, "--timeout=90s", timeout=110)


def verify_orphan(v, controller, child_kind, pod):
    children = owned_children(v, child_kind, controller)
    if len(children) != 1 or not any(o["uid"] == children[0]["metadata"]["uid"] for o in pod["metadata"].get("ownerReferences", [])):
        raise RuntimeError("Expected a real controller -> intermediate controller -> Pod chain")
    result = {"action": change(v, controller, "orphan"), "before": v.stable({"pod": pod})}
    v.report.setdefault("orphan", {})[controller["kind"]] = result
    wait_deleted(v, [controller, *children])
    current = v.get("pod", pod["metadata"]["name"], v.namespace)
    if current["metadata"].get("ownerReferences"):
        raise RuntimeError("Orphaned Pod still has owners")
    result["deletedControllers"] = [o["kind"] + "/" + o["metadata"]["name"] for o in [controller, *children]]
    result["ownerReferences"] = current["metadata"].get("ownerReferences", [])


def verify_kill(v, controller, pod, child_kind=None):
    children = owned_children(v, child_kind, controller) if child_kind else []
    if child_kind and len(children) != 1:
        raise RuntimeError("Expected one intermediate controller before kill-switch")
    result = {"action": change(v, controller, "kill")}
    v.report.setdefault("kill", {})[controller["kind"]] = result
    wait_deleted(v, [controller, *children, pod])
    result["deleted"] = [o["kind"] + "/" + o["metadata"]["name"] for o in [controller, *children, pod]]


def retained_storage(v, pvc, pv):
    current_pvc = v.get("pvc", pvc["metadata"]["name"], v.namespace)
    current_pv = v.get("pv", pv["metadata"]["name"])
    for old, current in ((pvc, current_pvc), (pv, current_pv)):
        if old["metadata"]["uid"] != current["metadata"]["uid"] or current["metadata"].get("deletionTimestamp") or current["status"]["phase"] != "Bound":
            raise RuntimeError("Retained storage was replaced, deleted or unbound")
    if current_pvc["spec"]["volumeName"] != pv["metadata"]["name"] or current_pv["spec"]["claimRef"]["uid"] != pvc["metadata"]["uid"]:
        raise RuntimeError("Retained PVC/PV binding changed")
    return {"pvcUID": current_pvc["metadata"]["uid"], "pvUID": current_pv["metadata"]["uid"], "phase": "Bound"}


def verify_actions(v, storage_class):
    storage = v.get("storageclass", storage_class)
    if storage.get("reclaimPolicy", "Delete") != "Delete":
        raise RuntimeError("Use a Delete-reclaim storage class so disposable volume cleanup can complete")
    v.setup_identity([
        {"apiGroups": ["apps"], "resources": ["deployments", "replicasets", "statefulsets"], "verbs": ["get", "delete"]},
        {"apiGroups": ["batch"], "resources": ["cronjobs", "jobs"], "verbs": ["get", "delete"]},
    ])
    controllers = {}
    for action in ("orphan", "kill"):
        name = action + "-deployment"
        controllers[name] = v.create("Deployment", name, "apps/v1", v.namespace, spec={
            "replicas": 1, "selector": {"matchLabels": {"app": name}}, "template": template(name)})
        name = action + "-cronjob"
        job_template = template(name)
        job_template["spec"]["restartPolicy"] = "Never"
        controllers[name] = v.create("CronJob", name, "batch/v1", v.namespace, spec={
            "schedule": "* * * * *", "concurrencyPolicy": "Forbid", "startingDeadlineSeconds": 120,
            "jobTemplate": {"spec": {"backoffLimit": 0, "template": job_template}}})
    name = "kill-statefulset"
    pod_template = template(name)
    pod_template["spec"]["containers"][0]["volumeMounts"] = [{"name": "data", "mountPath": "/data"}]
    v.create("Service", name, namespace=v.namespace, spec={"clusterIP": "None", "selector": {"app": name}, "ports": [{"port": 8080}]})
    controllers[name] = v.create("StatefulSet", name, "apps/v1", v.namespace, spec={
        "replicas": 1, "serviceName": name, "selector": {"matchLabels": {"app": name}}, "template": pod_template,
        "persistentVolumeClaimRetentionPolicy": {"whenDeleted": "Retain", "whenScaled": "Retain"},
        "volumeClaimTemplates": [{"metadata": {"name": "data"}, "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": storage_class,
                                  "resources": {"requests": {"storage": "16Mi"}}}}]})
    before = wait_ready(v, controllers)
    pvc = v.get("pvc", "data-kill-statefulset-0", v.namespace)
    pv = v.get("pv", pvc["spec"]["volumeName"])
    v.cleanup_waits.append(("persistentvolume", pv["metadata"]["name"], pv["metadata"]["uid"]))
    v.report["storage"] = {"before": retained_storage(v, pvc, pv), "pvName": pv["metadata"]["name"], "storageClass": storage_class}
    v.command("exec", "-n", v.namespace, before[name]["metadata"]["name"], "--", "sh", "-c",
              'printf %s "$1" > /data/proof', "verify", v.namespace)
    v.start()
    for kind, child in (("deployment", "replicasets"), ("cronjob", "jobs")):
        name = "orphan-" + kind
        verify_orphan(v, controllers[name], child, before[name])
        name = "kill-" + kind
        verify_kill(v, controllers[name], before[name], child)
    verify_kill(v, controllers["kill-statefulset"], before["kill-statefulset"])
    v.report["storage"]["afterKill"] = retained_storage(v, pvc, pv)
    recovery = template("recovery")
    recovery["spec"]["volumes"] = [{"name": "data", "persistentVolumeClaim": {"claimName": pvc["metadata"]["name"]}}]
    recovery["spec"]["containers"][0]["volumeMounts"] = [{"name": "data", "mountPath": "/data", "readOnly": True}]
    pod = v.create("Pod", "recovery", namespace=v.namespace, spec=recovery["spec"])
    v.command("wait", "--for=condition=ready", "pod/recovery", "-n", v.namespace, "--timeout=90s", timeout=110)
    data = v.command("exec", "-n", v.namespace, pod["metadata"]["name"], "--", "cat", "/data/proof").stdout
    if data != v.namespace:
        raise RuntimeError("Retained volume contents did not survive kill-switch")
    v.report["storage"]["dataSurvivedRemount"] = True
    # Include a fresh CronJob scheduling boundary, checking controllers do not return.
    time.sleep(65)
    for kind in ("deployments", "replicasets", "cronjobs", "jobs", "statefulsets"):
        if v.get(kind, namespace=v.namespace)["items"]:
            raise RuntimeError("Controllers remain or were recreated: " + kind)
    for name in ("orphan-deployment", "orphan-cronjob"):
        current = v.get("pod", before[name]["metadata"]["name"], v.namespace)
        result = v.report["orphan"][controllers[name]["kind"]]
        result["after"] = v.stable({"pod": current})
        if result["before"] != result["after"] or current["metadata"].get("ownerReferences") or current["status"]["phase"] != "Running":
            raise RuntimeError("Orphaned Pod changed or stopped")
        v.command("exec", "-n", v.namespace, current["metadata"]["name"], "--", "kill", "-0", "1")
        result["pid1Alive"] = True
    v.report["result"] = "PASS"
