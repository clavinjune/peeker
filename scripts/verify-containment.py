#!/usr/bin/env python3
"""Opt-in live response verification. Default: Cilium; --actions: orphan/kill/storage."""
import argparse
import hashlib
import http.client
import json
import pathlib
import signal
import socket
import subprocess
import time
import uuid


class Verification:
    def __init__(self, context, binary):
        self.kubectl = ["kubectl", "--context=" + context, "--request-timeout=20s"]
        self.binary = str(pathlib.Path(binary).resolve())
        self.namespace = "peeker-verify-" + uuid.uuid4().hex[:10]
        self.created = []
        self.cleanup_waits = []
        self.process = None
        self.generation = ""
        self.report = {"context": context, "namespace": self.namespace}
        self.context = context

    def command(self, *args, body=None, check=True, timeout=60):
        result = subprocess.run(self.kubectl + list(args), input=None if body is None else json.dumps(body),
                                text=True, capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"kubectl {args}: {result.stderr.strip()}")
        return result

    def get(self, kind, name=None, namespace=None):
        args = ["get", kind] + ([name] if name else [])
        args += ["-n", namespace] if namespace else []
        return json.loads(self.command(*args, "-o", "json").stdout)

    def create(self, kind, name, version="v1", namespace=None, **fields):
        metadata = {"name": name, "labels": {"peeker.dev/verification": self.namespace}}
        if namespace:
            metadata["namespace"] = namespace
        obj = {"apiVersion": version, "kind": kind, "metadata": metadata, **fields}
        created = json.loads(self.command("create", "-f", "-", "-o", "json", body=obj).stdout)
        self.created.append((kind, name, namespace, created["metadata"]["uid"]))
        return created

    def role(self, name, rules, cluster=False):
        self.create("ClusterRole" if cluster else "Role", name, "rbac.authorization.k8s.io/v1",
                    None if cluster else self.namespace, rules=rules)

    def binding(self, name, role, subjects, cluster=False):
        self.create("ClusterRoleBinding" if cluster else "RoleBinding", name, "rbac.authorization.k8s.io/v1",
                    None if cluster else self.namespace,
                    roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole" if cluster else "Role", "name": role},
                    subjects=subjects)

    def subject(self, name, namespace=None):
        return {"kind": "ServiceAccount", "name": name, "namespace": namespace or self.namespace}

    def setup_identity(self, rules):
        self.create("Namespace", self.namespace)
        existing = self.command("get", "serviceaccount", "peeker-responder", "-n", "peeker-system", "--ignore-not-found", "-o", "name")
        if not existing.stdout.strip():
            self.create("ServiceAccount", "peeker-responder", namespace="peeker-system", automountServiceAccountToken=False)
        responder = [self.subject("peeker-responder", "peeker-system")]
        self.role("responder", rules)
        self.binding("responder", "responder", responder)

    def setup(self):
        self.setup_identity([
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "patch"]},
            {"apiGroups": ["cilium.io"], "resources": ["ciliumnetworkpolicies"], "verbs": ["create"]},
            {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"], "verbs": ["delete"]},
        ])
        # Grant only missing endpoint reads in the disposable namespace.
        self.role("reader-endpoints", [{"apiGroups": ["cilium.io"], "resources": ["ciliumendpoints"], "verbs": ["get", "list"]}])
        self.binding("reader-endpoints", "reader-endpoints", [self.subject("peeker-reader", "peeker-system")])
        self.role(self.namespace + "-responder", [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterrolebindings"],
                                                  "resourceNames": [self.namespace + "-grant"], "verbs": ["delete"]}], cluster=True)
        self.binding(self.namespace + "-responder", self.namespace + "-responder", [self.subject("peeker-responder", "peeker-system")], cluster=True)
        for name in ("target", "probe", "control"):
            self.create("ServiceAccount", name, namespace=self.namespace, automountServiceAccountToken=False)
            self.create("Deployment", name, "apps/v1", self.namespace, spec={
                "replicas": 1, "selector": {"matchLabels": {"app": name}},
                "template": {"metadata": {"labels": {"app": name}, "annotations": {"sidecar.istio.io/inject": "false"}}, "spec": {
                    "serviceAccountName": name, "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "http", "image": "busybox:1.37", "imagePullPolicy": "IfNotPresent",
                                    "command": ["sh", "-c", "printf ok > /tmp/index.html; exec httpd -f -p 8080 -h /tmp"],
                                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "32Mi"}},
                                    "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}]}],
                    "volumes": [{"name": "tmp", "emptyDir": {}}],
                }}})
        self.create("NetworkPolicy", "allow-all", "networking.k8s.io/v1", self.namespace,
                    spec={"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "ingress": [{}], "egress": [{}]})
        for name in ("private-data", "shared-data", "control-data"):
            self.create("ConfigMap", name, namespace=self.namespace, data={"test": "non-secret"})
            self.role(name, [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [name], "verbs": ["get"]}])
        self.binding("private", "private-data", [self.subject("target")])
        self.binding("control", "control-data", [self.subject("control")])
        self.binding("shared", "shared-data", [{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:serviceaccounts:" + self.namespace}])
        self.role(self.namespace + "-grant", [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": [self.namespace], "verbs": ["get"]}], cluster=True)
        self.binding(self.namespace + "-grant", self.namespace + "-grant", [self.subject("target")], cluster=True)
        self.command("wait", "--for=condition=available", "deployment", "--all", "-n", self.namespace, "--timeout=180s", timeout=200)
        self.command("wait", "--for=condition=ready", "pods", "--all", "-n", self.namespace, "--timeout=90s", timeout=110)

    def pods(self):
        return {p["metadata"]["labels"]["app"]: p for p in self.get("pods", namespace=self.namespace)["items"]}

    def stable(self, pods):
        return {name: {"uid": p["metadata"]["uid"], "spec": hashlib.sha256(json.dumps(p["spec"], sort_keys=True).encode()).hexdigest(),
                       "containers": [(s["name"], s["containerID"], s["restartCount"]) for s in p["status"]["containerStatuses"]]}
                for name, p in pods.items()}

    def connectivity(self, pods):
        result = {}
        for source, dest in (("probe", "target"), ("control", "target"), ("target", "probe"), ("target", "control"), ("probe", "control"), ("control", "probe")):
            response = self.command("exec", "-n", self.namespace, pods[source]["metadata"]["name"], "-c", "http", "--",
                                    "wget", "-T", "2", "-qO-", "http://" + pods[dest]["status"]["podIP"] + ":8080/index.html", check=False, timeout=15)
            if response.returncode and not any(reason in response.stderr.lower() for reason in ("timed out", "timeout", "connection refused", "no route")):
                raise RuntimeError("Connectivity probe failed for a reason other than network denial: " + response.stderr)
            result[source + "->" + dest] = response.returncode == 0 and response.stdout == "ok"
        return result

    def permissions(self):
        result = {}
        for account, resource, name in (("target", "configmaps", "private-data"), ("target", "namespaces", self.namespace),
                                         ("target", "configmaps", "shared-data"), ("control", "configmaps", "control-data")):
            output = self.command("--as=system:serviceaccount:" + self.namespace + ":" + account,
                                  "--as-group=system:serviceaccounts", "--as-group=system:serviceaccounts:" + self.namespace,
                                  "--as-group=system:authenticated", "auth", "can-i", "get", resource + "/" + name, "-n", self.namespace, check=False)
            answer = output.stdout.strip()
            if answer not in ("yes", "no"):
                raise RuntimeError("Permission check failed: " + output.stderr)
            result[account + ":get:" + resource + "/" + name] = answer
        return result

    def api(self, path, payload=None, raw=False):
        headers = {"X-Peeker-Context": self.generation}
        if payload is not None:
            headers.update({"Origin": self.base, "Content-Type": "application/json", "X-Peeker-Action": "registry"})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            connection.request("GET" if payload is None else "POST", path,
                               body=None if payload is None else json.dumps(payload), headers=headers)
            response = connection.getresponse()
            body = response.read()
            if response.status >= 300:
                raise RuntimeError(body.decode())
            return body.decode() if raw else json.loads(body)
        finally:
            connection.close()

    def start(self):
        with socket.socket() as port:
            port.bind(("127.0.0.1", 0))
            self.port = port.getsockname()[1]
            address = "127.0.0.1:" + str(self.port)
        self.base = "http://" + address
        self.process = subprocess.Popen([self.binary, "--context", self.context, "--listen", address], stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while True:
            try:
                self.generation = self.api("/api/contexts")["generation"]
                break
            except (OSError, RuntimeError):
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise
                time.sleep(0.2)

    def run(self):
        self.setup()
        before = self.pods()
        deadline = time.monotonic() + 60
        while True:
            endpoints = self.get("ciliumendpoints", namespace=self.namespace)["items"]
            owners = {o["uid"] for e in endpoints for o in e["metadata"].get("ownerReferences", []) if o["kind"] == "Pod"}
            if all(p["metadata"]["uid"] in owners for p in before.values()):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("CiliumEndpoints did not become available")
            time.sleep(1)
        self.report["before"] = {"pods": self.stable(before), "traffic": self.connectivity(before), "permissions": self.permissions()}
        assert all(self.report["before"]["traffic"].values()), self.report["before"]
        assert set(self.report["before"]["permissions"].values()) == {"yes"}, self.report["before"]
        self.start()
        deployment = self.get("deployment", "target", self.namespace)
        identity = {"kind": "Deployment", "namespace": self.namespace, "name": "target", "uid": deployment["metadata"]["uid"]}
        self.api("/api/registry/change", {**identity, "operation": "register"})
        self.report["action"] = self.api("/api/registry/change", {**identity, "operation": "contain"})
        backup = self.api("/api/registry/backup?id=" + self.report["action"]["backup"], raw=True)
        self.report["backupKinds"] = sorted({json.loads(doc)["kind"] for doc in backup.split("---\n") if doc.strip()})
        assert {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}.issubset(self.report["backupKinds"])
        expected = {key: "target" not in key for key in self.report["before"]["traffic"]}
        deadline = time.monotonic() + 60
        while True:
            traffic = self.connectivity(before)
            if traffic == expected:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Containment did not converge: " + json.dumps(traffic))
            time.sleep(1)
        # A bounded observation window catches delayed restarts as well as rollout replacements.
        time.sleep(20)
        after = self.pods()
        self.report["after"] = {"pods": self.stable(after), "traffic": self.connectivity(after), "permissions": self.permissions()}
        assert self.report["after"]["pods"] == self.report["before"]["pods"], "Pod UID/spec/container/restart changed"
        assert self.get("deployment", "target", self.namespace)["spec"] == deployment["spec"], "Controller spec changed"
        assert self.report["after"]["traffic"] == expected, self.report["after"]["traffic"]
        permissions = list(self.report["after"]["permissions"].values())
        assert permissions == ["no", "no", "yes", "yes"], permissions
        self.report["result"] = "PASS"

    def cleanup(self):
        errors = []
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=15)
            except Exception as error:
                errors.append(str(error))
        for kind, name, namespace, uid in reversed(self.created):
            # Namespace deletion collects the resources inside it; delete only our external objects separately.
            if namespace == self.namespace:
                continue
            args = ["-n", namespace] if namespace else []
            try:
                current = self.command("get", kind, name, *args, "--ignore-not-found", "-o", "json")
                if not current.stdout.strip():
                    continue
                if json.loads(current.stdout)["metadata"]["uid"] != uid:
                    raise RuntimeError("UID changed; refusing cleanup of " + kind + "/" + name)
                self.command("delete", kind, name, *args, "--wait=true", "--timeout=90s", timeout=110)
            except Exception as error:
                errors.append(str(error))
        for kind, name, uid in self.cleanup_waits:
            try:
                current = self.command("get", kind, name, "--ignore-not-found", "-o", "json")
                if current.stdout.strip() and json.loads(current.stdout)["metadata"]["uid"] == uid:
                    self.command("wait", "--for=delete", kind + "/" + name, "--timeout=90s", timeout=110)
            except Exception as error:
                errors.append(str(error))
        self.report["cleanup"] = errors or "PASS"
        if errors:
            raise RuntimeError("Cleanup incomplete: " + "; ".join(errors))

    def diagnostics(self):
        diagnostics = {}
        self.report["diagnostics"] = diagnostics
        for kind in ("pods", "deployments", "replicasets", "statefulsets", "cronjobs", "jobs", "persistentvolumeclaims", "events", "ciliumendpoints", "ciliumnetworkpolicies"):
            try:
                diagnostics[kind] = self.get(kind, namespace=self.namespace)["items"]
            except Exception as error:
                diagnostics[kind] = str(error)
        pods = diagnostics.get("pods")
        if isinstance(pods, list):
            diagnostics["logs"] = {pod["metadata"]["name"]: self.command(
                "logs", "-n", self.namespace, pod["metadata"]["name"], "--all-containers", "--tail=30", check=False
            ).stdout for pod in pods}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--binary", default="bin/peeker")
    parser.add_argument("--actions", action="store_true", help="verify orphan/kill and retained storage instead of containment")
    parser.add_argument("--storage-class", default="local-path", help="disposable storage provisioner for --actions; must use Delete reclaim policy")
    args = parser.parse_args()
    verification = Verification(args.context, args.binary)
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.actions:
            from response_actions import verify_actions
            verify_actions(verification, args.storage_class)
        else:
            verification.run()
    except Exception as error:
        verification.report["result"] = "FAIL"
        verification.report["error"] = str(error)
        verification.diagnostics()
        raise
    finally:
        try:
            verification.cleanup()
        finally:
            print(json.dumps(verification.report, indent=2), flush=True)


if __name__ == "__main__":
    main()
