#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
kubectl --context rancher-desktop config get-contexts rancher-desktop
kubectl --context rancher-desktop cluster-info
kubectl --context rancher-desktop wait --for=condition=Ready nodes --all --timeout=2m
kubectl --context rancher-desktop -n kube-system rollout status daemonset/cilium --timeout=2m
kubectl --context rancher-desktop -n kube-system exec daemonset/cilium -c cilium-agent -- cilium-dbg status --brief
kubectl --context rancher-desktop -n istio-system rollout status deployment/istiod --timeout=2m
kubectl --context rancher-desktop -n istio-system rollout status deployment/istio-ingressgateway --timeout=2m
kubectl --context rancher-desktop -n istio-system rollout status deployment/kiali --timeout=2m
.tools/istio/bin/istioctl --context rancher-desktop proxy-status
kubectl --context rancher-desktop -n peeker-bookinfo get pods -o json | python3 -c 'import json,sys; pods=json.load(sys.stdin)["items"]; assert len(pods)>=6; statuses=lambda p:p["status"].get("containerStatuses",[])+[c for c in p["status"].get("initContainerStatuses",[]) if c["name"]=="istio-proxy"]; [print(p["metadata"]["name"],[(c["name"],c["ready"]) for c in statuses(p)]) for p in pods]; assert all(any(c["name"]=="istio-proxy" and c["ready"] for c in statuses(p)) and all(c["ready"] for c in statuses(p)) and any(c["type"]=="Ready" and c["status"]=="True" for c in p["status"]["conditions"]) for p in pods)'
kubectl --context rancher-desktop -n istio-system get configmap kiali -o json | python3 -c 'import json,re,sys; config=json.load(sys.stdin)["data"]["config.yaml"]; section=re.search(r"(?ms)^external_services:\n(.*?)(?=^[^ \n]|\Z)",config).group(1); assert all(re.search(r"(?m)^  "+name+r":\n    enabled: false$",section) for name in ["prometheus","grafana","tracing","custom_dashboards"]); print("Kiali external integrations verified disabled:"); print(section)'
kubectl --context rancher-desktop get pods -A -o json | python3 -c 'import json,sys; pods=json.load(sys.stdin)["items"]; matches=[p["metadata"]["name"] for p in pods for c in p["spec"]["containers"] if any(x in c["image"].lower() for x in ["prometheus/prometheus","grafana/grafana","jaegertracing/","grafana/tempo"])]; print("Prometheus/Grafana/tracing backend pods:",matches); assert not matches'
kubectl --context rancher-desktop auth can-i list pods --all-namespaces --as=system:serviceaccount:peeker-system:peeker-reader
if kubectl --context rancher-desktop auth can-i create pods --as=system:serviceaccount:peeker-system:peeker-reader; then exit 1; fi
if kubectl --context rancher-desktop auth can-i get secrets --as=system:serviceaccount:peeker-system:peeker-reader; then exit 1; fi
