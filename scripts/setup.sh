#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(go env GOVERSION)" = go1.27.3
test "$(.tools/node/bin/node --version)" = v26.13.0
kubectl --context rancher-desktop --request-timeout=15s cluster-info
rdctl list-settings | python3 -c 'import json,sys; s=json.load(sys.stdin); assert s["kubernetes"]["enabled"]; assert not s["kubernetes"]["options"]["flannel"], "Flannel is enabled. Read the README networking prerequisite before installing Cilium."'
rdctl shell -- sudo -n sh -c 'test ! -f /etc/cni/net.d/10-flannel.conflist && test ! -f /var/lib/rancher/k3s/agent/etc/cni/net.d/10-flannel.conflist'
helm --kube-context rancher-desktop upgrade --install peeker-cilium cilium --repo https://helm.cilium.io --version 1.20.4 --namespace kube-system --values cluster/cilium.yaml --wait --timeout 5m
kubectl --context rancher-desktop wait --for=condition=Ready nodes --all --timeout=3m
.tools/istio/bin/istioctl install --context rancher-desktop --manifests .tools/istio/manifests -f cluster/istio.yaml --skip-confirmation
kubectl --context rancher-desktop apply -f cluster/namespaces.yaml
kubectl --context rancher-desktop apply -f cluster/reader.yaml
kubectl --context rancher-desktop apply -f cluster/telemetry.yaml
kubectl --context rancher-desktop -n peeker-bookinfo apply -f .tools/istio/samples/bookinfo/platform/kube/bookinfo.yaml
kubectl --context rancher-desktop -n peeker-bookinfo apply -f .tools/istio/samples/bookinfo/networking/bookinfo-gateway.yaml
kubectl --context rancher-desktop -n peeker-bookinfo apply -f .tools/istio/samples/bookinfo/networking/destination-rule-all.yaml
helm --kube-context rancher-desktop upgrade --install peeker-kiali kiali-server --repo https://kiali.org/helm-charts --version 2.34.1 --namespace istio-system --values cluster/kiali.yaml --wait --timeout 5m
kubectl --context rancher-desktop -n peeker-bookinfo wait --for=condition=Available deployments --all --timeout=5m
