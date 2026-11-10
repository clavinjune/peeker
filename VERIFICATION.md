# Verification — 2026-11-10

Executed on macOS arm64 against the existing **rancher-desktop** cluster. These are observed results, not expected outputs. Peeker uses request-scoped memory only and has no database.

## Toolchain and builds

```text
go version go1.27.3 darwin/arm64
node --version: v26.13.0 (.tools/node/bin/node)
bun --version: 1.4.2
istioctl client version: 1.32.0

bun install --frozen-lockfile: no changes
bun run typecheck: passed (tsc --noEmit)
bun run build: passed (907 modules)
dist/assets/index-Ds3eODoA.js: 470.17 kB / 142.78 kB gzip

go test -race -v ./...: 16 tests passed
go vet ./...: passed
go build -o bin/peeker ./cmd/peeker: passed
bash -n scripts/{bootstrap,setup,proxy,verify-cluster}.sh: passed
```

The tests cover policy additivity/defaulting, combined selectors, CIDRs and ports, unknown results, Cilium allow/deny distinction, UID ownership chains and cycles, Service/EndpointSlice matching, ReferenceGrants, route generations, Istio subsets, API/discovery failures, credential redaction and the read-only HTTP boundary.

Production startup initially exposed a Go ServeMux conflict between the API fallback and static handler. The fallback now uses `GET /api/`; a regression test constructs the production handler and verifies SPA routes, assets, API health, denied writes and unsupported endpoints.

## Live cluster

`bash scripts/setup.sh` completed successfully. `bash scripts/verify-cluster.sh` subsequently passed, including the native sidecar readiness check.

```text
CONTEXT: rancher-desktop
[local node]   Ready   control-plane   v1.37.0+k3s1

daemon set "cilium" successfully rolled out
cilium-dbg status --brief: OK
deployment "istiod" successfully rolled out
deployment "istio-ingressgateway" successfully rolled out
deployment "kiali" successfully rolled out

Helm peeker-cilium: deployed, chart cilium-1.20.4, revision 6
Helm peeker-kiali: deployed, chart kiali-server-2.34.1, revision 1
```

All seven Istio proxies (six Bookinfo pods and the ingress gateway) appeared in `istioctl --context rancher-desktop proxy-status`, connected to Istiod 1.32.0 with CDS/LDS/EDS/RDS subscriptions.

The details, productpage, ratings and three reviews workloads each had a ready application container and ready Istio proxy.

The injected proxies are native restartable init-container sidecars. No ambient components were installed. Initial Bookinfo image pulls encountered TLS timeouts; Kubernetes retries succeeded without changing the pinned images.

### CNI transition and existing workloads

Flannel was disabled using Rancher Desktop's supported setting, without resetting Kubernetes. The resulting k3s arguments include `--flannel-backend=none --disable-network-policy`. Cilium's live settings were:

```text
kube-proxy-replacement=false
bpf-lb-sock-hostns-only=true
cni-exclusive=false
routing-mode=tunnel
tunnel-port=8473
```

Recovery required shared BPF/cgroup/network-namespace mounts and the actual cri-dockerd default paths: `/opt/cni/bin` and `/etc/cni/net.d`. Earlier paths left the node NotReady; the corrected Helm values restored it. Persistent mount provisioning is stored in `cluster/rancher-desktop-override.yaml` and installed in the Rancher Desktop Lima override. VM restart persistence has been configured but was not separately retested with another VM restart.

The unrelated application and database workloads recovered automatically, preserving their original pod names and UIDs; their migration job remained completed. Neither deployments nor storage were deleted.

Existing Traefik and Gateway API Helm releases remain installed. Cilium 1.20's published guaranteed Kubernetes matrix ends at 1.36; this is successful live verification on the existing 1.37 cluster, not a claim of upstream certification.

## Bookinfo and Kiali

- `GET http://127.0.0.1:9080/productpage`: **HTTP 200**, approximately 15 kB HTML.
- Browser displayed “The Comedy of Errors”, book details and reviews served by the reviews-v2 workload.
- `http://127.0.0.1:20001/kiali/` loaded the Kiali console. It showed one control plane, a sidecar data plane and six Istio configuration resources.
- `GET /kiali/api/config` returned `prometheus.enabled: false`.
- Kiali startup log: **`Prometheus is disabled`**.
- Installed ConfigMap verified Prometheus, Grafana, tracing and custom dashboards all disabled.
- Cluster image inventory found **zero Prometheus/Grafana/tracing backend pods**. Helm release inventory contains no new telemetry stack. Rancher Desktop's pre-existing metrics-server remains; it is not Prometheus.

Kiali's configuration UI works without Prometheus. Its zero-RPS / “no traffic” placeholders are not measurements; traffic rates, latency and metrics-backed graphs are unavailable.

## Peeker live API and browser

Both production `http://127.0.0.1:8080` and Bun/Vite development `http://127.0.0.1:5173` were exercised in Chrome. Vite's `/api/health` proxy returned HTTP 200.

```text
Live pod count: 24
Namespace filter peeker-bookinfo: 6 pods
All six: sidecar=true, ready=2, containers=2, ownership=resolved
peeker-bookinfo productpage: 7 evidence-backed graph edges
peeker-demo web: 7 evidence-backed graph edges
```

Observed interactions:

1. Inventory displayed namespace, pod name, controlling workload kind/name and Details buttons.
2. Selecting `peeker-demo` reduced the table to one real pod. Name filter `no-such-pod` displayed the explicit empty-result message; `web` restored the row.
3. Details opened a dedicated URL and showed pod labels, node, IP, readiness and `Pod → ReplicaSet → Deployment` UID-resolved ownership.
4. The demo selected `allow-demo-clients`, `isolate-web` and Cilium `deny-world-egress`. Ingress showed additive allow rules; egress showed isolation with no Kubernetes allow rules. Cilium world deny appeared separately.
5. Security edge selection opened resource evidence for `NetworkPolicy peeker-demo/allow-demo-clients`, field `spec.ingress[0]`, combined namespace AND pod selectors, and named TCP port `http`.
6. Clicking the Service topology node opened selector and EndpointSlice UID/port evidence. The routing tab showed `Ingress demo → Service web → Pod` as **configured**, not verified external reachability.
7. Productpage displayed native sidecar readiness `2/2`, ownership `Deployment productpage-v1`, and `Gateway bookinfo-gateway → VirtualService bookinfo → Service productpage → Pod`.
8. Configuration-derived topology and the local Kiali link were present. No measured traffic edges or rates were added by Peeker.

Every edge returned for the demo and productpage had a nonempty resource name and field path in its evidence. A local screenshot was saved at `.local/peeker-topology.png` (generated evidence, gitignored).

### Failure-state verification

The real cluster serves all 22 supported inventories, so optional-API absence was tested with a **controlled localhost HTTP fixture**, not by removing cluster APIs:

- A separate backend on port 8081 pointed at an unused proxy port 18999. Browser showed **“Cluster data unavailable”**, **“Cannot reach kubectl proxy”**, and a retry instruction rather than an empty table.
- A separate backend on 8083 used a fixture on 8003. The fixture forwarded GETs to the real read-only proxy except that Cilium discovery returned 404 and NetworkPolicy lists returned 403.
- Browser showed **19/22 readable**, both Cilium collections **missing-api**, NetworkPolicies **denied / HTTP 403**, and both policy directions **unknown**. Pod identity and other readable relationships remained visible.
- These temporary fixture/backend listeners were stopped after verification. Normal Peeker continues to use the real proxy on 8001.

### Read-only boundary

```text
POST, PUT, PATCH, DELETE, CONNECT, TRACE, HEAD /api/pods: HTTP 405
GET /api/v1/secrets: HTTP 404
GET /api/proxy: HTTP 404
GET /api/pods/peeker-demo/web/exec: HTTP 404
GET Secrets directly through the impersonated kubectl proxy: HTTP 403

ServiceAccount peeker-reader:
  list pods: yes
  create pods: no
  get secrets: no
```

Peeker, Vite, its kubectl proxy and project port-forwards listen on `127.0.0.1`. The browser receives selected resource views, never kubeconfig, service account tokens or pod environment contents.

## Scope of conclusions

No remaining blocker prevents local use. Cilium evaluation is partial; dynamic identities/FQDNs, L7 predicates, host policies and full effective-policy composition are not resolved. Complex Istio visibility/subset precedence, route-match/listener evaluation and general external reachability are also explicitly limited in the README. Gateway API grant/status behavior is covered by focused tests; live route-chain examples used Ingress and Istio resources.

Ripwire edit-check found no incompatible Handler callers. Quality-delta against the checkpoint baseline reported zero gating regressions and one non-gating new-test “dead-code” finding; the Go runner executed that test successfully. The baseline was captured after initial implementation because this repository originally had no HEAD, so it does not evaluate the entire initial implementation against an original code baseline.
