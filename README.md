# Peeker

A local, read-only Kubernetes security explorer for `rancher-desktop`. The first page lists real pods; pod pages explain ownership, network-policy selection, Services and route references with clickable resource evidence. **Memory only: no database, persistent inventory, credentials in the browser, or telemetry service.** Each refresh builds a request-scoped snapshot in Go and discards it after responding.

## Versions

| Component | Pin |
| --- | --- |
| Go | 1.27.3 |
| Node.js | 26.13.0 |
| Bun | 1.4.2 |
| Rancher Desktop inspected | 1.24.0, macOS arm64, Moby |
| Kubernetes inspected | 1.37.0+k3s1 |
| Cilium | 1.20.4 |
| Istio / Bookinfo manifests | 1.32.0, sidecar mode (Bookinfo images 1.20.3) |
| Kiali server chart / image | 2.34.1 |
| React / React DOM | 19.3.1 |
| Mantine core / hooks | 9.8.0 |
| TypeScript / Vite | 7.0.2 / 8.3.7 |

Frontend transitive dependencies are pinned in `web/bun.lock`. The Go backend uses only the standard library. Official Go and Node release indexes confirmed both exact requested versions. The pre-existing Node on PATH was 22.23.1; `.tools/node` contains the checksum-verified exact requested version, without replacing the global executable. The Istio Helm index lagged behind GitHub releases, so setup uses the verified official 1.32.0 release's `istioctl` and bundled manifests.

Istio 1.32 supports Kubernetes 1.37. Cilium 1.20's published guaranteed e2e matrix ends at 1.36; its documentation says newer Kubernetes compatibility depends on Kubernetes backward compatibility. This repository validates the actual 1.37 cluster rather than asserting it is in that published matrix.

## Toolchain and cluster setup

From this repository root:

```sh
bash scripts/bootstrap.sh
export PATH="$PWD/.tools/node/bin:$PATH"
go version
node --version
bun --version
kubectl --context rancher-desktop cluster-info
```

Bootstrap is intentionally pinned to the inspected macOS arm64 environment. It refuses a different Go version or platform rather than substituting versions. It needs `curl`, `tar`, `shasum`, Python 3, Helm and Rancher Desktop's `rdctl` and `kubectl`.

### Rancher Desktop networking prerequisite

The initial cluster used Flannel and contained unrelated workloads. **Do not reset Kubernetes, change the Kubernetes version, or switch container engines.** Those workloads and storage must be retained. Changing the CNI restarts the local VM and interrupts workloads while their pod sandboxes are recreated.

For the inspected Rancher Desktop version, Flannel is a **non-GUI setting**. The supported setting is:

```sh
rdctl api /v1/propose_settings --method PUT --body '{"version":19,"kubernetes":{"options":{"flannel":false}}}'
rdctl set --kubernetes.options.flannel=false
```

The preview returned `severity: restart`, not reset. Wait for Rancher Desktop to finish restarting. Its server arguments must include both `--flannel-backend=none` and `--disable-network-policy`:

```sh
rdctl api /v1/backend_state
rdctl shell -- sudo -n cat /etc/conf.d/k3s
```

Before the restart, install `cluster/rancher-desktop-override.yaml` at `~/Library/Application Support/rancher-desktop/lima/_config/override.yaml`. If an override already exists, merge its `provision` entry rather than overwriting the user's configuration. This provisions shared BPF, cgroupv2 and network namespace mounts needed by Cilium with Moby. For this session the override was newly created; the mount commands were also applied to the running VM. The official Cilium Rancher Desktop tutorial's older **Reset Kubernetes** step is deliberately not used.

After disabling Flannel, move any remaining `10-flannel.conflist` files in `/etc/cni/net.d` and `/var/lib/rancher/k3s/agent/etc/cni/net.d` to the same name plus `.peeker-backup`, preserving their contents. Do not move them while Flannel is enabled. `setup.sh` refuses to install alongside an active Flannel configuration. Backups are not CNI config files.

With Flannel disabled, k3s launches its embedded cri-dockerd without CNI path overrides. It uses `/etc/cni/net.d` and `/opt/cni/bin`. The runtime explicitly reported the latter in `k3s.log`; installing binaries into `/usr/libexec/cni` or `/var/lib/rancher/k3s/data/cni` left kubelet `NotReady` even with a healthy Cilium agent. The checked-in values use these cri-dockerd defaults. The former Flannel-mode k3s directories are not the runtime's active paths after this transition.

Cilium uses a distinct `10.44.0.0/16` pool and VXLAN port 8473 to avoid collisions with old Flannel sandboxes (`10.42.0.0/16`, VXLAN 8472). Kube-proxy is retained, socket load balancing is host-namespace-only, and CNI exclusivity is disabled for Istio coexistence. Istiod uses host networking so the API server can reach the injection webhook through the overlay. No ambient components are installed. Cilium L7 interception is not combined with Bookinfo's Istio mTLS.

```sh
bash scripts/setup.sh
bash scripts/verify-cluster.sh
```

Setup uses pinned Helm releases (`peeker-cilium`, `peeker-kiali`), `istioctl install`, and declarative applies. Rerunning reconciles these same installations. It does not reset the cluster or install Prometheus, Grafana, tracing, Hubble, or their operators. It is intended for this inspected cluster; do not run it over an unrelated pre-existing Cilium or default Istio installation.

Official guidance:

- [Rancher Desktop non-GUI settings](https://docs.rancherdesktop.io/1.24/references/non-gui-settings/)
- [Cilium k3s installation](https://docs.cilium.io/en/stable/installation/k3s/), [CNI migration](https://docs.cilium.io/en/stable/installation/k8s-install-migration/), [Istio coexistence](https://docs.cilium.io/en/stable/network/servicemesh/istio/)
- [Istio supported versions](https://istio.io/latest/docs/releases/supported-releases/)
- [Kiali without Prometheus](https://kiali.io/docs/configuration/external-services/metrics/prometheus/#disabling-prometheus)

## Run locally

Run each long-lived command in its own terminal, from the repository root:

```sh
bash scripts/proxy.sh
```

```sh
go run ./cmd/peeker
```

```sh
export PATH="$PWD/.tools/node/bin:$PATH"
cd web
bun install --frozen-lockfile
bun run dev
```

- Frontend development: **http://127.0.0.1:5173**
- Go backend / built frontend: **http://127.0.0.1:8080**
- Kubernetes proxy: `http://127.0.0.1:8001` (backend-only; not a browser API)
- Set `KUBECTL_PROXY_URL=http://127.0.0.1:8002` to use another loopback proxy. Non-loopback URLs, credentials in URLs, redirects, query strings and URL paths are rejected.

```sh
kubectl --context rancher-desktop -n istio-system port-forward --address=127.0.0.1 service/istio-ingressgateway 9080:80
kubectl --context rancher-desktop -n istio-system port-forward --address=127.0.0.1 service/kiali 20001:20001
```

- Bookinfo: **http://127.0.0.1:9080/productpage**
- Kiali: **http://127.0.0.1:20001/kiali/**

`cluster/kiali.yaml` sets `external_services.prometheus.enabled: false`, disables Grafana, tracing, custom dashboards, AI and metrics export, and enables view-only mode. Kiali 2.34.1 supports configuration/workload/service visibility without Prometheus. **Its traffic graph, rates, latency, traffic tabs and request-based health are unavailable.** Istio configuration does not supply traffic metrics. Anonymous Kiali access is for this localhost-only port-forward.

Kiali may still render zero-RPS or “no traffic” placeholders in its overview when metrics are disabled; these are not measurements. This Istio release injects `istio-proxy` as a native restartable init-container sidecar. Peeker and the verification script count its readiness alongside application containers.

## Read-only boundary and architecture

Browser → same-origin Go API → fixed allowlisted Kubernetes reads through `kubectl proxy` → `rancher-desktop`. Vite proxies only `/api` to Go during development. Production assets are served by Go. No database or external application services are needed.

Go exposes only:

- `GET /api/health`
- `GET /api/pods?namespace=...&name=...`
- `GET /api/pods/{namespace}/{name}`

Every non-GET method is rejected before contacting Kubernetes. There are no mutation, exec, attach, arbitrary proxy, or arbitrary resource endpoints. Names are validated. The HTTP client only makes GET requests to fixed resource/discovery paths, bounds response size and pagination, times out, and refuses redirects. The frontend receives selected pod identity fields, not pod environments, volume credentials, service account tokens, Secrets or kubeconfig. Loopback Host and same-origin checks prevent exposing reads via an arbitrary website's origin or DNS rebinding.

`cluster/reader.yaml` defines a get/list-only ServiceAccount identity. `scripts/proxy.sh` uses the explicitly targeted Rancher Desktop admin connection **with impersonation of that identity**, including its service-account groups. The underlying caller must have impersonation permission. The proxy also rejects mutating HTTP methods. The original admin kubeconfig remains on the host; it is never loaded by Peeker. Alternatively, use a kubeconfig containing a short-lived token for `peeker-system/peeker-reader` and a context named `rancher-desktop`, omitting impersonation flags. Keep that kubeconfig outside the repo and renew the token when it expires. A proxy using unmodified admin credentials is **not** made read-only by being a proxy.

Read permissions: namespaces, pods, Services, replicationcontrollers; apps deployments/replicasets/statefulsets/daemonsets; batch jobs/cronjobs; NetworkPolicies/Ingresses; EndpointSlices; Cilium namespaced/clusterwide policies; Istio VirtualServices/Gateways/DestinationRules; Gateway API HTTPRoutes/TCPRoutes/Gateways/ReferenceGrants; discovery GETs. No Secrets, pod logs, exec/attach, watches, or writes are granted. Discovery failure is distinct from missing APIs; denied and disconnected reads remain errors, never empty inventories.

## Interpretation limits

- Kubernetes NetworkPolicies use controlling pod labels, match expressions, `policyTypes` defaulting, separate ingress/egress isolation and a union of allow rules. Namespace and pod selectors in one peer are ANDed; separate peers/rules/policies are ORed. Pod-only peers are namespace-local. Empty selectors match all; an empty directional rule list allows nothing from that policy, while `[{}]` allows all in that direction. IP block exceptions, port ranges, named destination ports, default TCP, UDP and SCTP are displayed.
- An allowance is a configuration predicate, including potential future pods. Peer counts use current readable namespaces/pods. Zero current matches does not erase a selector rule. Named ports are reported as destination-pod named-port constraints, not guessed from the source. CIDRs are not equated to workloads because NAT ordering varies.
- The ingress/egress summaries are **Kubernetes NetworkPolicy-only**. Absence of isolation does not prove internet access or absence of other enforcement. Both ends of a connection, the CNI's enforcement mode, host policies, routing, Istio authorization/mTLS and applications can affect delivery.
- Cilium policy endpoint selectors are matched against Kubernetes label identities. Rules display entities, peers, CIDRs, service/FQDN selectors, ports, deny rules and L7 restrictions. This is a **partial rule inventory**, not Cilium's complete effective policy engine. Allow edges remain unknown, and explicit deny rules are distinguished; selecting deny rules take precedence over allow rules, including Kubernetes allowances. Dynamic DNS identities, named-port resolution, cluster identities, CIDR groups, host/node policies, L7 predicates, authentication and enforcement-mode overrides are not fully evaluated. Raw L7 headers and secret values are withheld.
- Ownership follows controlling references and matching UIDs, including ReplicaSet→Deployment and Job→CronJob. Unreadable, missing, recreated, cyclic, or unsupported custom owners are labeled unresolved; names are never guessed.
- Services connect through nonempty selectors and/or EndpointSlice Pod UID references. Empty Service selectors do not mean all pods. Endpoint readiness and port mappings are evidence, not assumed delivery. EndpointSlices without a Pod UID are not guessed from a possibly reused IP.
- Ingress backends, Istio HTTP/TCP/TLS destinations and Gateway API HTTP/TCP backend references are resolved by service name, namespace and port. Istio named subsets are label-checked when a unique visible DestinationRule is found; missing/ambiguous subset resolution is unknown. Custom DNS suffixes, wildcard service hosts, VirtualService delegation/mirrors, and complex DestinationRule lookup precedence are not resolved.
- Gateway API cross-namespace Service refs require a matching ReferenceGrant. Current-generation `Accepted` and `ResolvedRefs` conditions are distinguished from configured refs. Gateway listener constraints and Programmed status are displayed; route match evaluation, host intersection, cross-namespace gateway listener admission and actual external reachability are not synthesized when no authoritative status proves acceptance. Istio and Ingress lack a universal equivalent accepted condition; these remain configured references.
- Graphs are **configuration-derived topology**. Every relationship links to resource/field evidence, including explicit unknown-inventory evidence. The graph draws at most 22 nodes for readability; its relationship list retains all evidence. No observed traffic, RPS, latency or error rates are invented.
- Snapshots are bounded, request-scoped and not transactionally consistent across Kubernetes collections. Refresh after a rollout. Optional missing CRDs are normal. Denied APIs or disconnected proxies mean incomplete knowledge.

## Isolated policy demo

This is separate from normal Bookinfo operation and has no Istio injection. It demonstrates additive ingress policy selection, egress isolation, a Cilium world-deny rule and an Ingress-to-Service-to-pod chain. It does not claim that the Ingress can bypass the ingress policy.

```sh
kubectl --context rancher-desktop apply -f cluster/demo.yaml
kubectl --context rancher-desktop -n peeker-demo rollout status deployment/web --timeout=3m
```

Choose `peeker-demo` in the UI and open the `web` pod. Ingress has an allow predicate restricted to `purpose=policy-demo` namespaces AND `role=client` pods on named port `http`; egress is isolated without Kubernetes allow rules. No client pod is created, so the selector may have no current matches.

```sh
kubectl --context rancher-desktop delete -f cluster/demo.yaml --ignore-not-found
```

## Checks and builds

```sh
go test -race -v ./...
go vet ./...
go build -o bin/peeker ./cmd/peeker
export PATH="$PWD/.tools/node/bin:$PATH"
cd web
bun run typecheck
bun run build
cd ..
./bin/peeker
```

Tests exercise additive policy semantics, selector expressions, namespace AND semantics, policy direction defaulting, unknown/denied results, CIDR exceptions, ports, Cilium deny precedence, UID ownership chains, EndpointSlices, grants, subsets, stale route status, mutation rejection, production asset/API routing, URL validation and credential redaction. Actual live verification and browser results are recorded in [VERIFICATION.md](VERIFICATION.md).

## Cleanup

Stop the foreground backend, Vite, proxy and port-forward processes with Ctrl-C. Remove the isolated demo with the command above. Application resources and read permissions can be removed with:

```sh
kubectl --context rancher-desktop delete -f cluster/reader.yaml --ignore-not-found
kubectl --context rancher-desktop delete -f cluster/namespaces.yaml --ignore-not-found
helm --kube-context rancher-desktop uninstall peeker-kiali -n istio-system --ignore-not-found
.tools/istio/bin/istioctl uninstall --context rancher-desktop --manifests .tools/istio/manifests -f cluster/istio.yaml --skip-confirmation
```

Istio CRDs are retained by its uninstaller to avoid deleting other users' custom resources. Review for other consumers before removing shared infrastructure. **Keep Cilium while this cluster uses it:** uninstalling the active CNI would break unrelated workloads. To return to Flannel, perform a separate reverse CNI migration, preserve workload data, restore the saved Flannel settings/config and then uninstall only `peeker-cilium`; do not reset Kubernetes. Remove only the provision block added by this project from the Lima override after Cilium is retired. No cleanup command deletes unrelated workloads, their storage, or existing Traefik/Gateway API installations.
