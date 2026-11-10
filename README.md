# Peeker

A local, read-only Kubernetes security explorer with a context selector. The first page prioritizes pods by configuration risk; compact findings explain pod hardening and service-account permissions, with expandable actions and evidence. Pod pages also explain ownership, network policies, Services and routes, and show live HTTP traffic from Istio access logs. **Cluster data stays in memory: no database, persistent application inventory, credentials in the browser, or telemetry backend.** Snapshots and traffic aggregates are discarded when their request or session ends. Only your workload-hiding preferences are saved in browser storage, separately for each context.

The production frontend is statically generated at build time and embedded in the Go executable. Deploy just the binary; it serves the HTML, JavaScript, CSS and API from one loopback address.

## Install as a Go tool

With Go 1.27.3, inside an existing Go module (or run `go mod init example.com/peeker-tools` in a new directory):

```sh
go get -tool github.com/clavinjune/peeker/cmd/peeker@latest
go tool peeker
```

Open **http://127.0.0.1:8080** and choose a Kubernetes context. This records a tool dependency in the consumer's `go.mod`; run it with `go tool peeker`. No Node, Bun or frontend build is needed. Install `kubectl` and configure the read-only Kubernetes identity described below in each cluster you want to inspect. The downloaded module includes its setup manifests; locate it with `go list -m -f '{{.Dir}}' github.com/clavinjune/peeker`.

Use `@v0.0.1` instead of `@latest` to pin this release.

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
| MCP Go SDK | 1.8.0 |

Frontend transitive dependencies are pinned in `web/bun.lock`; the official MCP Go SDK and its dependencies are pinned in `go.mod` and `go.sum`. Official Go and Node release indexes confirmed both exact requested versions. The pre-existing Node on PATH was 22.23.1; `.tools/node` contains the checksum-verified exact requested version, without replacing the global executable. The Istio Helm index lagged behind GitHub releases, so setup uses the verified official 1.32.0 release's `istioctl` and bundled manifests.

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

After toolchain bootstrap, build the standalone application from the repository root:

```sh
bash scripts/build.sh
```

This installs from the frozen frontend lockfile, type-checks, builds and prerenders the frontend, checks the generated files for publication, then compiles `bin/peeker` with those assets embedded. `web/dist` is included in version control and the Go module, so `go run` and `go test ./...` also work from a fresh checkout without a frontend build. Rebuild after frontend source changes.

Start Peeker and choose a context in the dropdown:

```sh
./bin/peeker
```

Use `./bin/peeker -context rancher-desktop` to select a context at startup. Istio sidecars are expected by default; use `-expect-istio=false` for intentionally sidecar-free or ambient clusters.

For frontend development, also run:

```sh
export PATH="$PWD/.tools/node/bin:$PATH"
cd web
bun install --frozen-lockfile
bun run dev
```

- Frontend development: **http://127.0.0.1:5173**
- Go backend / built frontend: **http://127.0.0.1:8080**
- Kubernetes proxy: managed automatically on an ephemeral loopback port (backend-only; not a browser API).
- For an externally managed proxy, run `bash scripts/proxy.sh` separately, then `./bin/peeker -proxy http://127.0.0.1:8001`. `KUBECTL_PROXY_URL` also opts into external mode. The selector is disabled because Peeker cannot identify or switch that proxy's context. Non-loopback URLs, credentials in URLs, redirects, query strings and URL paths are rejected.

The compiled binary runs from any directory without an external `web/dist`, Node, Bun or the Go compiler. Managed mode needs `kubectl` on PATH and a trusted local kubeconfig. `go run ./cmd/peeker` uses the included generated assets. Rebuild the binary to include frontend changes; Vite supplies live frontend updates during development.

### Contexts, networking badges and hidden workloads

- The dropdown lists `kubectl config get-contexts -o name`; choosing one starts its own loopback proxy, impersonating `system:serviceaccount:peeker-system:peeker-reader`. Selection does not modify kubeconfig's current context. **Reload contexts** refreshes the list; **Reconnect** restarts the selected proxy. Authentication remains kubectl's responsibility, including any trusted kubeconfig exec plugins.
- Apply `cluster/reader.yaml` with an authorized administrator to each intended cluster. The local caller also needs permission to impersonate the reader and its service-account/authenticated groups. Missing permissions remain denied; Peeker never falls back to unrestricted credentials. The Rancher Desktop networking/install scripts are specific to the inspected local cluster and are not required for other clusters.
- Context selection is shared by tabs connected to one Peeker process. Switching stops the previous proxy, cancels its reads/streams and resets the view; generation headers reject stale requests. Other tabs check context state every three seconds. Graceful shutdown stops the managed proxy.
- **Istio detected** and **Cilium detected** mean their API groups are registered (`networking.istio.io` and `cilium.io`). They do not assert that a controller is healthy or that every pod uses it. Failed discovery shows **Networking detection unavailable**.
- A row's **Hide** checkbox hides its UID-resolved top-level owning workload (for example Deployment, DaemonSet or CronJob), including replacement pods. The preference identifies the context, namespace, API group, kind and workload name; recreating that workload with the same name retains the preference. Unresolved ownership and standalone pods fall back to the exact pod instance.
- Enable **Show hidden** and uncheck a row's Hide checkbox to restore it. Risk summaries reflect the visible rows. Workload identifiers are stored only in this browser's local storage, scoped to the Peeker origin and context name. Renaming or repointing a kubeconfig context changes or reuses that preference scope. Blocked/full storage shows an explicit warning; external-proxy mode hides only within the current view.

```sh
kubectl --context rancher-desktop -n istio-system port-forward --address=127.0.0.1 service/istio-ingressgateway 9080:80
kubectl --context rancher-desktop -n istio-system port-forward --address=127.0.0.1 service/kiali 20001:20001
```

- Bookinfo: **http://127.0.0.1:9080/productpage**
- Kiali: **http://127.0.0.1:20001/kiali/**

`cluster/kiali.yaml` sets `external_services.prometheus.enabled: false`, disables Grafana, tracing, custom dashboards, AI and metrics export, and enables view-only mode. Kiali 2.34.1 supports configuration/workload/service visibility without Prometheus. **Its traffic graph, rates, latency, traffic tabs and request-based health are unavailable.** Istio configuration does not supply traffic metrics. Anonymous Kiali access is for this localhost-only port-forward.

Kiali may still render zero-RPS or “no traffic” placeholders in its overview when metrics are disabled; these are not measurements. This Istio release injects `istio-proxy` as a native restartable init-container sidecar. Peeker and the verification script count its readiness alongside application containers.

## Read-only boundary and architecture

Browser → same-origin Go API → fixed allowlisted Kubernetes reads through `kubectl proxy` → selected context. Vite proxies only `/api` to Go during development. Production assets are served from Go's embedded read-only filesystem. No database or external application services are needed.

### Static generation and embedding

- `web/src/App.tsx` is shared by the build-time renderer and browser.
- `web/scripts/prerender.mjs` uses React's `renderToString` to generate the application shell, headings, context controls and loading state inside `web/dist/index.html` after Vite builds the JavaScript and CSS. It runs with Bun and the existing dependencies.
- `web/src/main.tsx` hydrates generated HTML in production and mounts normally under Vite development.
- `web/embed.go` embeds only `dist/index.html` and `dist/assets` with Go's required `//go:embed` compiler directive.
- `cmd/peeker/main.go` passes that embedded filesystem to the HTTP handler. The handler serves the shell for `/` and direct `/pods/{namespace}/{name}` navigation, and serves files under `/assets/`. Asset directory listings and source-file access return 404. HTML is revalidated; hashed assets have immutable caching.

SSG covers the application shell. Kubernetes inventory, pod details and graphs remain live client-side API reads after hydration; builds require no cluster connection and contain no cluster snapshots or credentials. Pod URLs use the same generated shell and load their current details in the browser. JavaScript is required for live data and interaction. There is no runtime server-side React renderer and no Node/Bun runtime in production.

### Publishing generated assets

Run `bash scripts/build.sh` and include all of `web/dist` in the same commit as frontend changes, including deletions of old hashed assets. Publish that commit as a Go module version. Go builds do not run Bun or regenerate frontend files.

`scripts/check-dist.py` allows only prerendered `index.html` and its linked hashed JavaScript/CSS files. It rejects unexpected files, directories, symlinks, source maps, development entry points, local workstation paths and selected credential formats. Vite source maps are disabled. The generated shell contains no live workload data; `.local`, `.tools`, `.env*`, Python caches, dependencies and binaries are gitignored. This targeted check complements review of the files being published; it is not an exhaustive secret detector.

Go exposes only:

- `GET /api/health`
- `GET /api/contexts` (add `?refresh=true` to rediscover local context names)
- `POST /api/context` (managed mode only; selects a local proxy, never mutates Kubernetes)
- `GET /api/capabilities`
- `GET /api/pods?namespace=...&name=...`
- `GET /api/pods/{namespace}/{name}`
- `GET /api/pods/{namespace}/{name}/traffic?uid=...` (bounded server-sent events or an explicit availability state)
- `POST /mcp` (read-only agent tools over Streamable HTTP)

Every non-GET method except local context selection and MCP POSTs is rejected before contacting Kubernetes. Context selection requires an exact same-origin Origin, JSON content type, action header, bounded payload and a name from fresh kubectl discovery. Commands use fixed argument arrays without a shell. There are no Kubernetes mutation, exec, attach, arbitrary proxy, or arbitrary resource endpoints. Names are validated. The HTTP client only makes GET requests to fixed resource/discovery paths, bounds response size and pagination, times out, and refuses redirects. The frontend receives selected pod identity fields, not pod environments, volume credentials, service account tokens, Secrets or kubeconfig. Loopback Host and same-origin checks prevent exposing reads via an arbitrary website's origin or DNS rebinding.

`cluster/reader.yaml` defines a get/list-only ServiceAccount identity. Managed proxies use the selected context **with impersonation of that identity**, including its service-account groups; `scripts/proxy.sh` does the same for Rancher Desktop. The underlying caller must have impersonation permission. The proxy also rejects mutating HTTP methods. The original kubeconfig remains on the host and is read only by kubectl; Peeker requests only context names. Alternatively, start an external proxy with a kubeconfig containing a short-lived token for `peeker-system/peeker-reader`, omitting impersonation flags. Keep that kubeconfig outside the repo and renew the token when it expires. A proxy using unmodified admin credentials is **not** made read-only by being a proxy.

Read permissions: namespaces, pods, Services, ServiceAccounts, replicationcontrollers; Roles/RoleBindings/ClusterRoles/ClusterRoleBindings; apps deployments/replicasets/statefulsets/daemonsets; batch jobs/cronjobs; NetworkPolicies/Ingresses; EndpointSlices; Cilium namespaced/clusterwide policies; Istio VirtualServices/Gateways/DestinationRules; Gateway API HTTPRoutes/TCPRoutes/Gateways/ReferenceGrants; discovery GETs; `get` on `pods/log`. No Secrets, exec/attach, watches, or writes are granted. Kubernetes RBAC cannot restrict logs by container name: this identity can read other containers' logs, while Peeker fixes its log requests to `istio-proxy` and exposes only aggregates. Discovery failure is distinct from missing APIs; denied and disconnected reads remain errors, never empty inventories. Existing installations should reapply `cluster/reader.yaml` for the added read permissions.

## MCP and agent skill

Connect a trusted local agent's MCP client to **http://127.0.0.1:8080/mcp** with Streamable HTTP (use Peeker's configured port). Start Peeker with `-context CONTEXT` or choose a context in the browser first. The endpoint uses stateless JSON responses and provides four tools:

| Tool | Purpose |
| --- | --- |
| `cluster_status` | Current context, readiness and generation |
| `cluster_capabilities` | Registered networking APIs and assessment expectations |
| `list_pods` | Risk-ranked inventory, optional namespace and pages of up to 100 |
| `get_pod` | Findings, actions, ownership, policy/routing evidence and coverage gaps |

All reads after `cluster_status` require its generation. A context switch rejects stale requests and cancels active reads. Pagination uses fresh snapshots; workloads hidden in the browser remain included. MCP cannot switch contexts, mutate Kubernetes, execute commands, read Secrets or return raw logs. Cluster-derived strings are untrusted evidence, never agent instructions. Four concurrent single-object MCP requests, 16 KiB request bodies, 16 MiB captured API results and 45-second request/read deadlines bound this interface. Batch requests and subscriptions are rejected, list-change notifications are disabled, and responses enforce `Cache-Control: no-store`.

Install the accompanying workflow in the current project or your home directory:

```sh
peeker skills add
peeker skills add --global
```

For Go-tool installations, use `go tool peeker skills add [--global]`. These create `.agents/skills/peeker/SKILL.md` under the current directory or home, respectively. Existing skills are preserved, and symlinks cannot redirect writes outside the chosen root. The installer does not configure the agent's MCP client; register the endpoint in that client's settings.

The endpoint is intended for trusted processes on the same machine; keep it on loopback. Peeker keeps cluster responses in memory, but a consuming agent may retain tool results in its own conversation history.

## Live pod traffic

Open a pod's **Live traffic** tab. Peeker follows only new `istio-proxy` log lines while that tab is mounted. Regular and native restartable-init sidecars are supported. Pods without Istio show **“istio-proxy isn't there”**; waiting, denied, replaced, idle and disconnected states remain explicit. Pause or leave the tab to cancel the upstream log request; **New session** resets the counts. Sessions end after five minutes without automatic replay.

`cluster/istio.yaml` defines the `peeker-access-log` JSON provider, and `cluster/telemetry.yaml` enables it only in `peeker-bookinfo`. `setup.sh` applies both. The provider logs timestamps, protocol, proxy addresses, cluster, status/flags and duration; it omits request paths, query strings, headers and bodies. This creates ordinary Kubernetes container logs subject to the node's log retention; Peeker itself writes no log data or aggregates to disk. Remove the Telemetry resource to stop this scoped logging. No Prometheus, Grafana or tracing backend is installed.

- Arrows represent completed HTTP requests observed by the selected sidecar. Counts, HTTP/proxy errors and mean duration are session aggregates, not mesh-wide telemetry.
- Only structured JSON with a timestamp, supported HTTP protocol and an `inbound|` or `outbound|` cluster is recognized. TCP, passthrough and startup logs are excluded. No observed records can mean idle traffic or disabled/incompatible logging; it never proves zero traffic.
- Inbound peers use the direct downstream address, not forwarded request headers. Outbound peers use the upstream address. Unique pod-IP matches come from inventory at session start; shared or unresolved addresses remain unknown. IP reuse during a session can stale attribution; start a fresh session after rollouts. The selected pod UID is checked before streaming.
- One sidecar cannot show downstream relationships between other workloads. The graph retains up to 64 directed relationships and renders at most 22 nodes, with all retained relationships in the expandable list.
- Four concurrent sessions are allowed per process. Each reads at most 16 MiB, 100,000 lines and 16 KiB per line, sends aggregates once a second and uses bounded channels and write deadlines. Unrecognized and relationship-limit omissions are counted. Raw logs and arbitrary log fields never reach the browser.

## Risk scoring

The inventory defaults to **Highest risk**, with **Needs review** (incomplete assessments first) and **Namespace / name** alternatives. Summary counts reflect the current filters. Each row shows a score, severity and top finding; details start with collapsed findings containing recommended actions and technical evidence.

Risk model v1 is a configuration-prioritization heuristic, not a probability of compromise, compliance certification or CVSS score:

| Highest finding | Score band |
| --- | --- |
| Critical | 80–100 |
| High | 50–79 |
| Medium | 20–49 |
| Low | 5–19 |

The highest severity supplies the band's starting score. Each additional distinct finding adds `max(1, floor(its severity's starting score / 5))`, capped at the band's ceiling. Multiple affected containers or bindings retain evidence without counting the same finding twice. No lower-severity combination outranks a higher severity. Zero means **No findings in supported checks**, never proven secure. Unknown checks produce `≥score`; zero with unknown checks is **Unrated**. Ties prioritize incomplete coverage, then namespace/name.

- Pod checks cover regular, init and ephemeral containers: privileged mode, explicit UID 0, privilege escalation, powerful added capabilities, default capability retention, seccomp, writable root filesystems, host namespaces, mounted hostPath volumes and service-account token configuration. Container settings override inherited pod settings; unspecified image users and node seccomp defaults remain unknown. Windows hardening is marked incomplete.
- RBAC checks resolve direct service-account subjects, matching User identities and service-account/authenticated groups. Findings cover unrestricted cluster administration, wildcards on supported sensitive permissions, Secrets reads, exec/attach, supported workload writes, and bind/escalate/identity/token delegation. Published aggregated role rules are used; unavailable or unresolved roles create coverage gaps.
- RoleBindings retain their namespace scope, even when referencing ClusterRoles or accounts from another namespace. All namespaces' RBAC collections are read even when pod inventory is filtered. Named-resource constraints are recognized and identified in evidence; top-level create is not authorized by a `resourceNames`-restricted rule.
- Identity grants are assessed even when token automount is disabled. Admission policy, other authorizers, unmodeled RBAC escalation paths and actual token usability are not evaluated. The service-account defaults are current snapshots, not a reconstruction of pod admission history.
- **Deny-by-default networking is expected in both directions.** Kubernetes NetworkPolicy, CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy contribute to one baseline. Missing isolation produces separate medium ingress/egress findings. Narrow exceptions are permitted. Supported broad allowances on all ports are findings: unrestricted Kubernetes peers or `/0` blocks without exclusions, and Cilium unrestricted rules, `all`/`world` entities or `/0` CIDR/CIDRSet rules without exclusions. Kubernetes protocol-only ports and full numeric port ranges also count as broad access for that protocol. Other overly broad combinations are not exhaustively proven.
- Kubernetes policy allows are additive; a separate empty allow list cannot undo a broad allowance. For Cilium, any selecting policy enabling default-deny establishes isolation. Omitted `enableDefaultDeny` defaults to enabled only when that direction has nonempty allow or deny rules; empty lists alone do not isolate. An explicit supported Cilium deny-all overrides broad allowances; partial deny overlap remains unknown. Explicitly disabled default-deny does not supply isolation and cannot override another selecting policy's enabled setting.
- Inventory and detail use the same combined checks. Policy types/defaulting, selectors and namespace boundaries are honored. Denied inventories, unknown selectors and unavailable namespace identity labels remain coverage gaps. Missing Cilium APIs do not imply missing protection; Kubernetes checks still apply. Host-network pods remain unknown. These findings describe configured policy intent, not actual reachability or CNI enforcement mode.
- **Istio sidecars are expected by default.** Missing regular or restartable-init `istio-proxy` containers produce a medium finding. Use `-expect-istio=false` for intentional ambient/sidecar-free configurations. Presence does not establish proxy health, mTLS or mesh enforcement.
- Actual network-policy enforcement, image vulnerabilities and runtime behavior are outside this score. Infrastructure workloads may intentionally require high-risk privileges. Completed pods retain their configured score; their phase remains visible. Review findings in workload context rather than blindly removing required permissions.

## Interpretation limits

- Kubernetes NetworkPolicies use controlling pod labels, match expressions, `policyTypes` defaulting, separate ingress/egress isolation and a union of allow rules. Namespace and pod selectors in one peer are ANDed; separate peers/rules/policies are ORed. Pod-only peers are namespace-local. Empty selectors match all; an empty directional rule list allows nothing from that policy, while `[{}]` allows all in that direction. IP block exceptions, port ranges, named destination ports, default TCP, UDP and SCTP are displayed.
- An allowance is a configuration predicate, including potential future pods. Peer counts use current readable namespaces/pods. Zero current matches does not erase a selector rule. Named ports are reported as destination-pod named-port constraints, not guessed from the source. CIDRs are not equated to workloads because NAT ordering varies.
- The ingress/egress summaries are **Kubernetes NetworkPolicy-only**. Absence of isolation does not prove internet access or absence of other enforcement. Both ends of a connection, the CNI's enforcement mode, host policies, routing, Istio authorization/mTLS and applications can affect delivery.
- Cilium policy endpoint selectors are matched against Kubernetes label identities. Rules display entities, peers, CIDRs, service/FQDN selectors, ports, deny rules and L7 restrictions. This is a **partial rule inventory**, not Cilium's complete effective policy engine. Allow edges remain unknown, and explicit deny rules are distinguished; selecting deny rules take precedence over allow rules, including Kubernetes allowances. Dynamic DNS identities, named-port resolution, cluster identities, CIDR groups, host/node policies, L7 predicates, authentication and enforcement-mode overrides are not fully evaluated. Raw L7 headers and secret values are withheld.
- Ownership follows controlling references and matching UIDs, including ReplicaSet→Deployment and Job→CronJob. Unreadable, missing, recreated, cyclic, or unsupported custom owners are labeled unresolved; names are never guessed.
- Services connect through nonempty selectors and/or EndpointSlice Pod UID references. Empty Service selectors do not mean all pods. Endpoint readiness and port mappings are evidence, not assumed delivery. EndpointSlices without a Pod UID are not guessed from a possibly reused IP.
- Ingress backends, Istio HTTP/TCP/TLS destinations and Gateway API HTTP/TCP backend references are resolved by service name, namespace and port. Istio named subsets are label-checked when a unique visible DestinationRule is found; missing/ambiguous subset resolution is unknown. Custom DNS suffixes, wildcard service hosts, VirtualService delegation/mirrors, and complex DestinationRule lookup precedence are not resolved.
- Gateway API cross-namespace Service refs require a matching ReferenceGrant. Current-generation `Accepted` and `ResolvedRefs` conditions are distinguished from configured refs. Gateway listener constraints and Programmed status are displayed; route match evaluation, host intersection, cross-namespace gateway listener admission and actual external reachability are not synthesized when no authoritative status proves acceptance. Istio and Ingress lack a universal equivalent accepted condition; these remain configured references.
- Policy and topology graphs are **configuration-derived**. Live traffic is a separate, explicitly labeled sidecar observation. Every relationship links to evidence, including explicit unknown-inventory evidence. Graphs draw at most 22 nodes for readability; relationship lists retain all evidence.
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
bash scripts/build.sh
bun test web/tests
python3 -m unittest discover -s scripts -p 'test_*.py'
go test -race -v ./...
go vet ./...
./bin/peeker
```

Tests exercise hardening inheritance, coverage gaps, token precedence, severity bands/deduplication, sorting, RBAC scopes/subjects/constraints, publication checks, additive network policy semantics, selectors, CIDRs/ports, Cilium deny precedence, UID ownership chains, route resolution/status, mutation rejection, embedded HTML/assets, deep links, path boundaries, URL validation and credential redaction. Traffic tests cover parsing, IPv6/shared/unknown peer attribution, native/absent sidecars, denial/replacement, aggregation bounds, stream cancellation/capacity and split UTF-8 events. Actual live verification and browser results are recorded in [VERIFICATION.md](VERIFICATION.md).

## Cleanup

Stop the foreground backend, Vite, proxy and port-forward processes with Ctrl-C. Remove the isolated demo with the command above. Application resources and read permissions can be removed with:

```sh
kubectl --context rancher-desktop delete -f cluster/reader.yaml --ignore-not-found
kubectl --context rancher-desktop delete -f cluster/namespaces.yaml --ignore-not-found
helm --kube-context rancher-desktop uninstall peeker-kiali -n istio-system --ignore-not-found
.tools/istio/bin/istioctl uninstall --context rancher-desktop --manifests .tools/istio/manifests -f cluster/istio.yaml --skip-confirmation
```

Istio CRDs are retained by its uninstaller to avoid deleting other users' custom resources. Review for other consumers before removing shared infrastructure. **Keep Cilium while this cluster uses it:** uninstalling the active CNI would break unrelated workloads. To return to Flannel, perform a separate reverse CNI migration, preserve workload data, restore the saved Flannel settings/config and then uninstall only `peeker-cilium`; do not reset Kubernetes. Remove only the provision block added by this project from the Lima override after Cilium is retired. No cleanup command deletes unrelated workloads, their storage, or existing Traefik/Gateway API installations.
