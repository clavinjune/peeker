# Verification — 2026-11-11

Executed on macOS arm64. The v0.0.3 Registry checks include controlled loopback fixtures, real image scans, live Cilium containment, and live orphan/kill/storage checks on disposable **rancher-desktop** workloads. These are observed results, not expected outputs. Peeker keeps cluster data in bounded, session-local memory and has no database.

## v0.0.3 Explore / Registry verification

The existing Pod workspace is now `/explore`; `/registry` adds UID-bound controller registrations, template/live-Pod evidence, image scanning and explicit responder actions.

```text
bash scripts/build.sh: passed on Go 1.27.4; frozen dependencies, TypeScript, 920 Vite modules, React SSG, embedded binary
bash -n scripts/bootstrap.sh scripts/setup.sh scripts/build.sh: passed
bun test (web): 10 passed, 48 assertions
python3 -m unittest discover -s scripts -p 'test_*.py': 4 passed
go test -race ./...: passed across all packages, including 12 new Registry/action tests
go vet ./...: passed
go mod verify: all modules verified
go tool deadcode ./...: no unreachable functions reported
go tool govulncheck ./...: no vulnerabilities found with Go 1.27.4
bun audit --cwd web: no vulnerabilities found across 88 packages
Semgrep p/security-audit + p/secrets: 175 applicable rules, 80 files, zero findings and zero parse errors
git diff --cached --check (source/docs; generated assets excluded): passed
```

- The initial Go 1.27.3 vulnerability check reported `GO-2026-6859` in `net/http`, fixed by Go 1.27.4. The user explicitly approved keeping the concurrent Go 1.27.4/dependency upgrades. Build/bootstrap/setup checks and current documentation now agree; historical verification records below retain their original versions. Node 26.13.0, Bun 1.4.2 and frontend dependency pins remain in place.
- Registry regression tests exercise supported controller kinds, Pod rejection, UID/context isolation, same-origin/action headers, external-proxy mutation rejection, template/live evidence separation, reference-value redaction, backup-before-mutation, shared identities and mixed subjects, Cilium/host-network/incomplete-inventory refusal, containment retry and partial failure, Deployment/ReplicaSet and CronJob/Job orphan chains, foreground deletion preconditions, and Trivy argument/cancellation boundaries.
- Chrome exercised the embedded frontend using a synthetic Kubernetes API and fake kubectl proxies on port 8086. Registration, the risk badge, detail/hardening evidence, real asynchronous Trivy results, containment and its backup, Deployment-to-ReplicaSet orphan requests, and the kill-switch completed. The final build showed explicit deletion-request feedback instead of a misleading inaccessible-workload alert. Registry retained the stale UID registration and its downloadable 773-byte Role/RoleBinding YAML backup after deletion and navigation. `/explore` and `/explore/pods/default/web-pod` rendered the preserved inventory and detail tabs.
- Trivy 0.76.2 scanned the real public `alpine:3.22` image with remote image access, vulnerability-only scanning, telemetry disabled and memory-backed image caching. Its valid CycloneDX report contained **17 components and 1 vulnerability** (30,925 bytes); the browser also displayed the completed report. Counts describe that scan, not a stable property of the mutable tag. Trivy databases and temporary analysis retain Trivy's own local storage behavior.
- The final Semgrep JSON includes every new production Registry Go file and `web/src/Registry.tsx`; normal test/dependency/generated-file exclusions apply. Publication checks accepted the three embedded static files with no detected credentials, workstation paths, source maps or development entry points. No application exception or hydration warning was observed; the post-delete detail refresh produced an expected HTTP 409 console entry.
- Ripwire contract checks passed for the checked Registry/backend entry points. Its unchanged `App` signature still triggered a JSX-call arity notice; TypeScript, the build and browser hydration passed. Quality-delta against `a0665b4b3` reports **three gating notices**: similarity between test request builders and short-horizon churn in `App`/`Client`. New-symbol complexity notices remain; Go tests and React callbacks also appear as structural dead-code notices despite execution. This is not a clean quality-gate claim. Vite retains a nonfatal approximately 545 kB JavaScript chunk-size warning.

### Evidence-backed image classification

- Real Trivy integration scans classified `alpine:3.22` as **not-distroless** (16 OS packages; `apk-tools 2.14.13-r0`, `busybox 1.37.0-r20`, `busybox-binsh 1.37.0-r20`) and `gcr.io/distroless/static-debian12:nonroot` as **distroless-consistent** (five OS packages; no recognized shell/package-manager packages). Both reported `linux/arm64` requested and `arm64` scanned. The scanner now explicitly requests the platform and all packages; the earlier implicit Trivy default had selected amd64 on this arm64 host.
- Resolved digests were `alpine@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f` and `gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab`. These identify the reported scan-time references, not a permanent guarantee about moving tags.
- Backend cases cover shell/package-manager detection, unsupported/empty inventories, language-package name collisions and duplicate packages. Frontend tests ensure a mutable-tag result never classifies a different pinned/observed digest and choose the latest completed matching result.
- Chrome scanned Alpine using the latest embedded binary and displayed the classification, digest, architecture, detected tools and limitations on both the SBOM and Hardening pages. The SBOM showed 17 components and one vulnerability. The browser tab, fixture and reader proxy were stopped afterward.
- Classification is package-database evidence, not filesystem/provenance proof. Manually copied binaries or incomplete inventories can escape detection; absent evidence stays **unknown**. Peeker stores results only in the current context session.

### Response-action scope

Containment, orphaning and kill-switch mutations were verified against controlled fixtures and the disposable live workloads below. The full reader/responder manifests were not applied: the live tests temporarily granted only test-scoped access. Existing workloads/storage were preserved, and no telemetry backend was installed.

Containment requires complete inventories and UID-matched CiliumEndpoints, refuses host-network Pods, and configures explicit ingress/egress denies for **current Pods only** without changing their specs or controller templates. It reports configuration rather than verified enforcement; replacement Pods need another action. Direct unshared RBAC grants are revoked after backup; shared/group/default/Peeker identities and role definitions remain. Orphaning can preserve processes for investigation but removes self-healing and does not prevent external reconciliation. Kill-switch deletion is asynchronous; Peeker issues no PVC/PV deletes. Registrations, scans and backups disappear on reconnect/context switch/process exit, and recovery is manual.

### Live Cilium containment

```text
python3 scripts/verify-containment.py --context rancher-desktop
result: PASS
cleanup: PASS
backupKinds: ClusterRole, ClusterRoleBinding, Role, RoleBinding
```

The successful run used a disposable namespace with three non-root BusyBox HTTP Deployments and an explicit allow-all NetworkPolicy. Peeker used the real reader and responder impersonation paths. All six HTTP paths worked before containment; these were the observed results after convergence and a further 20-second stability window:

| HTTP path | Before | After |
| --- | --- | --- |
| probe → target | allowed | denied |
| control → target | allowed | denied |
| target → probe | allowed | denied |
| target → control | allowed | denied |
| probe → control | allowed | allowed |
| control → probe | allowed | allowed |

- All three Pod UIDs, SHA-256 hashes of Pod specs, container IDs and restart counts were identical before/after; all restart counts stayed **0**. The target Deployment spec was also unchanged.
- `kubectl auth can-i` with the target ServiceAccount and its normal groups changed direct ConfigMap and namespace grants from **yes → no**. Its shared group ConfigMap grant remained **yes**, and the control ServiceAccount's independent grant remained **yes**. The action reported retained built-in group discovery grants and retained role definitions; containment does not promise zero remaining authorization.
- The downloaded backup contained original Role, ClusterRole, RoleBinding and ClusterRoleBinding objects. The direct test RoleBinding and ClusterRoleBinding were removed; shared bindings stayed intact.
- Cleanup removed the disposable namespace, external test RBAC objects and newly created responder ServiceAccount, then stopped Peeker and its proxies. Label-filtered inventory checks returned no remaining test resources; the responder ServiceAccount was absent, no verification processes remained, and ports 58534/8086 had no listeners. No PVC/PV resources were created or deleted by the test.
- The first attempt timed out waiting for Deployment availability before Peeker started and cleaned up successfully. A rerun with failure diagnostics passed without changing the workloads; the initial startup cause is unconfirmed. Future failures capture disposable Pod/controller status, events, Cilium objects and bounded logs before cleanup.
- This proves the six tested **new HTTP connections** on this Cilium cluster and stability during the measured window. Long-lived existing connections, other protocols, other nodes/clusters and workloads with network-dependent health probes need their own enforcement checks.

### Orphan propagation race regression

The first live orphan run exposed a real race hidden by synchronous fixtures: deleting a Deployment with orphan propagation asynchronously removed its ReplicaSet's owner reference between Peeker's GET and DELETE, changing `resourceVersion` and returning HTTP 409. The parent disappeared, the ReplicaSet remained, and the test reported failure and cleaned up its namespace and generated volume.

`registryStore.orphanChild` now refreshes on HTTP 409, with at most four attempts and cancellable delays. Every DELETE retains UID/resourceVersion preconditions; replacement UIDs or newly added owner references are refused. Other HTTP/transport failures are not retried. A new regression first reproduced the failure, then passed six cases: detached owner, replacement UID, adoption by another owner, forbidden response, retry limit and cancellation. The existing orphan-chain tests, full explorer and CLI race tests, and explorer vet passed. The embedded binary was rebuilt with `go build -trimpath -o bin/peeker ./cmd/peeker`. Targeted Semgrep scanned both live-verification scripts and the changed action backend: 143 rules, zero findings/errors. Ripwire retains the same three gating notices; new test/harness complexity and size notices remain.

### Live orphan / kill-switch / retained storage

```text
python3 scripts/verify-containment.py --context rancher-desktop --actions --storage-class local-path
result: PASS
cleanup: PASS
orphan Deployment: Deployment + ReplicaSet removed; Pod unchanged; PID 1 alive
orphan CronJob: CronJob + scheduled Job removed; Pod unchanged; PID 1 alive
kill Deployment: Deployment + ReplicaSet + Pod deleted
kill CronJob: CronJob + scheduled Job + Pod deleted
kill StatefulSet: StatefulSet + Pod deleted
storage: PVC/PV UIDs unchanged, Bound after kill; marker survived read-only remount
```

- The successful run used a disposable namespace, the rebuilt embedded binary, real reader/responder impersonation and namespace-scoped controller-delete permissions. CronJob children were created by the Kubernetes scheduler/controller rather than synthetic owner references.
- Both orphaned Pods had empty owner references and retained identical UIDs, Pod-spec hashes, container IDs and **0 restarts**. A further **65-second** observation crossed a CronJob scheduling boundary; neither controller chain returned, both Pods remained Running, and `kill -0 1` confirmed their original container processes were alive. This demonstrates the investigation benefit of removing controller-driven replacement, while the UI continues to explain the loss of self-healing and the possibility of external reconciliation.
- Foreground kill-switch garbage collection removed the listed Deployment/ReplicaSet/Pod and CronJob/Job/Pod chains and the StatefulSet/Pod. The same checks confirmed no Deployment, ReplicaSet, CronJob, Job or StatefulSet remained in the disposable namespace after the observation window.
- The StatefulSet explicitly used `persistentVolumeClaimRetentionPolicy: {whenDeleted: Retain, whenScaled: Retain}`. Its 16 MiB `local-path` PVC and backing PV retained their original UIDs and stayed Bound after deletion. A separate recovery Pod mounted the retained claim read-only and read the original marker, proving data survival rather than only object survival.
- After these assertions, test cleanup removed the orphaned/recovery Pods, disposable namespace/PVC, temporary responder identity and permissions, and waited for the generated Delete-reclaim PV to disappear. Follow-up queries found no test namespace/RBAC/ServiceAccount or generated PV, no Peeker/proxy processes, and no listener on port 60424. The earlier failed run also cleaned up its generated volume. No existing workload or storage object was deleted.
- Coverage is the tested Deployment and CronJob orphan chains, Deployment/CronJob/StatefulSet kill paths, and explicit Retain policy on this local-path provisioner. Other retention policies, operators/GitOps reconciliation and storage provisioners still follow their own Kubernetes behavior; Peeker issues no PVC/PV deletion requests.

Temporary verification services and their child proxies were stopped, and the verification browser tab was closed.

Final generated asset SHA-256 values:

```text
f5b24082bac78602f9b578666813ac746f06a2e0f96e4364c27b576486634d0d  web/dist/index.html
e62a6c6407b06ec8a5cc72a469ded9af673183f584c6be9f63ed6e3d8f0ab1c5  web/dist/assets/index-CrGwXJhQ.js
e66bbba5038c9486d52c98c4559f85ca41a562d89685473b7e813326af398d0e  web/dist/assets/index-DDcKAgJo.css
```

### Publication privacy review

- Reviewed all **109 publishable files** (all text) and **150 historical Git blobs** before the release commit. Filename/content checks found no sensitive files, real credentials, personal email addresses or actual workstation paths. Commit/tag identities use a public bot handle and GitHub noreply addresses; commit messages and tag annotations were also checked.
- Removed disposable namespace and Pod/PVC/PV identifiers from this record. Remaining credential/path-shaped matches are intentionally synthetic rejection-test fixtures; private IP ranges are documented configuration or test data.
- Semgrep `p/secrets` and `p/security-audit` ran 175 applicable rules across 80 files with **zero findings**. Ripwire's injection/exfiltration scan of the embedded agent skill also returned **zero findings**. Generated-asset publication checks passed.
- The final staged index contained the same 109 reviewed files; a source archive matched their contents exactly. The release notes were checked separately. Whitespace checks passed for source/docs; Vite's generated JavaScript retains five whitespace-only lines in its generated output.
- Local fixtures, toolchains, dependencies, caches, environment files and binaries are excluded by `.gitignore`. These are publication-focused checks, not a full security audit or a guarantee that automated scanners detect every possible secret.

## v0.0.2 release verification

```text
bash scripts/build.sh: passed; frozen lockfile, TypeScript, 918 Vite modules, React SSG, embedded Go build
bun test web/tests: 9 passed, 42 assertions
python3 -m unittest discover -s scripts -p 'test_*.py': 4 passed
go test -race ./...: passed across all packages
go vet ./...: passed
go mod verify: all modules verified
go tool deadcode ./...: no unreachable functions
go tool govulncheck ./...: no vulnerabilities found
bun audit --cwd web: no vulnerabilities found across 88 packages
go tool fieldalignment ./...: 17 advisory layout suggestions, exit 3
git diff --check: passed
```

### Inventory, MCP and Permissions

- Backend regressions cover namespace-first requests, explicit all-namespace scope, pending/cancelled assessments, stable risk/review/name ordering across pages, complete filtered summaries, hiding, refresh isolation, cache deduplication/expiry, snapshot expiry/eviction/capacity, wrong-scope rejection and closed-context admission. Removed obsolete frontend sorting and moved its ordering checks to the production backend paging path.
- Chrome exercised a 130-pod fixture: the default namespace was selected, backend pages held 100 rows, and the virtual viewport rendered at most 14 rows. Hiding one owning ReplicaSet removed 13 pods across pages and changed totals from 130 to 117 and critical findings from 1 to 0. Next-page navigation showed rows 101–117 and reset scrolling.
- Namespace switching selected the fixture's three `team-a` pods. Name filtering produced both an explicit empty result and a single matching row. A browser-injected namespace-discovery denial exercised manual scope entry; clearing the field made no cluster-wide request. All namespaces required explicit selection. A deliberately invalid snapshot produced the real backend HTTP 410; Refresh restarted successfully with a new snapshot.
- Pod detail navigation and the Permissions tab showed `ServiceAccount default/app`, a cross-namespace `RoleBinding team-a/read-settings`, its `Role reader`, namespace scope, `get,list`, and the named ConfigMap restriction `settings`, with expandable evidence. Backend regressions also cover benign and non-resource URL grants, denied inventories, default ServiceAccount fallback and output-field allowlisting.
- Official MCP SDK subprocess tests initialized stdio, listed the four read-only tools, read status, exited cleanly on EOF and verified managed-proxy cleanup. HTTP MCP tests still pass. Stdio starts no browser listener and uses the current kubeconfig context when neither a context nor an external proxy is specified.
- The embedded skill documents both transports, snapshot traversal, severity bands, distinct-finding aggregation, pending/partial results, supported checks, configured RBAC grants and assessment limitations. Existing installed skill files are preserved by the installer; upgrading an old copy requires manual review/replacement.

### Publication review and limitations

- Semgrep `p/security-audit` and `p/secrets` ran 175 applicable rules over 69 source/configuration files with zero findings or errors; normal test, dependency and generated-file exclusions applied. The full publishable-file credential/path review additionally included tests and generated assets. Its only matches were deliberately fictitious rejection-test values and their historical documentation.
- The generated-asset checker accepted exactly the three linked static files below. No credentials, actual workstation paths, cluster snapshots, source maps or development entry points were detected. Temporary fixtures, binaries, dependencies, toolchains and scan results are ignored. Commits use the existing public bot noreply identity.
- Ripwire contract checks found no incompatible callers for the checked backend/UI entry points. Its test map named 18 Go test files, all covered by the full race run, and seven frontend symbols without indexed automated reach; changed UI interactions were checked in Chrome. These structural results are not an automated end-to-end browser test suite.
- Quality-delta against `75c3da32d` reported four gating structural notices: three short-horizon changes in `Client.snapshot`, `Handler` and CLI `run`, plus similarity between the two small typed RBAC/peer memoizers. These are reviewed trade-offs for the requested cache/transport changes; the memoizers remain separate rather than introducing a shared abstraction for two uses. Non-gating results include new-function complexity, minor existing-function growth and Go test entry points misidentified as dead code. This is not a clean quality-gate claim.
- Field-layout suggestions remain advisory. Vite reports a nonfatal JavaScript chunk-size warning (approximately 525 kB before compression). No benchmark was run, and collection/job limits are not measured cluster-capacity claims.
- This release received focused tests, scans and fixture browser verification, not a new comprehensive independent security audit or live-cluster retest. RBAC permissions describe configured grants; other authorizers, admission and credential usability remain outside the assessment.
- Chrome reported no application exceptions or hydration warnings; the final deliberate snapshot-rejection check produced the expected HTTP 410 console entry. Temporary fixture processes and the verification browser page were stopped afterward.

Generated asset SHA-256 values:

```text
b96b631eab2a453fc89945030e954da415835d668032cf8c7d604b71a966c785  web/dist/assets/index-CT3vrKDC.js
e66bbba5038c9486d52c98c4559f85ca41a562d89685473b7e813326af398d0e  web/dist/assets/index-DDcKAgJo.css
285f2987a4f402cfb611e43fb8f379e583ca78f7628e1e0adb8834bcaf616dc0  web/dist/index.html
```

## v0.0.1 release verification

```text
bash scripts/build.sh: passed; frozen lockfile, TypeScript, 915 Vite modules, React SSG, embedded Go build
bun test web/tests: 8 passed, 27 assertions
python3 -m unittest discover -s scripts -p 'test_*.py': 4 passed
go test -race ./...: passed across CLI, skill installer, explorer and embedded-web packages
go vet ./...: passed
go mod verify: all modules verified
bash -n scripts/{build,setup,proxy,bootstrap,verify-cluster}.sh: passed
git diff --check: passed
```

### Contexts, hiding and policy findings

- Managed startup with `-context rancher-desktop` returned 24 pods and 17/17 readable inventory collections. Istio and Cilium detection badges appeared beside Read only.
- Chrome verified hiding a Deployment, 23 visible rows after reload, Show hidden restoring 24 rows, and unchecking Hide removing the saved preference. Unit fixtures verify replacement-pod stability, context separation and exact-instance fallback for unresolved ownership.
- Reconnect through Vite's same-origin proxy succeeded. Its generation changed, old-generation inventory returned HTTP 409, and another tab reset its active traffic view to refreshed security findings. Fixture tests cover cross-context isolation, startup/shutdown, cancellation and failed discovery without contacting other live contexts.
- Bookinfo displayed medium ingress/egress baseline findings. The isolated demo satisfied its network baseline and displayed the expected missing-Istio finding. Live MCP inventory and detail risk values matched.
- Cilium regression cases cover namespaced/clusterwide policies, explicit and implicit default-deny, disabled directions, broad world/all/CIDRSet rules, empty ports, union semantics, deny precedence, unavailable inventories, authoritative namespace/service-account identity aliases and unavailable namespace labels. Istio tests cover regular/native sidecars and disabled expectations.
- Production Chrome reported no console errors or hydration warnings. Vite's only observed error was the deliberately stale request's HTTP 409.

### MCP and skill installation

- The official SDK client successfully initialized and exercised the four read-only tools. Tests verified stale generations, bounded pagination, invalid identifiers, cross-origin/Host rejection and oversized requests.
- Final review corrections added regression coverage for Kubernetes protocol-only/full-range broad allowances and MCP batch/subscription rejection, disabled notification capabilities, outer request deadlines, cancellation/capacity and enforced no-store headers. Legacy SDK-client interoperability still passed.
- A live MCP session returned the expected context, both registered networking APIs, 24 risk-ranked pods and evidence-backed demo details. No context-switch or mutation tool was advertised.
- Project and global skill installation passed with temporary project/home directories. Existing skills were preserved; an escaping symlink could not write outside the selected root.
- A fresh consumer module/cache installed the 84-file publication bundle through a local file-backed module proxy using `go get -tool ...@latest`. `go tool peeker` served embedded HTML, hashed assets, direct pod links and 24 live risk summaries, initialized MCP as version 0.0.1, and installed the project skill. Only the unpublished local module bypassed checksum-database lookup; public dependencies used the public proxy and checksum database.

### Publication checks

- All 84 publishable files, including tests and generated assets, were scanned with Semgrep (`p/security-audit`, `p/golang`, `p/javascript`, `p/secrets`; metrics disabled): 264 applicable rules, zero findings or errors. Earlier generated-JavaScript timeouts were resolved using a 60-second limit. The final exact-method/no-store corrections and their tests were rescanned separately: 91 applicable rules, zero findings or errors.
- The generated-asset checker accepted exactly three files. The full publication-set credential/path check found only the intentionally fictitious workstation path in the rejection test and its verification description. Local caches, toolchains, screenshots, scan output, binaries, dependencies and environment files are ignored.
- Publication-history review removed local workload identities and addresses from older documentation before the first push. Commit identities use the authenticated GitHub bot's noreply address. The verified implementation manifest is `49c4f43907aa44c5eed7e7e50135707c18bccf3d3cb521ea55dc2bc4270e501c` (SHA-256 over sorted publishable paths and bytes, separated by NULs, excluding Markdown and `web/dist`).
- `bun audit --json` returned no advisories. OSV checks covered the complete Go module graph plus Go 1.27.3 stdlib/toolchain. They identified Windows-only `GO-2026-5024` in transitive `golang.org/x/sys`; it was upgraded from v0.41.0 to the fixed v0.44.0. The fixed-version query returned no advisories, and race tests, vet, module verification, binary build and isolated installation passed afterward.
- Ripwire contract checks found no incompatible backend callers; quality-delta reported zero gating regressions. Non-gating notices include complexity in new policy/RBAC helpers, context/traffic handling and test functions, plus minor existing graph/evaluator growth. These checks are structural and do not prove security.

The broader source audit remains **incomplete**, with no confirmed security findings. Its protocol-only-port candidate and MCP contract caveats prompted the corrections above. A fresh focused source reviewer validated the production corrections after finding an additional JSON method-casing mismatch, which was fixed and regression-tested. Actual SDK cancellation tests passed for legacy and current protocols, including server-handler completion. Full independent multi-pass coverage, independent generated-asset reproduction and deployment enforcement validation were unavailable; this release does not claim exhaustive security certification or proven CNI/mesh/Kiali enforcement.

Generated asset SHA-256 values:

```text
b92116af9a1e1bb46d4240e490a8f0024de7a095d698f8ba8058bac693cdc89f  web/dist/assets/index-e4hjW6Vs.js
f30692b7ff11983e0964188f15b4c8a18da5b14597d38778aca20b4378274830  web/dist/assets/index-tP6nTYID.css
f02a9644f86385b7410512f124767b7abb985397a2ce5837869d54b9f6f58c8b  web/dist/index.html
```

The sections below are historical verification checkpoints. Their file/test counts, scores, process modes and publication status describe those earlier builds.

## Live traffic and publication follow-up

```text
bash scripts/build.sh: passed, 912 Vite modules, 3 publishable embedded assets
bun test web/tests: 5 passed
python3 -m unittest discover -s scripts -p 'test_*.py': 4 passed
go test -race -v ./...: 32 top-level tests passed
go vet ./...: passed
bash -n scripts/{build,setup,proxy,bootstrap,verify-cluster}.sh: passed
Semgrep source/tests: 264 applicable rules, 57 files, 0 findings, 0 parse errors
Semgrep generated assets: 41 applicable rules, all 3 files, 0 findings
bun audit --json: {} (no known dependency advisories)
OSV Go stdlib/toolchain 1.27.3 query: no known advisories returned
```

Semgrep used `p/security-audit`, `p/golang`, `p/javascript` and `p/secrets` with metrics disabled. The final pass bypassed Semgrep's default test exclusions and covered all 57 publishable non-dist files. The separate generated-asset pass explicitly included all three assets and bypassed Semgrep's dist exclusions. Advisory databases and pattern scans are time-bound checks, not proof that unknown vulnerabilities do not exist.

### Observed traffic

- Added the JSON access-log provider to the existing Istio mesh ConfigMap with a resource-version guard, preserving other settings. Applied namespace-scoped Bookinfo Telemetry and read-only `pods/log` RBAC. No workloads, storage or cluster components were reinstalled or deleted.
- Confirmed the sidecar emits only the configured timestamp, protocol, address, cluster, status/flags and duration fields. Paths, request headers, bodies and query strings are omitted by this provider.
- Six successful Bookinfo productpage requests yielded 18 observations on the productpage sidecar: six inbound requests and twelve outbound requests. Five directed relationships resolved to the ingress gateway, details and all three reviews versions; no errors were observed.
- The non-Istio pod endpoint returned `absent` and the explicit “istio-proxy isn't there” message.
- Chrome verified the initial listening/idle message, live graph/count updates, edge evidence, Pause, and the absent-sidecar page. A browser session remained live beyond the server's ordinary 60-second write timeout. No console errors or warnings appeared.
- Focused tests cover parser rejection/redaction, IPv6 and shared/unknown peer attribution, edge/line limits, regular/native sidecars, waiting/deleted/replaced/denied states, final aggregates, four-stream capacity and upstream cancellation. Frontend tests exercise split UTF-8/multiple events, JSON denial and bounded/canceled reads.
- Traffic is limited to completed HTTP inbound/outbound records on the selected sidecar. The UI documents unknown peers, session resets, omitted records and the lack of mesh-wide downstream visibility. Peeker stores aggregates only in memory; Kubernetes retains its own ordinary container logs.

### Installable publication bundle

The local file-backed module-proxy installation was repeated with 60 publishable files and a fresh consumer module/cache. The exact `go get -tool github.com/clavinjune/peeker/cmd/peeker@latest` command succeeded; `go tool peeker` served embedded HTML, hashed assets, deep links and 24 live risk summaries without a frontend build. The temporary tool process was stopped. The normal loopback service on port 8080 uses the rebuilt binary.

Publication checks accepted exactly three generated assets. An additional publishable-file path/credential check found only a deliberately fake home-directory rejection-test string; no actual workstation paths or credentials were found. Ripwire contract checks found no incompatible callers and quality-delta reported zero gating regressions. Non-gating notices include new helper/test complexity and a minor increase in the shared graph's display branches.

## Risk scoring and module publication follow-up

```text
bash scripts/build.sh: passed
  frozen frontend lockfile: unchanged
  TypeScript, Vite (910 modules), React prerender, embedded Go build: passed
  publication check: 3 generated files accepted
bun test web/tests: 2 tests passed
python3 -m unittest discover -s scripts -p 'test_*.py': 4 tests passed
go test -race ./...: passed (26 tests)
go vet ./...: passed
Semgrep: 304 rules, 43 scanned files, 0 findings
```

The security tests cover inheritance and overrides, unknown image/node defaults, regular/init/ephemeral containers, deduplication, token mounting precedence, Windows coverage, host mounts, RBAC namespace/cluster scope, group subjects, resource-name restrictions, delegation/subresource writes, denied/missing roles and namespace-filtered inventory reads.

### Live risk API and compact UI

- Applied the expanded get/list-only reader manifest. All 14 inventory collections and 27 detail collections were readable. Secret reads through the impersonated proxy still returned HTTP 403.
- The inventory returned 24 pods, sorted by descending score: 4 critical, 13 high, 4 low and 3 with no findings. Fifteen assessments had unknown checks. These are configuration classifications, including completed pods, not measured compromise or runtime exposure.
- The top three inventory scores exactly matched their detail reports. Every reported finding had remediation and resource/field evidence.
- Chrome verified highest-risk, coverage-gap and alphabetical ordering, pod-name filtering, direct pod URLs, collapsed findings and expandable recommendations/evidence. A fresh productpage detail opened with metadata, findings, coverage gaps and scoring explanations collapsed. No React errors or hydration warnings appeared; the existing unconfigured favicon request still returned 404. Production and Vite development both loaded 24 pods after the backend restart.
- A controlled loopback fixture denied the five ServiceAccount/RBAC collections while forwarding other GETs to the real read-only proxy. All 24 pods remained visible with partial coverage; the three zero-finding pods became **Unrated**, not secure. The UI displayed **9/14 readable** and detail reports retained denied-read evidence. The fixture and temporary verification servers were stopped afterward.

### Local module installation

A file-backed Go module proxy served a local `v0.0.0` archive of 53 publishable repository files, including all three `web/dist` files. A fresh consumer module and isolated module cache ran the exact command:

```sh
go get -tool github.com/clavinjune/peeker/cmd/peeker@latest
go tool peeker
```

The consumer's `go.mod` contained the tool directive and module requirement. The tool started on a temporary loopback port and served prerendered HTML, both immutable hashed assets, a direct pod URL fallback and 24 live pods with risk summaries. No frontend build, repository checkout or external runtime assets were needed by the consumer. Checksum-database access was disabled only for this unpublished local-proxy test.

The generated shell contains no workload snapshot. Publication checks reject unexpected artifacts, symlinks, selected credential patterns, workstation paths, source maps and development entry points. Semgrep covered Go/TypeScript/Python and secret patterns; its default test/vendor exclusions apply, and generated assets were checked separately. Local screenshots, scan reports, fixtures, toolchains and binaries are ignored. Public verification text omits unrelated workload identities and addresses.

Ripwire reported no incompatible callers for the changed backend contracts and zero gating regressions against `505ad86`. Non-gating findings were complexity in the new RBAC resolver/publication validator, test functions not recognized as entry points, and a short repeated assertion pattern in two distinct publication tests. The validation logic was retained together for readability; all test entry points executed successfully.

No remote push or module publication was performed. Public `@latest` requires publishing a commit/version containing the generated assets. The normal loopback service uses the verified embedded binary on port 8080.

## Embedded SSG frontend follow-up

The frontend now prerenders its application shell at build time and embeds the generated HTML, JavaScript and CSS in the Go executable. Cluster data still loads through the live API after hydration. No dependencies were added.

```text
bash scripts/build.sh: passed
  frozen lockfile install: no changes
  tsc --noEmit: passed
  Vite build: 908 modules
  React prerender: dist/index.html, 11,038 bytes
  embedded Go binary: bin/peeker
go test -race -v ./...: 17 tests passed
go vet ./...: passed
bash -n scripts/build.sh: passed
```

The binary was copied to a temporary directory containing only `peeker`, then started from that directory on `127.0.0.1:8082`. It served the application successfully without source files or a `web/dist` directory at runtime.

- The raw HTTP response contained the inventory heading, filters and loading UI before JavaScript executed.
- Both embedded hashed assets returned HTTP 200 with JavaScript/CSS content types and immutable caching. HTML used `Cache-Control: no-cache`.
- `/assets/`, `/assets/%2e%2e/index.html`, `/src/App.tsx` and `/api/proxy` returned 404; `POST /` returned 405.
- Chrome hydrated the page and loaded **24 live pods**. Details navigation, direct productpage URL reload, the topology tab, browser Back and empty-result filtering worked.
- No React hydration errors or warnings appeared. The existing unconfigured favicon request returned 404.
- Vite development still loaded 24 pods after the shared-component extraction.
- The embedded-frontend regression test checks actual generated HTML, its linked assets and the deep-link fallback. The HTTP boundary test now uses an in-memory filesystem and also rejects asset traversal and directory listings.
- Ripwire quality-delta against commit `505ad86` reported zero gating regressions and one non-gating new-test dead-code finding; Go executed that test successfully. Its App edit-check arity warning concerned JSX call sites; TypeScript and browser hydration passed.

The normal Peeker process was restarted with the embedded binary on port 8080; its HTTP response contained the 11,038-byte prerendered page and its API returned 24 pods. The temporary port-8082 verification process was stopped afterward.

The following sections record the original cluster/application verification before this packaging change.

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
