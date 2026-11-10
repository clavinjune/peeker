Build and verify a working local Kubernetes security explorer in this repository, including the Rancher Desktop cluster setup and a simple read-only web application.

## Stack and scope

Use:
- Kubernetes context: rancher-desktop
- Cilium for Kubernetes networking and network policies
- Istio in sidecar mode
- Istio Bookinfo as the example microservices application
- Kiali
- Go 1.27.3
- Node.js v26.13.0
- Bun for frontend package management and scripts
- React, TypeScript, tsc, and Mantine UI from mantine.dev

Keep the implementation straightforward and small. Follow existing repository conventions. Do not add comments to source code; put explanations in the README.

Inspect the repository, local tools, and cluster before making changes. Verify that the requested toolchain versions exist and are available. Do not silently substitute versions. If an exact version is unavailable, report the evidence and the specific decision needed.

Proceed through implementation and verification rather than stopping at a plan. If blocked by credentials, unavailable software, or a required manual Rancher Desktop setting, explain the exact blocker.

## 1. Prepare the cluster

Explicitly target rancher-desktop for all cluster operations, including Helm and kubectl proxy. Verify the context and cluster connectivity.

Inspect the current CNI, Kubernetes version, installed components, and available resources. Use compatible, pinned component versions and official installation guidance.

Install and verify:
1. Cilium
2. Istio using sidecar injection, not ambient mode
3. Bookinfo in a dedicated namespace with injected sidecars
4. Kiali

Handle Rancher Desktop’s existing networking configuration correctly. Do not install conflicting CNIs or reset the cluster. If replacing its default CNI requires a manual setting, provide the precise instructions.

Configure Cilium and Istio for supported coexistence.

Do not install Prometheus, Grafana, or tracing backends. Do not enable charts or add-ons that implicitly install them.

For Kiali, “Istio only” means Kubernetes/Istio configuration visibility with metrics and tracing integrations disabled. Verify the selected Kiali version’s supported configuration for operation without Prometheus.

Kiali’s telemetry-based features may be unavailable without Prometheus. Make that limitation explicit; do not claim Istio configuration alone supplies traffic metrics.

Provide localhost access to Bookinfo and Kiali through documented port-forward commands or another simple local mechanism.

Store reproducible installation configuration and commands in the repository. Make rerunning setup safe where practical.

## 2. Read-only Go application

Create a Go backend and a Mantine React/TypeScript frontend.

The backend must access the Kubernetes API through kubectl proxy, explicitly connected to rancher-desktop. Use a configurable local proxy URL, defaulting to http://127.0.0.1:8001.

The browser communicates with the Go backend, not directly with Kubernetes.

Keep the application read-only:
- Only allow explicitly supported Kubernetes resource reads.
- Do not expose create, update, patch, delete, exec, attach, or arbitrary proxy operations.
- Do not implement an unrestricted Kubernetes API passthrough.
- Validate namespace and resource identifiers.
- Keep credentials out of frontend code and responses.
- Bind local services to loopback by default.
- Document a least-privilege read-only identity for kubectl proxy; the proxy itself does not make administrative credentials read-only.

Cluster installation is allowed to create resources. The running explorer must not modify the cluster.

Handle missing CRDs, denied permissions, disconnected proxies, loading states, and empty results clearly. An inaccessible resource must not be presented as an absent resource.

Use a simple architecture and avoid unnecessary abstractions or additional services.

## 3. Pod list page

The first page must display actual cluster pods in a table.

Required columns:
- Namespace
- Pod name
- Controller name and kind
- Details button

Provide:
- Namespace dropdown with an “All namespaces” option
- Pod-name filtering
- Refresh action
- Clear loading, empty, and error states

Resolve controller ownership using ownerReferences:
- Pod → ReplicaSet → Deployment
- Pod → Job → CronJob
- Direct StatefulSet, DaemonSet, Job, or other controlling owner

Use the controlling owner reference rather than guessing from names. Show standalone pods and unresolved ownership accurately.

## 4. Pod details and network-policy analysis

The Details button opens a dedicated page for the selected pod.

Show basic identity:
- Namespace and name
- Labels
- Node
- Phase and container readiness
- Controller ownership chain
- Pod IP
- Istio sidecar presence

Focus the page on CKS-style network-security questions.

Identify policies selecting the pod:
- Kubernetes NetworkPolicy
- CiliumNetworkPolicy, when available
- CiliumClusterwideNetworkPolicy, when available

For Kubernetes NetworkPolicy, correctly handle:
- Pod and namespace selectors, including match expressions
- policyTypes and defaulting
- Ingress and egress isolation separately
- Additive allow rules across selecting policies
- Combined namespaceSelector and podSelector semantics
- IP blocks and exceptions
- Ports and protocols
- Empty selectors and empty rule lists

Distinguish:
- Not isolated by Kubernetes NetworkPolicy
- Isolated with allowed peers
- Isolated with no allowed traffic in that direction
- Unknown or partially evaluated

“No selecting NetworkPolicy” must not be labeled as proven internet reachability or proof that no other enforcement exists.

Inspect relevant Cilium rules and display their selectors, peers, entities, ports, allow/deny rules, and L7 restrictions where present. Respect Cilium deny precedence when evaluating supported rules. Clearly identify unsupported constructs and avoid claiming a complete effective-policy verdict from partial evaluation.

Show which policy and rule supports each conclusion. Explain that static configuration analysis does not prove packet delivery.

## 5. Security graph

Render a simple interactive node graph centered on the selected pod.

Examples, only when supported by configuration:
- Allowed namespace or workload → selected pod
- Selected pod → allowed destination
- Selected pod → egress isolated, no allowed destinations

Use clear visual distinctions for:
- Allowed traffic
- Denied traffic
- Unrestricted-by-policy directions
- Unknown or partially evaluated relationships

Include relevant peers, CIDRs, namespaces, services, and ports without making the graph unnecessarily busy.

Clicking a graph node or edge should reveal the associated resources and policy evidence.

Avoid misleading “world → pod” edges when the evidence only establishes lack of NetworkPolicy isolation.

## 6. Routing and exposure relationships

Determine whether the pod is connected to:
- Ingress
- Istio VirtualService and Gateway
- Gateway API HTTPRoute and TCPRoute

Discover whether the relevant APIs are installed. Missing APIs are normal and should not break the page.

Resolve relationships through actual backend references and services:
- Route or ingress → backend Service → selected pod
- Use Service selectors and EndpointSlices where relevant
- Account for namespaces, ports, Istio destination subsets, and cross-namespace reference permissions
- Inspect route attachment/status where available

Distinguish a configured reference from an accepted route and from verified external reachability.

Display matching resources and the relationship chain. Do not infer relationships solely from similar resource names.

## 7. Kiali-style topology

Provide a lightweight topology view showing discovered relationships among workloads, services, routes, and the selected pod, using Kubernetes, Istio, and Cilium configuration.

Label this view “configuration-derived topology.”

Do not fabricate requests per second, latency, error rates, or observed traffic edges.

Without Prometheus, do not promise Kiali’s usual metrics-backed traffic graph.

If existing Cilium/Hubble observations can be integrated simply without Prometheus, they may enrich the graph. Keep them optional, distinctly labeled as observed traffic, and separate from inferred configuration. Do not expand the project into a telemetry platform.

Provide a convenient link to the local Kiali UI.

## 8. Local workflow and documentation

Provide concise commands or scripts for:
- Cluster setup and verification
- Starting kubectl proxy against rancher-desktop
- Running the Go backend
- Installing and running the frontend with Bun
- Type-checking with tsc
- Building the application
- Accessing Bookinfo and Kiali
- Cleaning up only resources installed for this project

Pin dependencies and commit the frontend lockfile.

Document:
- Component and toolchain versions
- Local URLs and ports
- Required Kubernetes read permissions
- Architecture and request flow
- Network-policy interpretation limits
- Kiali behavior without Prometheus
- Configuration-derived versus observed topology

Add a small, isolated demo policy setup with commands to apply and remove it, so the UI can demonstrate policy selection and ingress/egress restrictions. Keep it separate from normal Bookinfo operation.

## 9. Verification and completion

Verify the live setup and application, not just compilation.

Show evidence that:
- The target context is rancher-desktop
- Cilium and Istio are healthy
- Bookinfo workloads are ready and have Istio sidecars
- Bookinfo responds successfully
- Kiali is reachable with Prometheus integration disabled
- This setup did not install Prometheus
- The application lists real pods and filters by namespace
- Controller ownership resolves correctly
- Pod details show actual policies and route relationships
- Graph edges are backed by resource evidence
- Missing APIs and proxy failures produce useful UI states
- The application has no cluster mutation endpoints

Run Go tests, frontend type-checking, and production builds. Add focused tests for meaningful policy-evaluation and ownership-resolution edge cases, particularly additive policies, selector semantics, direction-specific isolation, and unknown results.

Exercise the UI in a browser if browser tooling is available.

Finish with a concise summary containing:
- What was installed and implemented
- Files and entry points
- Exact startup commands and URLs
- Actual verification output
- Any remaining blockers or explicitly unsupported cases

Do not mark the task complete based only on generated files or unverified claims.