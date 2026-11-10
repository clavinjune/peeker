export type Resource = { kind: string; namespace?: string; name: string; uid?: string; apiVersion?: string };
export type Evidence = { resource: Resource; field: string; description: string };
export type State = { resource: string; status: string; message?: string };
export type ContextInfo = { mode: 'managed' | 'external'; contexts: string[]; current: string; generation: string; status: string; message?: string };
export type Capabilities = { istio: string; cilium: string; message?: string };
export type Risk = { score: number; level: string; findings: number; checked: number; unknown: number; topFinding: string };
export type Finding = { id: string; title: string; severity: string; summary: string; remediation: string; evidence: Evidence[] };
export type SecurityReport = { risk: Risk; serviceAccount: string; findings: Finding[]; gaps: { id: string; evidence: Evidence[] }[] };
export type Pod = Resource & {
  labels: Record<string, string> | null; node: string; phase: string; ip: string;
  sidecar: boolean; ready: number; containers: number;
  risk: Risk;
  ownership: { owners: Resource[]; status: string; message?: string };
};
export type GraphNode = { id: string; label: string; kind: string; resource?: Resource };
export type GraphEdge = { id: string; from: string; to: string; status: string; label: string; evidence: Evidence[] | null };
export type GraphData = { nodes: GraphNode[]; edges: GraphEdge[] };
export type TrafficView = { status: string; message: string; startedAt: string; requests: number; errors: number; ignored: number; dropped: number; graph: GraphData };
export type Direction = { status: string; summary: string; evidence: Evidence[] };
export type Policy = {
  resource: Resource; selection: string; selector: unknown; notes: string[];
  rules: { field: string; action: string; peers: unknown; ports: unknown; restrictions?: Record<string, unknown> }[];
};
export type InventorySummary = { total: number; critical: number; high: number; review: number; pending: number };
export type PermissionsReport = { serviceAccount: Resource; identity: string; status: string; grants: { binding: Resource; role: Resource; scope: string; rule: { apiGroups: string[]; resources: string[]; verbs: string[]; resourceNames: string[]; nonResourceURLs: string[] }; evidence: Evidence[] }[]; gaps: Evidence[] };
export type PodList = { pods: Pod[]; states: State[]; snapshot: string; status: 'loading' | 'assessing' | 'complete' | 'error'; message?: string; capturedAt: string; expiresAt: string; summary: InventorySummary; total: number; hidden: number; offset: number; nextOffset: number; hasMore: boolean };
export type Detail = {
  pod: Pod; capturedAt: string; states: State[]; security: SecurityReport; permissions: PermissionsReport;
  policies: { ingress: Direction; egress: Direction; policies: Policy[]; graph: GraphData };
  routing: { relationships: { route: Resource; service: Resource; status: string; description: string; evidence: Evidence[] }[]; graph: GraphData };
};
export const resourceName = (r: Resource) => `${r.kind} ${r.namespace ? `${r.namespace}/` : ''}${r.name}${r.apiVersion?.includes('/') ? ` (${r.apiVersion})` : ''}`;
