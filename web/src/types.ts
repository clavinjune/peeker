export type Resource = { kind: string; namespace?: string; name: string; uid?: string; apiVersion?: string };
export type Evidence = { resource: Resource; field: string; description: string };
export type State = { resource: string; status: string; message?: string };
export type Pod = Resource & {
  labels: Record<string, string> | null; node: string; phase: string; ip: string;
  sidecar: boolean; ready: number; containers: number;
  ownership: { owners: Resource[]; status: string; message?: string };
};
export type GraphNode = { id: string; label: string; kind: string; resource?: Resource };
export type GraphEdge = { id: string; from: string; to: string; status: string; label: string; evidence: Evidence[] | null };
export type GraphData = { nodes: GraphNode[]; edges: GraphEdge[] };
export type Direction = { status: string; summary: string; evidence: Evidence[] };
export type Policy = {
  resource: Resource; selection: string; selector: unknown; notes: string[];
  rules: { field: string; action: string; peers: unknown; ports: unknown; restrictions?: Record<string, unknown> }[];
};
export type PodList = { pods: Pod[]; namespaces: string[]; states: State[] };
export type Detail = {
  pod: Pod; capturedAt: string; states: State[];
  policies: { ingress: Direction; egress: Direction; policies: Policy[]; graph: GraphData };
  routing: { relationships: { route: Resource; service: Resource; status: string; description: string; evidence: Evidence[] }[]; graph: GraphData };
};
export const resourceName = (r: Resource) => `${r.kind} ${r.namespace ? `${r.namespace}/` : ''}${r.name}${r.apiVersion?.includes('/') ? ` (${r.apiVersion})` : ''}`;
