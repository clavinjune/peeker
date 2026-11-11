import { useContext, useEffect, useState } from 'react';
import { Accordion, Alert, Badge, Button, Checkbox, Code, Group, Paper, Select, SimpleGrid, Stack, Table, Tabs, Text, TextInput, Title } from '@mantine/core';
import { ClusterContext, useAPI } from './Cluster';
import { Availability, RequestState } from './ClusterUI';
import { Permissions } from './Permissions';
import { RiskBadge, SecurityFindings } from './Security';
import { Traffic } from './Traffic';
import { EvidenceList, Graph } from './Graph';
import { resourceName } from './types';
import type { Detail, Resource, Risk, State } from './types';
import { imageScanFor, type ImageClassification } from './imageEvidence';

type Navigate = (path: string) => void;
type WorkloadRow = { resource: Resource; registered: boolean; registeredAt: string; pods: number; risk: Risk };
type RegistryList = { workloads: WorkloadRow[]; entries: (Resource & { registeredAt: string })[]; states: State[]; actionsAvailable: boolean; backups: { id: string; resource: Resource }[] };
type ContainerEvidence = { name: string; type: string; image: string; observedImage: string; digestPinned: boolean; distroless: string; settings: Record<string, unknown> };
type WorkloadEvidence = Omit<Detail, 'states' | 'capturedAt'> & { containers: ContainerEvidence[]; host: Record<string, unknown>; references: { kind: string; name: string; field: string }[]; services: { resource: Resource; type: string }[] };
type WorkloadDetail = { resource: Resource; registered: boolean; actionsAvailable: boolean; template: WorkloadEvidence; pods: WorkloadEvidence[]; podCount: number; podsTruncated: boolean; states: State[]; capturedAt: string; recommendations: string[]; scans: Scan[] };
type ActionResult = { status?: string; steps?: string[]; backup?: string; id?: string; error?: string };
type BOM = { components?: { name: string; version?: string; type: string; purl?: string; licenses?: unknown[] }[]; vulnerabilities?: { id: string; ratings?: { severity?: string; score?: number }[]; description?: string; recommendation?: string; affects?: { ref: string }[] }[] };
type Scan = { id: string; uid: string; image: string; status: string; message: string; startedAt: string; sbom?: BOM; classification?: ImageClassification };

export const workloadPath = (r: Resource) => `/registry/${[r.kind, r.namespace ?? '', r.name, r.uid ?? ''].map(encodeURIComponent).join('/')}`;
const identity = (r: Resource) => ({ kind: r.kind, namespace: r.namespace, name: r.name, uid: r.uid });

function useRegistryChange() {
  const cluster = useContext(ClusterContext);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ActionResult | null>(null);
  const change = async (operation: string, resource: Resource, image?: string) => {
    setBusy(true); setResult(null);
    try {
      const response = await fetch('/api/registry/change', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Peeker-Action': 'registry', 'X-Peeker-Context': cluster?.generation ?? '' }, body: JSON.stringify({ operation, ...identity(resource), image }) });
      const body = await response.json() as ActionResult;
      setResult(body);
      return response.ok ? body : null;
    } catch { setResult({ error: 'Request interrupted. Refresh workload state before retrying.' }); return null; }
    finally { setBusy(false); }
  };
  return { busy, result, change };
}

function ActionFeedback({ result }: { result: ActionResult | null }) {
  const cluster = useContext(ClusterContext);
  const [error, setError] = useState('');
  const download = async () => {
    try {
      const response = await fetch(`/api/registry/backup?id=${encodeURIComponent(result?.backup ?? '')}`, { headers: { 'X-Peeker-Context': cluster?.generation ?? '' } });
      if (!response.ok) throw new Error('Backup is no longer available in this context session');
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'peeker-rbac-backup.yaml'; anchor.click(); URL.revokeObjectURL(url);
    } catch (e) { setError(e instanceof Error ? e.message : 'Download failed'); }
  };
  return result && <Alert color={result.error || result.status === 'partial-or-failed' ? 'orange' : 'indigo'} title={result.error || result.status}>{result.steps?.map((step, i) => <Text size="sm" key={i}>{step}</Text>)}{result.backup && <Button mt="sm" variant="light" onClick={download}>Download RBAC backup YAML</Button>}{error && <Text c="red">{error}</Text>}</Alert>;
}

export function Registry({ navigate }: { navigate: Navigate }) {
  const [namespace, setNamespace] = useState('default');
  const [refresh, setRefresh] = useState(0);
  const [filter, setFilter] = useState('');
  const [onlyManaged, setOnlyManaged] = useState(false);
  const [hidden, setHidden] = useState(new Set<string>());
  const [page, setPage] = useState(0);
  useEffect(() => setPage(0), [namespace, filter, onlyManaged, hidden]);
  const namespaces = useAPI<{ namespaces: string[]; state: State }>('/api/namespaces', 0);
  const { data, loading, error } = useAPI<RegistryList>(`/api/registry?namespace=${encodeURIComponent(namespace)}`, refresh);
  const mutation = useRegistryChange();
  const rows = data?.workloads.filter(w => (!onlyManaged || w.registered) && !hidden.has(w.resource.uid ?? '') && `${w.resource.kind} ${w.resource.name}`.toLowerCase().includes(filter.toLowerCase())) ?? [];
  return <Stack gap="lg"><Group justify="space-between"><div><Text className="eyebrow">WORKLOAD SECURITY</Text><Title order={1}>Registry</Title><Text c="dimmed" size="sm">Own controller workloads in this context session. Registration stays in memory.</Text></div><Button variant="light" loading={loading} onClick={() => setRefresh(v => v + 1)}>Refresh</Button></Group>
    <Group align="end"><Select label="Namespace" searchable allowDeselect={false} data={namespaces.data?.namespaces ?? [namespace]} value={namespace} onChange={v => v && setNamespace(v)} /><TextInput label="Filter workloads" value={filter} onChange={e => setFilter(e.currentTarget.value)} placeholder="Name or controller kind" /><Checkbox label="Registered only" checked={onlyManaged} onChange={e => setOnlyManaged(e.currentTarget.checked)} />{hidden.size > 0 && <Button variant="subtle" onClick={() => setHidden(new Set())}>Show {hidden.size} hidden</Button>}</Group>
    {(namespaces.error || namespaces.data?.state.status !== 'available') && <TextInput label="Namespace (manual)" value={namespace} onChange={e => setNamespace(e.currentTarget.value)} />}
    <RequestState loading={loading} error={error} /><ActionFeedback result={mutation.result} />
    {data && <><Text size="xs" c="dimmed">Highest configuration risk first · worst template/live-Pod score · {rows.length} visible workloads</Text><Table.ScrollContainer minWidth={700}><Table verticalSpacing="sm"><Table.Thead><Table.Tr><Table.Th>Workload</Table.Th><Table.Th>Risk / Pods</Table.Th><Table.Th>Ownership</Table.Th><Table.Th>Actions</Table.Th></Table.Tr></Table.Thead><Table.Tbody>{rows.slice(page * 100, (page + 1) * 100).map(w => <Table.Tr key={w.resource.uid}><Table.Td><Text fw={600}>{w.resource.name}</Text><Text size="xs" c="dimmed">{w.resource.kind} · {w.resource.namespace}</Text></Table.Td><Table.Td><RiskBadge risk={w.risk} /><Text size="xs" c="dimmed">{w.pods} Pods</Text></Table.Td><Table.Td><Badge color={w.registered ? 'indigo' : 'gray'}>{w.registered ? 'Managed by Peeker' : 'Discovered'}</Badge></Table.Td><Table.Td><Group gap="xs"><Button size="xs" variant="subtle" onClick={() => navigate(workloadPath(w.resource))}>Details →</Button><Button size="xs" variant="light" disabled={mutation.busy} onClick={async () => { await mutation.change(w.registered ? 'unregister' : 'register', w.resource); setRefresh(v => v + 1); }}>{w.registered ? 'Unregister' : 'Register'}</Button><Button size="xs" variant="subtle" color="gray" onClick={() => setHidden(new Set([...hidden, w.resource.uid ?? '']))}>Hide</Button></Group></Table.Td></Table.Tr>)}</Table.Tbody></Table></Table.ScrollContainer>{rows.length > 100 && <Group><Button variant="subtle" disabled={page === 0} onClick={() => setPage(v => v - 1)}>Previous</Button><Text size="sm">Page {page + 1}</Text><Button variant="subtle" disabled={(page + 1) * 100 >= rows.length} onClick={() => setPage(v => v + 1)}>Next</Button></Group>}{rows.length === 0 && <Text c="dimmed">No matching workloads in the readable inventories.</Text>}
      {data.entries.filter(e => !data.workloads.some(w => w.resource.uid === e.uid)).map(e => <Alert key={e.uid} color="orange" title={`${e.kind} ${e.name} · missing or replaced`}>Registration is bound to UID {e.uid}.<Button size="xs" variant="subtle" disabled={mutation.busy} onClick={async () => { await mutation.change('unregister', e); setRefresh(v => v + 1); }}>Remove stale registration</Button></Alert>)}
      {data.backups.length > 0 && <details><summary>RBAC backups · {data.backups.length}</summary><Stack mt="sm">{data.backups.map(b => <ActionFeedback key={b.id} result={{ status: `Backup for ${resourceName(b.resource)} · ${b.id}`, backup: b.id }} />)}</Stack></details>}
      <details><summary>Discovery coverage</summary><Availability states={data.states} /></details></>}
  </Stack>;
}

function ImageEvidence({ scan }: { scan?: Scan }) {
  const evidence = scan?.classification;
  if (!evidence) return <Text size="sm" my="sm">Distroless: unassessed. Scan this image for package-inventory evidence.</Text>;
  return <Paper withBorder p="sm" my="sm"><Stack gap="xs">
    <Text fw={600}>Scan-time image classification · {evidence.status}</Text>
    <Text size="sm">{evidence.summary}</Text>
    <Text size="xs">{evidence.osPackages} OS packages · requested {evidence.platform} · scanned architecture {evidence.architecture || 'unknown'} · {scan.startedAt}</Text>
    <Code>{evidence.digest || 'Resolved digest unavailable'}</Code>
    {evidence.tools.map(tool => <Text size="sm" key={`${tool.name}/${tool.version}`}>{tool.name} {tool.version} · {tool.kind}</Text>)}
    <Text size="xs" c="dimmed">{evidence.limitations}</Text>
  </Stack></Paper>;
}

function EvidencePanels({ evidence, template, scan, scans, busy, registered }: { evidence: WorkloadEvidence; template: boolean; scan: (image: string) => void; scans: Scan[]; busy: boolean; registered: boolean }) {
  return <Tabs defaultValue="findings" keepMounted={false}><Tabs.List>{['findings', 'hardening', 'exposure', 'policies', 'permissions', 'references', 'traffic'].map(tab => <Tabs.Tab key={tab} value={tab}>{tab === 'findings' ? 'Recommendations & findings' : tab === 'traffic' ? 'Live traffic' : tab[0].toUpperCase() + tab.slice(1)}</Tabs.Tab>)}</Tabs.List>
    <Tabs.Panel value="findings" pt="md"><SecurityFindings report={evidence.security} /></Tabs.Panel>
    <Tabs.Panel value="hardening" pt="md"><Stack><Paper withBorder p="md"><Text fw={600}>Host namespaces / process sharing</Text><Code block>{JSON.stringify(evidence.host, null, 2)}</Code><Text size="xs" c="dimmed">null = not explicitly configured; runtime defaults and policy enforcement may differ.</Text></Paper>{evidence.containers.map(c => <Paper withBorder p="md" key={`${c.type}/${c.name}`}><Group justify="space-between"><Title order={4}>{c.name}</Title><Badge color={c.digestPinned ? 'teal' : 'orange'}>{c.digestPinned ? 'Digest pinned' : 'Mutable reference'}</Badge></Group><Text size="xs" c="dimmed">{c.type}</Text><Code>{c.image}</Code>{c.observedImage && <Text size="xs" mt="xs">Observed digest: {c.observedImage}</Text>}<ImageEvidence scan={imageScanFor(c.observedImage || c.image, scans)} /><Code block>{JSON.stringify(c.settings, null, 2)}</Code><Text size="xs" c="dimmed" my="sm">Read-only root filesystem does not make mounted volumes immutable. Unspecified root user requires image/runtime evidence.</Text><Button size="xs" variant="light" disabled={!registered || busy} onClick={() => scan(c.observedImage || c.image)}>Scan {c.observedImage ? 'observed digest' : 'image'} with Trivy → SBOM</Button></Paper>)}</Stack></Tabs.Panel>
    <Tabs.Panel value="permissions" pt="md"><Permissions report={evidence.permissions} /></Tabs.Panel>
    <Tabs.Panel value="references" pt="md"><Stack><Text size="sm" c="dimmed">Names and reference locations only. Secret and ConfigMap contents are not fetched.</Text>{evidence.references.map((r, i) => <Paper withBorder p="sm" key={i}><Text fw={500}>{r.kind} · {r.name}</Text><Text size="xs" c="dimmed">{r.field}</Text></Paper>)}{!evidence.references.length && <Text>No supported references found.</Text>}</Stack></Tabs.Panel>
    <Tabs.Panel value="traffic" pt="md">{template ? <Alert color="gray">Select a running Pod above to observe its istio-proxy logs.</Alert> : <Traffic pod={evidence.pod} />}</Tabs.Panel>
    <Tabs.Panel value="exposure" pt="md"><Stack><Group>{evidence.services.map(s => <Badge tt="none" key={resourceName(s.resource)} color={s.type === 'LoadBalancer' ? 'orange' : 'gray'}>{s.type || 'ClusterIP'} · {s.resource.name}</Badge>)}</Group>{evidence.routing.relationships.map((r, i) => <Paper withBorder p="md" key={i}><Text fw={600}>{resourceName(r.route)} → {r.service.name}</Text><Text size="sm">{r.description}</Text><EvidenceList evidence={r.evidence} /></Paper>)}<Graph data={evidence.routing.graph} center={`Pod/${evidence.pod.namespace}/${evidence.pod.name}`} topology /></Stack></Tabs.Panel>
    <Tabs.Panel value="policies" pt="md"><Stack><SimpleGrid cols={2}>{(['ingress', 'egress'] as const).map(direction => <Paper withBorder p="md" key={direction}><Text fw={600}>{direction} · {evidence.policies[direction].status}</Text><Text size="sm">{evidence.policies[direction].summary}</Text><Text size="xs" c="dimmed">Kubernetes NetworkPolicy assessment</Text></Paper>)}</SimpleGrid><Accordion variant="separated">{evidence.policies.policies.map((p, i) => <Accordion.Item key={i} value={String(i)}><Accordion.Control>{resourceName(p.resource)} · {p.selection}</Accordion.Control><Accordion.Panel><Code block>{JSON.stringify({ selector: p.selector, rules: p.rules }, null, 2)}</Code>{p.notes.map((n, j) => <Text size="sm" key={j}>{n}</Text>)}</Accordion.Panel></Accordion.Item>)}</Accordion><Graph data={evidence.policies.graph} center={`Pod/${evidence.pod.namespace}/${evidence.pod.name}`} /></Stack></Tabs.Panel>
  </Tabs>;
}

export function RegistryDetail({ resource, navigate }: { resource: Resource; navigate: Navigate }) {
  const [refresh, setRefresh] = useState(0);
  const [removed, setRemoved] = useState(false);
  const [selected, setSelected] = useState('template');
  const [confirm, setConfirm] = useState('');
  const [operation, setOperation] = useState<string | null>(null);
  const query = new URLSearchParams(Object.entries(identity(resource)).map(([k, v]) => [k, v ?? '']));
  const { data, error, loading } = useAPI<WorkloadDetail>(`/api/registry/workload?${query}`, refresh);
  const mutation = useRegistryChange();
  const evidence = data?.pods.find(p => p.pod.uid === selected) ?? data?.template;
  const scan = async (image: string) => { const result = await mutation.change('scan', resource, image); if (result?.id) navigate(`/registry/sbom/${encodeURIComponent(result.id)}`); };
  const act = async () => { if (operation) { const result = await mutation.change(operation, resource); if (result && operation !== 'contain') setRemoved(true); setOperation(null); setConfirm(''); setRefresh(v => v + 1); } };
  return <Stack gap="lg"><Group justify="space-between"><Button variant="subtle" onClick={() => navigate('/registry')}>← Registry</Button><Button variant="light" loading={loading} onClick={() => setRefresh(v => v + 1)}>Refresh</Button></Group><div><Text className="eyebrow">{resource.kind} · {resource.namespace}</Text><Title order={1}>{resource.name}</Title><Text c="dimmed" size="xs">UID {resource.uid}</Text></div><RequestState loading={loading} error={removed ? '' : error} /><ActionFeedback result={mutation.result} />{removed && <Text>Deletion was requested. Return to Registry or Explore to inspect garbage collection and remaining Pods.</Text>}
    {data && evidence && !removed && <><Group><Badge color={data.registered ? 'indigo' : 'gray'}>{data.registered ? 'Managed by Peeker' : 'Discovered'}</Badge><Badge variant="light">{data.podCount} Pods</Badge><Badge color={evidence.pod.sidecar ? 'teal' : 'gray'}>Istio proxy {evidence.pod.sidecar ? 'present' : 'not detected'}</Badge><Button size="xs" variant="light" disabled={mutation.busy} onClick={async () => { await mutation.change(data.registered ? 'unregister' : 'register', resource); setRefresh(v => v + 1); }}>{data.registered ? 'Unregister' : 'Register workload'}</Button></Group>
      <details open><summary>Workload recommendations</summary><Paper withBorder p="md"><Stack gap="xs">{data.recommendations.map((r, i) => <Text size="sm" key={i}>• {r}</Text>)}</Stack></Paper></details>
      <Select label="Evidence source" value={selected} allowDeselect={false} onChange={v => v && setSelected(v)} data={[{ value: 'template', label: 'Controller template · declared configuration' }, ...data.pods.map(p => ({ value: p.pod.uid ?? '', label: `${p.pod.name} · ${p.pod.phase} · risk ${p.pod.risk.score}` }))]} />
      {selected === 'template' && <Text size="sm" c="dimmed">Template evidence precedes admission and sidecar injection. Select a running Pod to inspect observed configuration and traffic.</Text>}{data.podsTruncated && <Alert color="orange">Showing the first 100 Pods. Use Explore for additional Pod evidence.</Alert>}
      <EvidencePanels evidence={evidence} template={evidence === data.template} scan={scan} scans={data.scans} busy={mutation.busy} registered={data.registered} />
      {data.scans.length > 0 && <details><summary>Image scans &amp; SBOMs · {data.scans.length}</summary><Stack mt="sm">{data.scans.map(scan => <Paper withBorder p="sm" key={scan.id}><Group justify="space-between"><div><Text size="sm">{scan.image}</Text><Text size="xs" c="dimmed">{scan.status} · {new Date(scan.startedAt).toLocaleString()}</Text></div><Button size="xs" variant="light" onClick={() => navigate(`/registry/sbom/${encodeURIComponent(scan.id)}`)}>Open SBOM</Button></Group></Paper>)}</Stack></details>}
      <details><summary>Response actions</summary><Paper withBorder p="md"><Stack><Text size="sm">Contain network installs Cilium ingress/egress deny for current Pods, backs up RBAC, and removes direct grants when the ServiceAccount is unshared. Shared/group grants remain. Replacement Pods need a new action; enforcement requires cluster verification.</Text><Text size="sm">Make it orphan removes the controller chain while allowing current Pods to continue for investigation. It stops self-healing, does not isolate traffic, and external reconcilers can recreate controllers.</Text><Text size="sm">Kill-switch requests foreground deletion of the workload and dependent Pods. Peeker does not delete storage directly.</Text>{!data.actionsAvailable && <Alert color="gray">Use a managed kubeconfig context for response actions. Install cluster/responder.yaml and allow impersonation of peeker-responder.</Alert>}<Group>{[['contain', 'Contain network'], ['orphan', 'Make it orphan'], ['kill', 'Kill-switch']].map(([op, label]) => <Button key={op} color={op === 'kill' ? 'red' : 'orange'} variant="light" disabled={!data.registered || !data.actionsAvailable || mutation.busy} onClick={() => setOperation(op)}>{label}</Button>)}</Group>{operation && <Paper withBorder p="md"><Stack gap="sm"><Text fw={600}>Confirm {operation} for {resource.kind} {resource.namespace}/{resource.name}</Text><TextInput label="Type the workload name" value={confirm} onChange={e => setConfirm(e.currentTarget.value)} /><Group><Button color="red" disabled={confirm !== resource.name} loading={mutation.busy} onClick={act}>Execute {operation}</Button><Button variant="subtle" onClick={() => setOperation(null)}>Cancel</Button></Group></Stack></Paper>}</Stack></Paper></details>
      <details><summary>Data coverage · {new Date(data.capturedAt).toLocaleTimeString()}</summary><Availability states={data.states} /></details></>}
  </Stack>;
}

export function SBOMPage({ id, navigate }: { id: string; navigate: Navigate }) {
  const [refresh, setRefresh] = useState(0);
  const [filter, setFilter] = useState('');
  const { data, loading, error } = useAPI<Scan>(`/api/registry/scan?id=${encodeURIComponent(id)}`, refresh);
  useEffect(() => { if (data?.status !== 'running') return; const timer = setTimeout(() => setRefresh(v => v + 1), 2000); return () => clearTimeout(timer); }, [data]);
  const components = data?.sbom?.components?.filter(c => `${c.name} ${c.version} ${c.purl}`.toLowerCase().includes(filter.toLowerCase())) ?? [];
  const vulnerabilities = data?.sbom?.vulnerabilities ?? [];
  const download = () => { if (!data?.sbom) return; const url = URL.createObjectURL(new Blob([JSON.stringify(data.sbom, null, 2)], { type: 'application/vnd.cyclonedx+json' })); const a = document.createElement('a'); a.href = url; a.download = 'peeker-sbom.cdx.json'; a.click(); URL.revokeObjectURL(url); };
  return <Stack gap="lg"><Button variant="subtle" onClick={() => navigate('/registry')}>← Registry</Button><Title order={1}>Image SBOM</Title><RequestState loading={loading && !data} error={error} />{data && <><Code>{data.image}</Code><Alert color={data.status === 'error' ? 'orange' : 'indigo'} title={data.status}>{data.message}</Alert>{data.classification && <ImageEvidence scan={data} />}{data.sbom && <><Group><Badge>{data.sbom.components?.length ?? 0} components</Badge><Badge color="orange">{vulnerabilities.length} vulnerabilities</Badge><Button variant="light" onClick={download}>Download CycloneDX</Button></Group><Text size="sm">Prioritize critical/high vulnerabilities with available fixes. Upgrade affected packages or base images, rebuild, then pin and rescan the resulting digest.</Text><Tabs defaultValue="vulnerabilities"><Tabs.List><Tabs.Tab value="vulnerabilities">Vulnerabilities</Tabs.Tab><Tabs.Tab value="components">Components</Tabs.Tab></Tabs.List><Tabs.Panel value="vulnerabilities" pt="md"><Accordion variant="separated">{vulnerabilities.slice(0, 200).map((v, i) => <Accordion.Item value={String(i)} key={i}><Accordion.Control>{v.id} · {v.ratings?.map(r => r.severity).filter(Boolean).join(', ') || 'unrated'}</Accordion.Control><Accordion.Panel><Text size="sm">{v.description}</Text><Text size="sm" fw={600} mt="sm">{v.recommendation}</Text><Code block>{v.affects?.map(a => a.ref).join('\n')}</Code></Accordion.Panel></Accordion.Item>)}</Accordion>{vulnerabilities.length > 200 && <Text>Showing 200. Download the full report for all vulnerabilities.</Text>}{!vulnerabilities.length && <Text>No vulnerabilities reported by this scan; this is not a guarantee of safety.</Text>}</Tabs.Panel><Tabs.Panel value="components" pt="md"><TextInput mb="md" placeholder="Filter components" value={filter} onChange={e => setFilter(e.currentTarget.value)} /><Table><Table.Thead><Table.Tr><Table.Th>Package</Table.Th><Table.Th>Version</Table.Th><Table.Th>Type</Table.Th></Table.Tr></Table.Thead><Table.Tbody>{components.slice(0, 500).map((c, i) => <Table.Tr key={i}><Table.Td>{c.name}</Table.Td><Table.Td>{c.version}</Table.Td><Table.Td>{c.type}</Table.Td></Table.Tr>)}</Table.Tbody></Table>{components.length > 500 && <Text>Showing 500 matching components. Filter or download the full SBOM.</Text>}</Tabs.Panel></Tabs></>}</>}</Stack>;
}
