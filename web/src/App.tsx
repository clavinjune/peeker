import { useEffect, useState } from 'react';
import { Accordion, Alert, Anchor, AppShell, Badge, Button, Card, Checkbox, Code, Container, Divider, Group, Loader, MantineProvider, Paper, Select, SimpleGrid, Stack, Table, Tabs, Text, TextInput, Title } from '@mantine/core';
import { Graph, EvidenceList } from './Graph';
import { RiskBadge, RiskOverview, SecurityFindings } from './Security';
import { rankPods } from './risk';
import { Traffic } from './Traffic';
import { ClusterContext, ContextControls, useAPI, useContexts } from './Cluster';
import { useHidden } from './Hidden';
import { resourceName } from './types';
import type { Capabilities, Detail, Pod, PodList, State } from './types';

function Detection({ refresh }: { refresh: number }) {
  const { data, loading } = useAPI<Capabilities>('/api/capabilities', refresh);
  return <Group gap="xs"><Badge variant="light" color="teal">Read only</Badge>{loading ? <Badge color="gray" variant="light">Detecting networking…</Badge> : <>{data?.istio === 'detected' && <Badge variant="light" color="indigo" title="networking.istio.io API group is registered">Istio detected</Badge>}{data?.cilium === 'detected' && <Badge variant="light" color="cyan" title="cilium.io API group is registered">Cilium detected</Badge>}{(!data || data.istio === 'unknown' || data.cilium === 'unknown') && <Badge variant="light" color="orange" title="API discovery unavailable; installed networking cannot be determined">Networking detection unavailable</Badge>}</>}</Group>;
}

function Availability({ states }: { states: State[] }) {
  const problems = states.filter(s => s.status !== 'available');
  return <Accordion variant="separated"><Accordion.Item value="apis"><Accordion.Control><Group><Text size="sm">API availability</Text><Badge color={problems.some(p => p.status !== 'missing-api') ? 'orange' : 'gray'} variant="light">{states.length - problems.length}/{states.length} readable</Badge></Group></Accordion.Control>
    <Accordion.Panel><Stack gap="xs">{states.map(s => <Group key={s.resource} justify="space-between"><Text size="sm">{s.resource}</Text><Badge color={s.status === 'available' ? 'teal' : s.status === 'missing-api' ? 'gray' : 'orange'}>{s.status}</Badge>{s.message && <Text size="xs" c="dimmed" w="100%">{s.message}</Text>}</Group>)}</Stack></Accordion.Panel>
  </Accordion.Item></Accordion>;
}
function RequestState({ loading, error }: { loading: boolean; error: string }) {
  if (loading) return <Paper p="xl" withBorder><Group><Loader size="sm" /><Text>Reading cluster resources…</Text></Group></Paper>;
  if (error) return <Alert color="red" title="Cluster data unavailable">{error}<Text size="sm" mt="sm">This is an inaccessible resource, not an empty cluster. Check the read-only proxy and use Refresh to retry.</Text></Alert>;
  return null;
}
function ownerLabel(pod: Pod) {
  const chain = pod.ownership;
  if (chain.status === 'standalone') return 'Standalone pod';
  const last = chain.owners.at(-1);
  return last ? `${last.kind} · ${last.name}` : 'Unresolved owner';
}
function Pods({ navigate }: { navigate: (path: string) => void }) {
  const [namespace, setNamespace] = useState(''); const [filter, setFilter] = useState(''); const [refresh, setRefresh] = useState(0);
  const [sort, setSort] = useState('risk');
  const [showHidden, setShowHidden] = useState(false);
  const hidden = useHidden();
  const { data, error, loading } = useAPI<PodList>(`/api/pods?namespace=${encodeURIComponent(namespace)}`, refresh);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  useEffect(() => { if (data?.states.find(s => s.resource === 'namespaces')?.status === 'available') setNamespaces(data.namespaces); }, [data]);
  const matching = data?.pods.filter(p => p.name.includes(filter)) ?? [];
  const hiddenCount = matching.filter(hidden.has).length;
  const pods = rankPods(matching.filter(p => showHidden || !hidden.has(p)), sort);
  return <Stack gap="md">
    <Group justify="space-between"><div><Text className="eyebrow">CLUSTER INVENTORY</Text><Title order={1}>Pods</Title><Text c="dimmed" size="sm">Prioritize workload risk.</Text></div><Detection refresh={refresh} /></Group>
    <RiskOverview pods={data ? pods : undefined} />
    <Paper withBorder p="sm"><Group align="end" gap="sm"><Select label="Namespace" data={[{ value: '', label: 'All namespaces' }, ...namespaces.map(n => ({ value: n, label: n }))]} value={namespace} onChange={value => setNamespace(value ?? '')} w={220} searchable /><TextInput label="Pod name" placeholder="Find a pod…" value={filter} onChange={e => setFilter(e.currentTarget.value)} style={{ flex: 1, minWidth: 150 }} /><Select label="Prioritize" value={sort} onChange={value => setSort(value ?? 'risk')} allowDeselect={false} data={[{ value: 'risk', label: 'Highest risk' }, { value: 'review', label: 'Needs review' }, { value: 'name', label: 'Namespace / name' }]} w={180} /><Button variant="light" onClick={() => setRefresh(v => v + 1)} loading={loading}>Refresh</Button></Group></Paper>
    <RequestState loading={loading} error={error} />
    <Group justify="space-between"><Checkbox label={`Show hidden (${hiddenCount})`} checked={showHidden} onChange={e => setShowHidden(e.currentTarget.checked)} /><Text size="xs" c="dimmed">{hidden.persistent ? 'Hiding follows the owning workload · Saved in this browser per context' : 'External proxy: hiding applies to this view only'} · Scores reflect visible rows</Text></Group>
    {hidden.warning && <Alert color="orange">{hidden.warning}</Alert>}
    {data && <><Paper withBorder className="table-panel"><Group px="md" py="sm" justify="space-between"><Text size="sm" fw={600}>{pods.length} matching pods</Text><Text size="xs" c="dimmed">Higher score = higher risk · ≥ = partial assessment</Text></Group><Table.ScrollContainer minWidth={900}><Table highlightOnHover verticalSpacing="sm" horizontalSpacing="md"><Table.Thead><Table.Tr><Table.Th>Risk</Table.Th><Table.Th>Workload</Table.Th><Table.Th>Namespace</Table.Th><Table.Th>Top finding</Table.Th><Table.Th>Hide</Table.Th><Table.Th /></Table.Tr></Table.Thead><Table.Tbody>
      {pods.map(p => <Table.Tr key={`${p.namespace}/${p.name}`}><Table.Td><RiskBadge risk={p.risk} />{p.risk.unknown > 0 && <Text size="xs" c="dimmed" mt={2}>Partial assessment</Text>}</Table.Td><Table.Td><Text fw={500} size="sm" className="inventory-name" title={p.name}>{p.name}</Text><Text c="dimmed" size="xs">{ownerLabel(p)} · {p.ready}/{p.containers} · {p.phase}</Text></Table.Td><Table.Td><Text size="xs">{p.namespace}</Text></Table.Td><Table.Td><Text size="sm">{p.risk.topFinding || (p.risk.unknown ? 'More information needed' : 'No findings')}</Text>{p.risk.findings > 1 && <Text size="xs" c="dimmed">+{p.risk.findings - 1} more</Text>}</Table.Td><Table.Td><Checkbox aria-label={`Hide ${p.name}`} title={p.ownership.status === 'resolved' ? `Hide ${ownerLabel(p)} and its replacement pods` : 'Ownership is unresolved or standalone: hide only this pod instance'} checked={hidden.has(p)} onChange={e => hidden.toggle(p, e.currentTarget.checked)} /></Table.Td><Table.Td><Button variant="subtle" size="xs" onClick={() => navigate(`/pods/${encodeURIComponent(p.namespace ?? '')}/${encodeURIComponent(p.name)}`)}>Details →</Button></Table.Td></Table.Tr>)}
    </Table.Tbody></Table></Table.ScrollContainer>{!pods.length && <Text ta="center" p="xl" c="dimmed">No pods match this namespace and name filter.</Text>}</Paper><Availability states={data.states} /></>}
  </Stack>;
}
function PodDetails({ namespace, name, navigate }: { namespace: string; name: string; navigate: (path: string) => void }) {
  const [refresh, setRefresh] = useState(0);
  const { data, error, loading } = useAPI<Detail>(`/api/pods/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`, refresh);
  const pod = data?.pod;
  return <Stack gap="lg"><Group justify="space-between"><Button variant="subtle" onClick={() => navigate('/')}>← Pod inventory</Button><Button variant="light" loading={loading} onClick={() => setRefresh(v => v + 1)}>Refresh</Button></Group>
    <div><Text className="eyebrow">POD SECURITY EXPLORER · {namespace}</Text><Title order={2} className="pod-title">{name}</Title></div><RequestState loading={loading} error={error} />
    {data && pod && <><details><summary>Pod information · {ownerLabel(pod)} · {pod.ready}/{pod.containers} ready</summary><Paper p="md" withBorder><SimpleGrid cols={{ base: 2, md: 4 }}>{[['Namespace', pod.namespace], ['Node', pod.node || 'Unscheduled'], ['Phase / readiness', `${pod.phase} · ${pod.ready}/${pod.containers}`], ['Pod IP', pod.ip || 'Not assigned'], ['Istio sidecar', pod.sidecar ? 'Present' : 'Not detected'], ['Controller', ownerLabel(pod)], ['Ownership', pod.ownership.status], ['Snapshot', new Date(data.capturedAt).toLocaleTimeString()]].map(([label, value]) => <div key={label}><Text c="dimmed" size="xs">{label}</Text><Text size="sm" fw={500}>{value}</Text></div>)}</SimpleGrid><Divider my="md" /><Group gap="xs">{Object.entries(pod.labels ?? {}).map(([key, value]) => <Badge key={key} variant="outline" color="gray" tt="none">{key}={value}</Badge>)}</Group><Text size="sm" mt="md">Ownership chain: Pod {pod.name}{pod.ownership.owners.map(o => ` → ${o.kind} ${o.name}`).join('')}</Text>{pod.ownership.message && <Text size="sm" c="orange">{pod.ownership.message}</Text>}</Paper></details>
      <Tabs defaultValue="findings" keepMounted={false}><Tabs.List><Tabs.Tab value="findings">Security findings</Tabs.Tab><Tabs.Tab value="traffic">Live traffic</Tabs.Tab><Tabs.Tab value="security">Network policies</Tabs.Tab><Tabs.Tab value="topology">Topology</Tabs.Tab><Tabs.Tab value="routes">Routes</Tabs.Tab><Tabs.Tab value="apis">Data coverage</Tabs.Tab></Tabs.List>
        <Tabs.Panel value="traffic" pt="md"><Traffic pod={pod} /></Tabs.Panel>
        <Tabs.Panel value="findings" pt="md"><SecurityFindings report={data.security} /></Tabs.Panel>
        <Tabs.Panel value="security" pt="lg"><Stack gap="lg"><SimpleGrid cols={{ base: 1, md: 2 }}>{(['ingress', 'egress'] as const).map(direction => <Card key={direction} withBorder padding="lg"><Group justify="space-between"><Title order={4}>{direction === 'ingress' ? 'Ingress' : 'Egress'}</Title><Badge color={data.policies[direction].status === 'denied' ? 'red' : data.policies[direction].status === 'unknown' ? 'yellow' : 'indigo'}>{data.policies[direction].status}</Badge></Group><Text mt="md" size="sm">{data.policies[direction].summary}</Text><Text size="xs" c="dimmed" mt="xs">Kubernetes NetworkPolicy only</Text></Card>)}</SimpleGrid>
          <Paper withBorder p="lg"><Title order={4} mb="md">Security graph</Title><Graph data={data.policies.graph} center={`Pod/${pod.namespace}/${pod.name}`} /></Paper>
          <Title order={4}>Selecting policies</Title>{!data.policies.policies.length && <Text c="dimmed">No selecting policies were found in the readable inventories. Check API availability before concluding that a policy type is absent.</Text>}
          <Accordion variant="separated">{data.policies.policies.map((p, i) => <Accordion.Item key={i} value={String(i)}><Accordion.Control><Group><Text size="sm" fw={600}>{resourceName(p.resource)}</Text><Badge variant="light">{p.selection}</Badge></Group></Accordion.Control><Accordion.Panel><Text size="sm">Selector</Text><Code block>{JSON.stringify(p.selector, null, 2)}</Code>{p.notes.map((n, i) => <Alert mt="sm" color="yellow" key={i}>{n}</Alert>)}{!p.rules.length && <Text mt="md" size="sm">No explicit allow/deny rules. See direction-specific isolation and policyTypes evidence.</Text>}{p.rules.map((r, i) => <Paper withBorder p="md" mt="md" key={i}><Text fw={600} size="sm">{r.field} · {r.action}</Text><Text size="sm" mt="xs">Peers</Text><Code block>{JSON.stringify(r.peers ?? [], null, 2)}</Code><Text size="sm" mt="xs">Ports</Text><Code block>{JSON.stringify(r.ports ?? [], null, 2)}</Code>{r.restrictions && <><Text size="sm" mt="xs">Restrictions / L7</Text><Code block>{JSON.stringify(r.restrictions, null, 2)}</Code></>}</Paper>)}</Accordion.Panel></Accordion.Item>)}</Accordion>
          <details><summary>Direction-specific isolation evidence</summary><EvidenceList evidence={[...data.policies.ingress.evidence, ...data.policies.egress.evidence]} /></details>
        </Stack></Tabs.Panel>
        <Tabs.Panel value="topology" pt="lg"><Paper p="lg" withBorder><Title order={4} mb="sm">Configuration-derived topology</Title><Text size="sm" c="dimmed" mb="lg">Workloads, Services and routes connected by resource references. This is not a traffic graph.</Text><Graph data={data.routing.graph} center={`Pod/${pod.namespace}/${pod.name}`} topology /><Anchor href="http://127.0.0.1:20001/kiali/" target="_blank" rel="noreferrer">Open local Kiali ↗</Anchor><Text c="dimmed" size="xs" mt="xs">Prometheus is disabled. Kiali traffic graphs, rates, latency and request-based health are unavailable.</Text></Paper></Tabs.Panel>
        <Tabs.Panel value="routes" pt="lg"><Stack>{!data.routing.relationships.length && <Alert color="gray">No matching route-to-Service-to-pod relationship found in readable APIs. Missing and denied APIs are listed separately.</Alert>}{data.routing.relationships.map((r, i) => <Paper key={i} withBorder p="lg"><Group justify="space-between"><Title order={5}>{resourceName(r.route)}</Title><Badge variant="light" color="yellow">{r.status}</Badge></Group><Text mt="sm">→ {resourceName(r.service)} → Pod {pod.name}</Text><Text size="sm" c="dimmed" my="md">{r.description}</Text><EvidenceList evidence={r.evidence} /></Paper>)}</Stack></Tabs.Panel>
        <Tabs.Panel value="apis" pt="lg"><Availability states={data.states} /></Tabs.Panel>
      </Tabs>
      <Text size="xs" c="dimmed">Security findings assess configuration. Live traffic reports sidecar observations; it does not verify policy enforcement.</Text>
    </>}
  </Stack>;
}
export function App() {
  const contexts = useContexts();
  const [path, setPath] = useState('/');
  useEffect(() => { const handler = () => setPath(window.location.pathname); handler(); window.addEventListener('popstate', handler); return () => window.removeEventListener('popstate', handler); }, []);
  const navigate = (next: string) => { window.history.pushState({}, '', next); setPath(next); window.scrollTo(0, 0); };
  const parts = path.split('/');
  const ready = !contexts.busy && contexts.info?.status === 'ready';
  return <MantineProvider theme={{ primaryColor: 'indigo', defaultRadius: 'md', fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif' }}><AppShell header={{ height: 100 }} padding="xl"><AppShell.Header><Group h="100%" justify="space-between" px="xl"><Group gap="sm"><div className="brand-mark">p</div><Text fw={750} size="xl">peeker</Text><Text c="dimmed" size="sm" visibleFrom="md">Kubernetes security explorer</Text></Group><ContextControls state={contexts} /></Group></AppShell.Header><AppShell.Main><Container size="xl" py="md">{contexts.error && <Alert color="orange" mb="md">{contexts.error}</Alert>}{ready ? <ClusterContext.Provider key={`${contexts.info?.generation}:${contexts.info?.current}`} value={contexts.info}>{parts.length === 4 && parts[1] === 'pods' ? <PodDetails key={path} namespace={decodeURIComponent(parts[2])} name={decodeURIComponent(parts[3])} navigate={navigate} /> : <Pods navigate={navigate} />}</ClusterContext.Provider> : <Stack><div><Text className="eyebrow">CLUSTER INVENTORY</Text><Title order={1}>Pods</Title></div><Alert color="gray" title={contexts.busy ? 'Switching context…' : 'Kubernetes context'}>{contexts.busy ? 'Starting its read-only proxy and clearing the previous cluster view.' : contexts.info?.message || 'Loading local Kubernetes contexts…'}</Alert><Text size="sm" c="dimmed">Each context needs peeker-reader permissions and local permission to impersonate that service account.</Text></Stack>}<Text ta="center" c="dimmed" size="xs" mt="xl" py="lg">Read-only · Browser → Go → kubectl proxy → Kubernetes · Cluster data stays in memory · No database</Text></Container></AppShell.Main></AppShell></MantineProvider>;
}
