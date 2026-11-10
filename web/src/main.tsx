import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Accordion, Alert, Anchor, AppShell, Badge, Button, Card, Code, Container, Divider, Group, Loader, MantineProvider, Paper, Select, SimpleGrid, Stack, Table, Tabs, Text, TextInput, Title } from '@mantine/core';
import '@mantine/core/styles.css';
import './style.css';
import { Graph, EvidenceList } from './Graph';
import { resourceName } from './types';
import type { Detail, Pod, PodList, State } from './types';

function useAPI<T>(url: string, refresh: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const abort = new AbortController(); setLoading(true); setError(''); setData(null);
    fetch(url, { signal: abort.signal }).then(async response => {
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || `Request failed: HTTP ${response.status}`);
      setData(body as T);
    }).catch((e: unknown) => { if (!abort.signal.aborted) setError(e instanceof Error ? e.message : 'Request failed'); }).finally(() => { if (!abort.signal.aborted) setLoading(false); });
    return () => abort.abort();
  }, [url, refresh]);
  return { data, error, loading };
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
  const { data, error, loading } = useAPI<PodList>(`/api/pods?namespace=${encodeURIComponent(namespace)}`, refresh);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  useEffect(() => { if (data?.states.find(s => s.resource === 'namespaces')?.status === 'available') setNamespaces(data.namespaces); }, [data]);
  const pods = data?.pods.filter(p => p.name.includes(filter)) ?? [];
  return <Stack gap="lg">
    <Group justify="space-between"><div><Text className="eyebrow">CLUSTER INVENTORY</Text><Title order={1}>Pods</Title><Text c="dimmed" mt="xs">Start with a workload. Follow its ownership, policy and exposure.</Text></div><Badge variant="light" color="teal">Read only</Badge></Group>
    <Paper withBorder p="md"><Group align="end"><Select label="Namespace" data={[{ value: '', label: 'All namespaces' }, ...namespaces.map(n => ({ value: n, label: n }))]} value={namespace} onChange={value => setNamespace(value ?? '')} w={260} searchable /><TextInput label="Pod name" placeholder="Filter by pod name…" value={filter} onChange={e => setFilter(e.currentTarget.value)} style={{ flex: 1 }} /><Button variant="light" onClick={() => setRefresh(v => v + 1)} loading={loading}>Refresh</Button></Group></Paper>
    <RequestState loading={loading} error={error} />
    {data && <><Paper withBorder className="table-panel"><Group p="md" justify="space-between"><Text fw={600}>Pod inventory</Text><Text size="sm" c="dimmed">{pods.length} matching pods</Text></Group><Table.ScrollContainer minWidth={760}><Table highlightOnHover verticalSpacing="md" horizontalSpacing="md"><Table.Thead><Table.Tr><Table.Th>Namespace</Table.Th><Table.Th>Pod name</Table.Th><Table.Th>Controller name and kind</Table.Th><Table.Th>Details</Table.Th></Table.Tr></Table.Thead><Table.Tbody>
      {pods.map(p => <Table.Tr key={`${p.namespace}/${p.name}`}><Table.Td><Badge variant="light" color="gray">{p.namespace}</Badge></Table.Td><Table.Td><Text fw={500} size="sm">{p.name}</Text><Text c="dimmed" size="xs">{p.phase} · {p.ready}/{p.containers} ready{p.sidecar ? ' · Istio sidecar' : ''}</Text></Table.Td><Table.Td><Text size="sm">{ownerLabel(p)}</Text>{p.ownership.status === 'unresolved' && <Text size="xs" c="orange">Unresolved: {p.ownership.message}</Text>}</Table.Td><Table.Td><Button variant="subtle" size="xs" onClick={() => navigate(`/pods/${encodeURIComponent(p.namespace ?? '')}/${encodeURIComponent(p.name)}`)}>Details →</Button></Table.Td></Table.Tr>)}
    </Table.Tbody></Table></Table.ScrollContainer>{!pods.length && <Text ta="center" p="xl" c="dimmed">No pods match this namespace and name filter.</Text>}</Paper><Availability states={data.states} /></>}
  </Stack>;
}
function PodDetails({ namespace, name, navigate }: { namespace: string; name: string; navigate: (path: string) => void }) {
  const [refresh, setRefresh] = useState(0);
  const { data, error, loading } = useAPI<Detail>(`/api/pods/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`, refresh);
  const pod = data?.pod;
  return <Stack gap="lg"><Group justify="space-between"><Button variant="subtle" onClick={() => navigate('/')}>← Pod inventory</Button><Button variant="light" loading={loading} onClick={() => setRefresh(v => v + 1)}>Refresh</Button></Group>
    <div><Text className="eyebrow">POD SECURITY EXPLORER · {namespace}</Text><Title order={2} className="pod-title">{name}</Title></div><RequestState loading={loading} error={error} />
    {data && pod && <><Paper p="lg" withBorder><SimpleGrid cols={{ base: 2, md: 4 }}>{[['Namespace', pod.namespace], ['Node', pod.node || 'Unscheduled'], ['Phase / readiness', `${pod.phase} · ${pod.ready}/${pod.containers}`], ['Pod IP', pod.ip || 'Not assigned'], ['Istio sidecar', pod.sidecar ? 'Present' : 'Not detected'], ['Controller', ownerLabel(pod)], ['Ownership', pod.ownership.status], ['Snapshot', new Date(data.capturedAt).toLocaleTimeString()]].map(([label, value]) => <div key={label}><Text c="dimmed" size="xs">{label}</Text><Text size="sm" fw={500}>{value}</Text></div>)}</SimpleGrid><Divider my="md" /><Group gap="xs">{Object.entries(pod.labels ?? {}).map(([key, value]) => <Badge key={key} variant="outline" color="gray" tt="none">{key}={value}</Badge>)}</Group><Text size="sm" mt="md">Ownership chain: Pod {pod.name}{pod.ownership.owners.map(o => ` → ${o.kind} ${o.name}`).join('')}</Text>{pod.ownership.message && <Text size="sm" c="orange">{pod.ownership.message}</Text>}</Paper>
      <Alert color="blue" title="Static configuration analysis">Configuration does not prove packet delivery. NetworkPolicy allowances can be constrained by Cilium, Istio authorization, host firewalls and routing. No traffic metrics or observed flows are collected.</Alert>
      <Tabs defaultValue="security" keepMounted={false}><Tabs.List><Tabs.Tab value="security">Network security</Tabs.Tab><Tabs.Tab value="topology">Configuration-derived topology</Tabs.Tab><Tabs.Tab value="routes">Routing & exposure</Tabs.Tab><Tabs.Tab value="apis">API availability</Tabs.Tab></Tabs.List>
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
    </>}
  </Stack>;
}
function App() {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => { const handler = () => setPath(window.location.pathname); window.addEventListener('popstate', handler); return () => window.removeEventListener('popstate', handler); }, []);
  const navigate = (next: string) => { window.history.pushState({}, '', next); setPath(next); window.scrollTo(0, 0); };
  const parts = path.split('/');
  return <AppShell header={{ height: 68 }} padding="xl"><AppShell.Header><Group h="100%" justify="space-between" px="xl"><Group gap="sm"><div className="brand-mark">p</div><Text fw={750} size="xl">peeker</Text><Text c="dimmed" size="sm" visibleFrom="sm">Kubernetes security explorer</Text></Group><Group><Badge variant="dot" color="indigo">rancher-desktop</Badge><Badge variant="light" color="gray">Memory only</Badge></Group></Group></AppShell.Header><AppShell.Main><Container size="xl" py="md">{parts.length === 4 && parts[1] === 'pods' ? <PodDetails key={path} namespace={decodeURIComponent(parts[2])} name={decodeURIComponent(parts[3])} navigate={navigate} /> : <Pods navigate={navigate} />}<Text ta="center" c="dimmed" size="xs" mt="xl" py="lg">Read-only · Browser → Go → kubectl proxy → Kubernetes · No database</Text></Container></AppShell.Main></AppShell>;
}
createRoot(document.getElementById('root')!).render(<MantineProvider theme={{ primaryColor: 'indigo', defaultRadius: 'md', fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif' }}><App /></MantineProvider>);
