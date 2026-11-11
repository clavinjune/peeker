import { useEffect, useState } from 'react';
import { Accordion, Alert, Anchor, AppShell, Badge, Button, Card, Code, Container, Divider, Group, MantineProvider, Paper, SimpleGrid, Stack, Tabs, Text, Title } from '@mantine/core';
import { Graph, EvidenceList } from './Graph';
import { SecurityFindings } from './Security';
import { Permissions } from './Permissions';
import { Inventory, ownerLabel } from './Inventory';
import { Availability, RequestState } from './ClusterUI';
import { Traffic } from './Traffic';
import { ClusterContext, ContextControls, useAPI, useContexts } from './Cluster';
import { resourceName } from './types';
import type { Detail } from './types';
import { Registry, RegistryDetail, SBOMPage } from './Registry';

function PodDetails({ namespace, name, navigate }: { namespace: string; name: string; navigate: (path: string) => void }) {
  const [refresh, setRefresh] = useState(0);
  const { data, error, loading } = useAPI<Detail>(`/api/pods/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`, refresh);
  const pod = data?.pod;
  return <Stack gap="lg"><Group justify="space-between"><Button variant="subtle" onClick={() => navigate('/explore')}>← Explore</Button><Button variant="light" loading={loading} onClick={() => setRefresh(v => v + 1)}>Refresh</Button></Group>
    <div><Text className="eyebrow">POD SECURITY EXPLORER · {namespace}</Text><Title order={2} className="pod-title">{name}</Title></div><RequestState loading={loading} error={error} />
    {data && pod && <><details><summary>Pod information · {ownerLabel(pod)} · {pod.ready}/{pod.containers} ready</summary><Paper p="md" withBorder><SimpleGrid cols={{ base: 2, md: 4 }}>{[['Namespace', pod.namespace], ['Node', pod.node || 'Unscheduled'], ['Phase / readiness', `${pod.phase} · ${pod.ready}/${pod.containers}`], ['Pod IP', pod.ip || 'Not assigned'], ['Istio sidecar', pod.sidecar ? 'Present' : 'Not detected'], ['Controller', ownerLabel(pod)], ['Ownership', pod.ownership.status], ['Snapshot', new Date(data.capturedAt).toLocaleTimeString()]].map(([label, value]) => <div key={label}><Text c="dimmed" size="xs">{label}</Text><Text size="sm" fw={500}>{value}</Text></div>)}</SimpleGrid><Divider my="md" /><Group gap="xs">{Object.entries(pod.labels ?? {}).map(([key, value]) => <Badge key={key} variant="outline" color="gray" tt="none">{key}={value}</Badge>)}</Group><Text size="sm" mt="md">Ownership chain: Pod {pod.name}{pod.ownership.owners.map(o => ` → ${o.kind} ${o.name}`).join('')}</Text>{pod.ownership.message && <Text size="sm" c="orange">{pod.ownership.message}</Text>}</Paper></details>
      <Tabs defaultValue="findings" keepMounted={false}><Tabs.List><Tabs.Tab value="findings">Security findings</Tabs.Tab><Tabs.Tab value="permissions">Permissions</Tabs.Tab><Tabs.Tab value="traffic">Live traffic</Tabs.Tab><Tabs.Tab value="security">Network policies</Tabs.Tab><Tabs.Tab value="topology">Topology</Tabs.Tab><Tabs.Tab value="routes">Routes</Tabs.Tab><Tabs.Tab value="apis">Data coverage</Tabs.Tab></Tabs.List>
        <Tabs.Panel value="permissions" pt="md"><Permissions report={data.permissions} /></Tabs.Panel>
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
function Page({ path, navigate }: { path: string; navigate: (path: string) => void }) {
  let parts: string[];
  try { parts = path.split('/').map(decodeURIComponent); } catch { return <Alert color="orange">Invalid page address</Alert>; }
  if (parts[1] === 'registry') {
    if (parts[2] === 'sbom' && parts.length === 4) return <SBOMPage id={parts[3]} navigate={navigate} />;
    if (parts.length === 6) return <RegistryDetail resource={{ kind: parts[2], namespace: parts[3], name: parts[4], uid: parts[5] }} navigate={navigate} />;
    return <Registry navigate={navigate} />;
  }
  if (parts[1] === 'explore') parts = parts.slice(1);
  if (parts.length === 4 && parts[1] === 'pods') return <PodDetails namespace={parts[2]} name={parts[3]} navigate={navigate} />;
  return <Inventory navigate={next => navigate(next.startsWith('/pods/') ? `/explore${next}` : next)} />;
}

export function App() {
  const contexts = useContexts();
  const [path, setPath] = useState('/');
  useEffect(() => { const handler = () => { if (window.location.pathname === '/') window.history.replaceState({}, '', '/explore'); setPath(window.location.pathname); }; handler(); window.addEventListener('popstate', handler); return () => window.removeEventListener('popstate', handler); }, []);
  const navigate = (next: string) => { window.history.pushState({}, '', next); setPath(next); window.scrollTo(0, 0); };
  const ready = !contexts.busy && contexts.info?.status === 'ready';
  return <MantineProvider theme={{ primaryColor: 'indigo', defaultRadius: 'md', fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif' }}>
    <AppShell header={{ height: 100 }} padding="xl">
      <AppShell.Header><Group h="100%" justify="space-between" px="xl"><Group gap="sm"><div className="brand-mark">p</div><Text fw={750} size="xl">peeker</Text><Button variant={path.startsWith('/registry') ? 'subtle' : 'light'} onClick={() => navigate('/explore')}>Explore</Button><Button variant={path.startsWith('/registry') ? 'light' : 'subtle'} onClick={() => navigate('/registry')}>Registry</Button></Group><ContextControls state={contexts} /></Group></AppShell.Header>
      <AppShell.Main><Container size="xl" py="md">
        {contexts.error && <Alert color="orange" mb="md">{contexts.error}</Alert>}
        {ready ? <ClusterContext.Provider key={`${contexts.info?.generation}:${contexts.info?.current}`} value={contexts.info}><Page key={path} path={path} navigate={navigate} /></ClusterContext.Provider> : <Stack><div><Text className="eyebrow">KUBERNETES SECURITY</Text><Title order={1}>Explore &amp; Registry</Title></div><Alert color="gray" title={contexts.busy ? 'Switching context…' : 'Kubernetes context'}>{contexts.busy ? 'Starting its read-only proxy and clearing the previous cluster view.' : contexts.info?.message || 'Loading local Kubernetes contexts…'}</Alert><Text size="sm" c="dimmed">Each context needs peeker-reader permissions and local permission to impersonate that service account.</Text></Stack>}
        <Text ta="center" c="dimmed" size="xs" mt="xl" py="lg">Explore is read-only · Registry actions use peeker-responder · Cluster data stays in memory</Text>
      </Container></AppShell.Main>
    </AppShell>
  </MantineProvider>;
}
