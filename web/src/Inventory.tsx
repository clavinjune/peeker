import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Checkbox, Group, Paper, Select, Stack, Table, Text, TextInput, Title } from '@mantine/core';
import { useAPI } from './Cluster';
import { useHidden } from './Hidden';
import { RiskBadge, RiskOverview } from './Security';
import { initialNamespace, rowWindow, useInventory } from './inventory-state';
import { Availability, Detection, RequestState } from './ClusterUI';
import type { Pod, State } from './types';

export function ownerLabel(pod: Pod) {
  const chain = pod.ownership;
  if (chain.status === 'standalone') return 'Standalone pod';
  const last = chain.owners.at(-1);
  return last ? `${last.kind} · ${last.name}` : 'Unresolved owner';
}

function PodRows({ pods, hidden, navigate }: { pods: Pod[]; hidden: ReturnType<typeof useHidden>; navigate: (path: string) => void }) {
  const [scroll, setScroll] = useState(0);
  const viewport = useRef<HTMLDivElement>(null);
  useEffect(() => { setScroll(0); viewport.current?.scrollTo(0, 0); }, [pods[0]?.uid, pods[0]?.name]);
  const window = rowWindow(pods.length, scroll);
  return <div className="inventory-viewport" ref={viewport} onScroll={e => setScroll(e.currentTarget.scrollTop)} tabIndex={0} aria-label="Pod rows"><Table highlightOnHover verticalSpacing={0} horizontalSpacing="md" className="inventory-table" aria-rowcount={pods.length + 1}><Table.Thead><Table.Tr><Table.Th>Risk</Table.Th><Table.Th>Workload</Table.Th><Table.Th>Namespace</Table.Th><Table.Th>Top finding</Table.Th><Table.Th>Hide</Table.Th><Table.Th /></Table.Tr></Table.Thead><Table.Tbody>
    {window.before > 0 && <Table.Tr aria-hidden="true"><Table.Td colSpan={6} style={{ height: window.before, padding: 0, border: 0 }} /></Table.Tr>}
    {pods.slice(window.start, window.end).map((p, index) => <Table.Tr key={`${p.namespace}/${p.name}`} aria-rowindex={window.start + index + 2} className="inventory-row"><Table.Td><RiskBadge risk={p.risk} />{p.risk.unknown > 0 && <Text size="xs" c="dimmed">Partial assessment</Text>}</Table.Td><Table.Td><Text fw={500} size="sm" className="inventory-name" title={p.name}>{p.name}</Text><Text c="dimmed" size="xs" truncate>{ownerLabel(p)} · {p.ready}/{p.containers} · {p.phase}</Text></Table.Td><Table.Td><Text size="xs" truncate>{p.namespace}</Text></Table.Td><Table.Td><Text size="sm" lineClamp={2}>{p.risk.topFinding || (p.risk.unknown ? 'More information needed' : 'No findings')}</Text></Table.Td><Table.Td><Checkbox aria-label={`Hide ${p.name}`} title={p.ownership.status === 'resolved' ? `Hide ${ownerLabel(p)} and replacement pods` : 'Hide only this pod instance'} checked={hidden.has(p)} onChange={e => hidden.toggle(p, e.currentTarget.checked)} /></Table.Td><Table.Td><Button variant="subtle" size="xs" onClick={() => navigate(`/pods/${encodeURIComponent(p.namespace ?? '')}/${encodeURIComponent(p.name)}`)}>Details →</Button></Table.Td></Table.Tr>)}
    {window.after > 0 && <Table.Tr aria-hidden="true"><Table.Td colSpan={6} style={{ height: window.after, padding: 0, border: 0 }} /></Table.Tr>}
  </Table.Tbody></Table></div>;
}

export function Inventory({ navigate }: { navigate: (path: string) => void }) {
  const [namespace, setNamespace] = useState<string | null>(null);
  const [filter, setFilter] = useState(''); const [name, setName] = useState('');
  const [sort, setSort] = useState('risk'); const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0); const [showHidden, setShowHidden] = useState(false);
  const preferences = useHidden();
  const hidden = { ...preferences, toggle: (pod: Pod, value: boolean) => { setOffset(0); preferences.toggle(pod, value); } };
  const namespaces = useAPI<{ namespaces: string[]; state: State }>('/api/namespaces', refresh);
  useEffect(() => { if (namespace === null && (namespaces.data || namespaces.error)) setNamespace(initialNamespace(namespaces.data?.namespaces ?? [])); }, [namespace, namespaces.data, namespaces.error]);
  useEffect(() => { const timer = setTimeout(() => { setName(filter); setOffset(0); }, 250); return () => clearTimeout(timer); }, [filter]);
  const { data, error, loading } = useInventory(!namespace ? null : { namespace: namespace === '*' ? '' : namespace, name, sort, offset, hidden: hidden.keys, showHidden }, refresh);
  const complete = data?.status === 'complete';
  const names = [...new Set([...(namespaces.data?.namespaces ?? []), ...(namespace && namespace !== '*' ? [namespace] : [])])].sort();
  return <Stack gap="md">
    <Group justify="space-between"><div><Text className="eyebrow">CLUSTER INVENTORY</Text><Title order={1}>Pods</Title><Text c="dimmed" size="sm">Prioritize workload risk.</Text></div><Detection refresh={refresh} /></Group>
    <RiskOverview summary={data?.status !== 'loading' ? data?.summary : undefined} />
    <Paper withBorder p="sm"><Group align="end" gap="sm"><Select label="Namespace" placeholder="Choose a namespace…" data={[...names.map(n => ({ value: n, label: n })), { value: '*', label: 'All namespaces (opt in)' }]} value={namespace} onChange={value => { if (value !== null) { setNamespace(value); setOffset(0); } }} w={220} searchable allowDeselect={false} /><TextInput label="Pod name" placeholder="Find a pod…" value={filter} onChange={e => setFilter(e.currentTarget.value)} style={{ flex: 1, minWidth: 150 }} /><Select label="Prioritize" value={sort} onChange={value => { setSort(value ?? 'risk'); setOffset(0); }} allowDeselect={false} data={[{ value: 'risk', label: 'Highest risk' }, { value: 'review', label: 'Needs review' }, { value: 'name', label: 'Namespace / name' }]} w={180} /><Button variant="light" onClick={() => { setOffset(0); setRefresh(v => v + 1); }} loading={loading}>Refresh</Button></Group></Paper>
    {(namespaces.error || namespaces.data?.state.status !== 'available') && !namespaces.loading && <Alert color="orange" title="Namespace discovery unavailable"><Text size="sm">{namespaces.error || namespaces.data?.state.message} Enter a namespace to read it directly.</Text><TextInput aria-label="Namespace name" value={namespace === '*' ? '' : namespace ?? ''} onChange={e => { setNamespace(e.currentTarget.value.replaceAll('*', '')); setOffset(0); }} /></Alert>}
    <RequestState loading={loading || namespace === null || data?.status === 'loading'} error={error} />
    {data?.status === 'assessing' && <Alert color="blue">Assessing {data.summary.pending} pending pods in the filtered view. Counts are provisional; rows stay in name order until assessment finishes.</Alert>}
    {data?.status === 'error' && <Alert color="red" title="Assessment incomplete">{data.message}</Alert>}
    <Group justify="space-between"><Checkbox label={`Show hidden (${data?.hidden ?? 0})`} checked={showHidden} onChange={e => { setShowHidden(e.currentTarget.checked); setOffset(0); }} /><Text size="xs" c="dimmed">{hidden.persistent ? 'Hiding follows the owning workload · Saved per context' : 'External proxy: hiding applies to this view only'} · Counts cover all filtered pages</Text></Group>
    {hidden.warning && <Alert color="orange">{hidden.warning}</Alert>}
    {data && data.status !== 'loading' && <><Paper withBorder className="table-panel"><Group px="md" py="sm" justify="space-between"><Text size="sm" fw={600}>{data.total} matching pods</Text><Text size="xs" c="dimmed">Higher score = higher risk · ≥ = partial assessment</Text></Group><PodRows pods={data.pods} hidden={hidden} navigate={navigate} />{!data.pods.length && <Text ta="center" p="xl" c="dimmed">No pods match this namespace and filter.</Text>}<Group p="sm" justify="space-between"><Button variant="subtle" disabled={!complete || offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</Button><Text size="xs">{data.total ? data.offset + 1 : 0}–{data.nextOffset} of {data.total} · {complete ? `Snapshot ${new Date(data.capturedAt).toLocaleTimeString()}` : 'Pagination available after assessment'}</Text><Button variant="subtle" disabled={!complete || !data.hasMore} onClick={() => setOffset(data.nextOffset)}>Next</Button></Group></Paper><Availability states={data.states} /></>}
  </Stack>;
}
