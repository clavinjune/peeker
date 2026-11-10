import { Accordion, Alert, Badge, Group, Loader, Paper, Stack, Text } from '@mantine/core';
import { useAPI } from './Cluster';
import type { Capabilities, State } from './types';

export function Detection({ refresh }: { refresh: number }) {
  const { data, loading } = useAPI<Capabilities>('/api/capabilities', refresh);
  return <Group gap="xs"><Badge variant="light" color="teal">Read only</Badge>{loading ? <Badge color="gray" variant="light">Detecting networking…</Badge> : <>{data?.istio === 'detected' && <Badge variant="light" color="indigo" title="networking.istio.io API group is registered">Istio detected</Badge>}{data?.cilium === 'detected' && <Badge variant="light" color="cyan" title="cilium.io API group is registered">Cilium detected</Badge>}{(!data || data.istio === 'unknown' || data.cilium === 'unknown') && <Badge variant="light" color="orange" title="API discovery unavailable; installed networking cannot be determined">Networking detection unavailable</Badge>}</>}</Group>;
}

export function Availability({ states }: { states: State[] }) {
  const problems = states.filter(s => s.status !== 'available');
  return <Accordion variant="separated"><Accordion.Item value="apis"><Accordion.Control><Group><Text size="sm">API availability</Text><Badge color={problems.some(p => p.status !== 'missing-api') ? 'orange' : 'gray'} variant="light">{states.length - problems.length}/{states.length} readable</Badge></Group></Accordion.Control>
    <Accordion.Panel><Stack gap="xs">{states.map(s => <Group key={s.resource} justify="space-between"><Text size="sm">{s.resource}</Text><Badge color={s.status === 'available' ? 'teal' : s.status === 'missing-api' ? 'gray' : 'orange'}>{s.status}</Badge>{s.message && <Text size="xs" c="dimmed" w="100%">{s.message}</Text>}</Group>)}</Stack></Accordion.Panel>
  </Accordion.Item></Accordion>;
}

export function RequestState({ loading, error }: { loading: boolean; error: string }) {
  if (loading) return <Paper p="xl" withBorder><Group><Loader size="sm" /><Text>Reading cluster resources…</Text></Group></Paper>;
  if (error) return <Alert color="red" title="Cluster data unavailable">{error}<Text size="sm" mt="sm">This is an inaccessible resource, not an empty cluster. Check the read-only proxy and use Refresh to retry.</Text></Alert>;
  return null;
}
