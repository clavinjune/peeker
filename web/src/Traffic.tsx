import { useContext, useEffect, useState } from 'react';
import { Alert, Badge, Button, Group, Paper, Stack, Text, Title } from '@mantine/core';
import { Graph } from './Graph';
import { readTraffic } from './traffic-stream';
import { ClusterContext } from './Cluster';
import type { Pod, TrafficView } from './types';

export function Traffic({ pod }: { pod: Pod }) {
  const generation = useContext(ClusterContext)?.generation ?? '';
  const [session, setSession] = useState(0);
  const [active, setActive] = useState(true);
  const [view, setView] = useState<TrafficView | null>(null);
  useEffect(() => {
    if (!pod.sidecar || !active) return;
    const abort = new AbortController();
    setView(null);
    const url = `/api/pods/${encodeURIComponent(pod.namespace ?? '')}/${encodeURIComponent(pod.name)}/traffic?uid=${encodeURIComponent(pod.uid ?? '')}`;
    fetch(url, { signal: abort.signal, headers: { 'X-Peeker-Context': generation } }).then(response => readTraffic(response, data => {
      if (!abort.signal.aborted) setView(data);
    })).then(() => {
      if (!abort.signal.aborted) setView(prior => prior && ['live', 'listening'].includes(prior.status) ? { ...prior, status: 'disconnected', message: 'The stream disconnected. Start a new session to reconnect.' } : prior);
    }).catch(() => {
      if (!abort.signal.aborted) setView(prior => ({ ...(prior ?? { requests: 0, errors: 0, ignored: 0, dropped: 0, startedAt: '', graph: { nodes: [], edges: [] } }), status: 'disconnected', message: 'Traffic stream unavailable or disconnected. Check the proxy, then start a new session.' }));
    });
    return () => abort.abort();
  }, [pod.namespace, pod.name, pod.uid, pod.sidecar, session, active, generation]);
  if (!pod.sidecar) return <Alert color="gray" title="Live traffic unavailable">istio-proxy isn't there. This pod has no Istio sidecar to observe.</Alert>;
  const status = active ? view?.status ?? 'connecting' : 'paused';
  return <Stack gap="md"><Group justify="space-between"><div><Title order={4}>Live pod traffic</Title><Text size="sm" c="dimmed">Completed HTTP requests observed by this pod’s istio-proxy.</Text></div><Group gap="xs"><Badge color={status === 'live' ? 'teal' : 'gray'}>{status}</Badge><Button size="xs" variant="light" onClick={() => { setActive(true); setSession(value => value + 1); }}>New session</Button><Button size="xs" variant="subtle" disabled={!active} onClick={() => setActive(false)}>Pause</Button></Group></Group>
    <Alert color={status === 'denied' ? 'orange' : 'gray'}>{active ? view?.message ?? 'Connecting to the sidecar…' : 'Observation paused. Start a new session to resume.'}</Alert>
    {view && view.graph?.nodes?.length > 0 && <Paper withBorder p="lg"><Group mb="md"><Badge variant="light">{view.requests} requests</Badge><Badge variant="light" color={view.errors ? 'orange' : 'gray'}>{view.errors} errors</Badge><Text size="xs" c="dimmed">Since {new Date(view.startedAt).toLocaleTimeString()}</Text></Group><Graph data={view.graph} center={`Pod/${pod.namespace}/${pod.name}`} traffic /></Paper>}
    <Text size="xs" c="dimmed">One sidecar’s view, updated each second. Up to five minutes per session; counts reset on reconnect. Other workloads’ downstream traffic is outside this view. Errors include HTTP 4xx/5xx and proxy failures.</Text>
    <details><summary>Coverage and limits</summary><Text size="sm" mt="xs">Structured JSON access logging must be enabled. Only inbound/outbound HTTP clusters are recognized; TCP, passthrough and startup logs are excluded. Peer identity uses unique pod IPs at session start; unresolved or shared IPs remain unknown. No request URLs, headers or raw logs are sent to the browser. Up to 64 relationships, 100,000 lines and 16 MiB are processed. {view?.ignored ?? 0} unrecognized lines; {view?.dropped ?? 0} requests omitted by the relationship limit.</Text></details>
  </Stack>;
}
