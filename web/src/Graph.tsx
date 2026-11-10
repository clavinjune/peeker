import { useId, useState } from 'react';
import { Badge, Button, Drawer, Group, Paper, Stack, Text, Title } from '@mantine/core';
import { resourceName } from './types';
import type { Evidence, GraphData } from './types';

const colors: Record<string, string> = { allowed: '#087f5b', denied: '#c92a2a', unrestricted: '#4263eb', unknown: '#a66a00', observed: '#087f5b' };

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  return <Stack gap="sm">{evidence.length ? evidence.map((e, i) => <Paper key={i} withBorder p="md">
    <Text fw={600}>{resourceName(e.resource)}</Text><Text size="xs" c="dimmed" ff="monospace">{e.field}</Text>
    <Text size="sm" mt="xs">{e.description}</Text>
  </Paper>) : <Text c="dimmed">Inventory unavailable; no resource-backed conclusion is possible.</Text>}</Stack>;
}

export function Graph({ data, center, topology = false, traffic = false }: { data: GraphData; center: string; topology?: boolean; traffic?: boolean }) {
  const marker = useId().replaceAll(':', '');
  const [selection, setSelection] = useState<{ title: string; evidence: Evidence[] } | null>(null);
  const nodes = data.nodes.slice(0, 22);
  const visible = new Set(nodes.map(n => n.id));
  const edges = data.edges.filter(e => visible.has(e.from) && visible.has(e.to));
  const levels = new Map<string, number>([[center, 0]]);
  for (let i = 0; i < 4; i++) {
    for (const e of edges) {
      if (levels.has(e.to) && !levels.has(e.from)) levels.set(e.from, Math.max(-3, (levels.get(e.to) ?? 0) - 1));
      if (levels.has(e.from) && !levels.has(e.to)) levels.set(e.to, Math.min(2, (levels.get(e.from) ?? 0) + 1));
    }
  }
  const columns = [...new Set(nodes.map(n => levels.get(n.id) ?? 1))].sort((a, b) => a - b);
  const groups = columns.map(level => nodes.filter(n => (levels.get(n.id) ?? 1) === level));
  const width = Math.max(800, columns.length * 270);
  const height = Math.max(290, ...groups.map(g => g.length * 95 + 40));
  const positions = new Map(nodes.map(n => {
    const column = columns.indexOf(levels.get(n.id) ?? 1);
    const index = groups[column].indexOf(n);
    return [n.id, { x: (column + 0.5) * width / columns.length, y: (index + 1) * height / (groups[column].length + 1) }];
  }));
  return <>
    <Group gap="sm" mb="md">
      {!topology && !traffic && <><Badge color="teal" variant="light">Allow rule</Badge><Badge color="red" variant="light">Deny rule / isolated</Badge><Badge color="indigo" variant="light">Not isolated by KNP</Badge></>}
      <Badge color={traffic ? 'teal' : 'yellow'} variant="light">{traffic ? 'Observed HTTP traffic' : topology ? 'Configured relationship' : 'Unknown / partial'}</Badge>
    </Group>
    <div className="graph-canvas">
      <svg viewBox={`0 0 ${width} ${height}`} style={{ minWidth: Math.min(width, 1050) }} aria-label={traffic ? 'Observed pod traffic' : topology ? 'Configuration-derived topology' : 'Network security graph'}>
        <defs>{Object.entries(colors).map(([key, color]) => <marker key={key} id={`${marker}-${key}`} markerWidth="9" markerHeight="7" refX="9" refY="3.5" orient="auto"><polygon points="0 0, 9 3.5, 0 7" fill={color} /></marker>)}</defs>
        {edges.map(e => {
          const from = positions.get(e.from)!; const to = positions.get(e.to)!;
          const forward = to.x >= from.x; const start = from.x + (forward ? 108 : -108); const end = to.x + (forward ? -112 : 112);
          const d = `M ${start} ${from.y} C ${(start + end) / 2} ${from.y}, ${(start + end) / 2} ${to.y}, ${end} ${to.y}`;
          return <g key={e.id} role="button" tabIndex={0} aria-label={`${e.status}: ${e.label}`} onClick={() => setSelection({ title: e.label, evidence: e.evidence ?? [] })} onKeyDown={event => { if (event.key === 'Enter') setSelection({ title: e.label, evidence: e.evidence ?? [] }); }}>
            <path d={d} stroke="transparent" strokeWidth="18" fill="none" />
            <path d={d} stroke={colors[e.status] ?? colors.unknown} strokeWidth="2" strokeDasharray={e.status === 'unknown' ? '5 5' : undefined} fill="none" markerEnd={`url(#${marker}-${e.status in colors ? e.status : 'unknown'})`} />
            <title>{e.label}</title>
          </g>;
        })}
        {nodes.map(n => {
          const p = positions.get(n.id)!;
          const open = () => setSelection({ title: n.label, evidence: data.edges.filter(e => e.to === n.id || e.from === n.id).flatMap(e => e.evidence ?? []) });
          const label = n.label.length > 30 ? `${n.label.slice(0, 29)}…` : n.label;
          return <g key={n.id} transform={`translate(${p.x},${p.y})`} role="button" tabIndex={0} aria-label={n.label} onClick={open} onKeyDown={event => { if (event.key === 'Enter') open(); }}>
            <rect x="-108" y="-31" width="216" height="62" rx="9" fill={n.id === center ? '#edf2ff' : 'white'} stroke={n.id === center ? '#4263eb' : '#ced4da'} strokeWidth={n.id === center ? 2 : 1} />
            <text textAnchor="middle" y="-7" fontSize="10" fill="#64748b">{n.id === center ? 'SELECTED POD' : n.kind.toUpperCase()}</text>
            <text textAnchor="middle" y="13" fontSize="11" fill="#182235">{label}</text><title>{n.label}</title>
          </g>;
        })}
      </svg>
    </div>
    {nodes.length < data.nodes.length && <Text size="sm" c="dimmed">Showing {nodes.length} of {data.nodes.length} nodes. All relationships are available below.</Text>}
    <Text size="xs" c="dimmed" mt="sm">{traffic ? 'Select an edge to inspect request counts, errors and mean duration. Arrows follow the request direction observed by this sidecar.' : 'Select a node or edge to inspect its resource evidence. Arrows describe configuration, not measured traffic or proven packet delivery.'}</Text>
    <details className="edge-list"><summary>All {data.edges.length} relationships and evidence</summary><Stack gap="xs" mt="sm">{data.edges.map(e => <Button key={e.id} justify="start" variant="subtle" color={e.status === 'denied' ? 'red' : 'gray'} onClick={() => setSelection({ title: e.label, evidence: e.evidence ?? [] })}>{e.status} · {e.label} · {e.evidence?.[0]?.resource.name ?? 'inventory unavailable'}</Button>)}</Stack></details>
    <Drawer opened={selection !== null} onClose={() => setSelection(null)} position="right" size="lg" title="Resource evidence">
      <Title order={4} mb="lg">{selection?.title}</Title><EvidenceList evidence={selection?.evidence ?? []} />
    </Drawer>
  </>;
}
