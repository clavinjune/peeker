import { Accordion, Badge, Group, Paper, SimpleGrid, Stack, Text, Tooltip } from '@mantine/core';
import { EvidenceList } from './Graph';
import { resourceName } from './types';
import type { InventorySummary, Risk, SecurityReport } from './types';

const colors: Record<string, string> = { critical: 'red', high: 'orange', medium: 'yellow', low: 'blue', none: 'teal', unknown: 'gray', pending: 'gray' };

export function RiskBadge({ risk }: { risk: Risk }) {
  const score = risk.level === 'unknown' || risk.level === 'pending' ? '—' : `${risk.unknown > 0 ? '≥' : ''}${risk.score}`;
  const label = risk.level === 'none' ? 'No findings' : risk.level === 'unknown' ? 'Unrated' : risk.level;
  return <Tooltip multiline w={280} label="Configuration risk, 0–100. Higher is more severe. Partial scores are a lower bound; no findings does not guarantee security."><Badge variant="light" color={colors[risk.level]} size="lg" className="risk-badge">{score} · {label}</Badge></Tooltip>;
}

export function RiskOverview({ summary }: { summary?: InventorySummary }) {
  const stats = [
    ['Pods', summary?.total, 'dark'],
    ['Critical', summary?.critical, 'red'],
    ['High', summary?.high, 'orange'],
    ['Need review', summary?.review, 'gray'],
  ] as const;
  return <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="sm">{stats.map(([label, count, color]) => <Paper key={label} withBorder p="sm"><Group justify="space-between"><Text size="sm" c="dimmed">{label}</Text><Text fw={700} size="xl" c={color}>{count ?? '—'}</Text></Group></Paper>)}</SimpleGrid>;
}

export function SecurityFindings({ report }: { report: SecurityReport }) {
  const { risk } = report;
  const gaps = [...new Map(report.gaps.flatMap(g => g.evidence).map(e => [`${resourceName(e.resource)}:${e.field}:${e.description}`, e])).values()];
  return <Stack gap="sm">
    <Paper withBorder p="md"><Group justify="space-between"><Group><RiskBadge risk={risk} /><Text size="sm">{risk.findings} findings</Text></Group><Text size="xs" c="dimmed">{risk.checked} checks evaluated · {risk.unknown} unknown</Text></Group><Text size="xs" c="dimmed" mt="xs">Identity: {report.serviceAccount} · Pod hardening + RBAC + deny-by-default networking · Risk model v1</Text></Paper>
    {!report.findings.length && <Text size="sm" c="dimmed">{risk.unknown ? 'Assessment incomplete. Review the coverage gaps below.' : 'No findings in the supported checks.'}</Text>}
    <Accordion variant="separated">{report.findings.map(f => <Accordion.Item key={f.id} value={f.id}><Accordion.Control><Group justify="space-between" pr="sm"><Text size="sm" fw={500}>{f.title}</Text><Badge size="sm" color={colors[f.severity]} variant="light">{f.severity}</Badge></Group></Accordion.Control><Accordion.Panel><Text size="sm">{f.summary}</Text><Text size="sm" mt="sm"><strong>Recommended action:</strong> {f.remediation}</Text><details><summary>Technical evidence ({f.evidence.length})</summary><EvidenceList evidence={f.evidence} /></details></Accordion.Panel></Accordion.Item>)}</Accordion>
    {gaps.length > 0 && <details className="coverage-gap"><summary>{risk.unknown} checks need more information</summary><EvidenceList evidence={gaps} /></details>}
    <details><summary>How scoring works</summary><Text size="sm" c="dimmed">Critical: 80–100 · High: 50–79 · Medium: 20–49 · Low: 5–19. The most severe finding sets the band; additional distinct findings increase the score within it. Repeated containers do not inflate the score. ≥ means incomplete coverage. Deny-by-default is expected for both directions across Kubernetes and Cilium policies; missing isolation and supported broad allowances are medium findings. Unresolved Cilium deny overlap remains unknown. Missing Istio sidecars are medium findings when expected (-expect-istio=false disables that expectation). Image vulnerabilities and actual runtime enforcement are outside this score.</Text></details>
  </Stack>;
}
