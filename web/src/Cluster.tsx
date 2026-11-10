import { createContext, useContext, useEffect, useRef, useState } from 'react';
import { Badge, Button, Group, Select } from '@mantine/core';
import type { ContextInfo } from './types';

export const ClusterContext = createContext<ContextInfo | null>(null);

export function useAPI<T>(url: string, refresh: number) {
  const cluster = useContext(ClusterContext);
  const generation = cluster?.generation;
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    if (!generation) return;
    const abort = new AbortController(); setLoading(true); setError(''); setData(null);
    fetch(`${url}${refresh > 0 ? `${url.includes('?') ? '&' : '?'}refresh=true` : ''}`, { signal: abort.signal, headers: { 'X-Peeker-Context': generation } }).then(async response => {
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || `Request failed: HTTP ${response.status}`);
      if (!abort.signal.aborted) setData(body as T);
    }).catch((e: unknown) => { if (!abort.signal.aborted) setError(e instanceof Error ? e.message : 'Request failed'); }).finally(() => { if (!abort.signal.aborted) setLoading(false); });
    return () => abort.abort();
  }, [url, refresh, generation]);
  return { data, error, loading };
}

export function useContexts() {
  const [info, setInfo] = useState<ContextInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const selecting = useRef<AbortController | null>(null);
  useEffect(() => () => selecting.current?.abort(), []);
  useEffect(() => {
    if (busy) return;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const load = async (discover: boolean) => {
      try {
        const response = await fetch(`/api/contexts${discover ? '?refresh=true' : ''}`, { signal: abort.signal });
        if (!response.ok) throw new Error('Context list unavailable. Check that Peeker is running.');
        const next = await response.json() as ContextInfo;
        if (!abort.signal.aborted) setInfo(next);
      } catch (e) {
        if (!abort.signal.aborted) { setInfo(null); setError(e instanceof Error ? e.message : 'Context list unavailable'); }
      } finally {
        if (!abort.signal.aborted) timer = setTimeout(() => load(false), 3000);
      }
    };
    void load(refresh > 0);
    return () => { abort.abort(); clearTimeout(timer); };
  }, [busy, refresh]);
  const select = async (name: string) => {
    if (selecting.current) return;
    const abort = new AbortController(); selecting.current = abort;
    setBusy(true); setError('');
    try {
      const response = await fetch('/api/context', { method: 'POST', signal: abort.signal, headers: { 'Content-Type': 'application/json', 'X-Peeker-Action': 'select-context' }, body: JSON.stringify({ name }) });
      const body = await response.json();
      if (!abort.signal.aborted) {
        setInfo(response.ok ? body : body.state ?? null);
        if (!response.ok) setError(body.error || 'Context switch failed');
      }
    } catch {
      if (!abort.signal.aborted) { setInfo(null); setError('Context switch failed. Refresh the context list to reconnect.'); }
    } finally {
      selecting.current = null;
      if (!abort.signal.aborted) setBusy(false);
    }
  };
  return { info, busy, error, select, refresh: () => { setError(''); setRefresh(value => value + 1); } };
}

export function ContextControls({ state }: { state: ReturnType<typeof useContexts> }) {
  const { info, busy, select } = state;
  if (info?.mode === 'external') return <Badge color="gray">External proxy</Badge>;
  return <Group gap="xs" wrap="nowrap"><Select aria-label="Kubernetes context" placeholder="Choose context…" data={info?.contexts ?? []} value={info?.current || null} onChange={value => { if (value) void select(value); }} disabled={busy} searchable allowDeselect={false} w={240} /><Button size="xs" variant="subtle" disabled={busy || !info?.current} onClick={() => { if (info?.current) void select(info.current); }}>Reconnect</Button><Button size="xs" variant="subtle" disabled={busy} onClick={state.refresh}>Reload contexts</Button></Group>;
}
