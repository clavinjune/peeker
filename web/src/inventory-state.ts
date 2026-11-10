import { useContext, useEffect, useRef, useState } from 'react';
import { ClusterContext } from './Cluster';
import type { PodList } from './types';

export function initialNamespace(namespaces: string[]) {
  return namespaces.includes('default') ? 'default' : [...namespaces].sort()[0] ?? 'default';
}

export function rowWindow(count: number, scrollTop: number) {
  const start = Math.max(0, Math.min(count, Math.floor(scrollTop / 80) - 3));
  const end = Math.min(count, start + 14);
  return { start, end, before: start * 80, after: (count - end) * 80 };
}

export type InventoryQuery = { namespace: string; name: string; sort: string; offset: number; hidden: string[]; showHidden: boolean };

export function useInventory(query: InventoryQuery | null, refresh: number) {
  const cluster = useContext(ClusterContext);
  const generation = cluster?.generation;
  const [data, setData] = useState<PodList | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const retained = useRef({ scope: '', refresh: -1, snapshot: '' });
  const body = JSON.stringify(query);
  useEffect(() => {
    if (!generation || body === 'null') { setData(null); setError(''); setLoading(false); return; }
    const query = JSON.parse(body) as InventoryQuery;
    const scope = `${generation}/${query.namespace}`;
    if (retained.current.scope !== scope || retained.current.refresh !== refresh) retained.current = { scope, refresh, snapshot: '' };
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    setData(null); setError(''); setLoading(true);
    const load = async () => {
      try {
        const snapshot = retained.current.snapshot;
        const response = await fetch('/api/pods/query', {
          method: 'POST', signal: abort.signal,
          headers: { 'Content-Type': 'application/json', 'X-Peeker-Context': generation, 'X-Peeker-Action': 'query-pods' },
          body: JSON.stringify({ ...query, all: query.namespace === '', limit: 100, snapshot, refresh: refresh > 0 && !snapshot }),
        });
        const next = await response.json();
        if (!response.ok) throw new Error(next.error || `Request failed: HTTP ${response.status}`);
        if (abort.signal.aborted) return;
        retained.current.snapshot = next.snapshot;
        setData(next as PodList); setLoading(false);
        if (next.status === 'loading' || next.status === 'assessing') timer = setTimeout(() => void load(), 500);
      } catch (e) {
        if (!abort.signal.aborted) { setError(e instanceof Error ? e.message : 'Inventory unavailable'); setLoading(false); }
      }
    };
    void load();
    return () => { abort.abort(); clearTimeout(timer); };
  }, [body, refresh, generation]);
  return { data, error, loading };
}
