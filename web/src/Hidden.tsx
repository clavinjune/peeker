import { useContext, useState } from 'react';
import { ClusterContext } from './Cluster';
import { hiddenKey, hiddenStorageKey, parseHidden } from './hidden-preferences';
import type { Pod } from './types';

export function useHidden() {
  const cluster = useContext(ClusterContext);
  const storageKey = cluster?.mode === 'managed' ? hiddenStorageKey(cluster.current) : '';
  const [initial] = useState(() => {
    try { return { keys: parseHidden(storageKey ? localStorage.getItem(storageKey) : null), warning: '' }; }
    catch { return { keys: new Set<string>(), warning: 'Saved hiding preferences are unavailable. Changes will apply to this view until storage is available.' }; }
  });
  const [keys, setKeys] = useState(initial.keys);
  const [warning, setWarning] = useState(initial.warning);
  const toggle = (pod: Pod, hidden: boolean) => {
    const next = new Set(keys);
    if (hidden) next.add(hiddenKey(pod)); else next.delete(hiddenKey(pod));
    setKeys(next);
    if (!storageKey) return;
    try {
      const raw = JSON.stringify([...next]);
      parseHidden(raw);
      localStorage.setItem(storageKey, raw);
      setWarning('');
    } catch { setWarning('Hiding applies to this view, but could not be saved in this browser.'); }
  };
  return { keys: [...keys], has: (pod: Pod) => keys.has(hiddenKey(pod)), toggle, warning, persistent: !!storageKey };
}
