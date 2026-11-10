import type { Pod } from './types';

export function hiddenKey(pod: Pod): string {
  const owner = pod.ownership.status === 'resolved' ? pod.ownership.owners.at(-1) : undefined;
  if (owner) return JSON.stringify([pod.namespace ?? '', owner.apiVersion?.split('/')[0] ?? '', owner.kind, owner.name]);
  return JSON.stringify([pod.namespace ?? '', '', 'Pod', pod.name, pod.uid ?? '']);
}

export function hiddenStorageKey(context: string): string {
  return `peeker.hidden.v1:${JSON.stringify(context)}`;
}

export function parseHidden(raw: string | null): Set<string> {
  if (!raw) return new Set();
  if (raw.length > 1024 * 1024) throw new Error('Hidden preferences exceed the storage limit.');
  const values: unknown = JSON.parse(raw);
  if (!Array.isArray(values) || values.length > 4096 || values.some(value => typeof value !== 'string' || value.length > 4096)) throw new Error('Hidden preferences could not be read.');
  return new Set(values);
}
