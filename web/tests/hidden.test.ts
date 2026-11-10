import { expect, test } from 'bun:test';
import { hiddenKey, hiddenStorageKey, parseHidden } from '../src/hidden-preferences';
import type { Pod } from '../src/types';

const pod = (name: string, status = 'resolved'): Pod => ({ kind: 'Pod', name, uid: name, namespace: 'demo', labels: {}, node: '', phase: '', ip: '', sidecar: false, ready: 1, containers: 1, risk: { score: 0, level: '', findings: 0, checked: 1, unknown: 0, topFinding: '' }, ownership: { status, owners: [{ kind: 'ReplicaSet', name: `${name}-rs`, apiVersion: 'apps/v1' }, { kind: 'Deployment', name: 'web', apiVersion: 'apps/v1' }] } });

test('workload hiding survives pod replacement and separates namespace, kind and context', () => {
  const first = pod('first'), replacement = pod('replacement');
  expect(hiddenKey(first)).toBe(hiddenKey(replacement));
  expect(hiddenKey({ ...first, namespace: 'other' })).not.toBe(hiddenKey(first));
  expect(hiddenKey({ ...first, ownership: { status: 'resolved', owners: [{ kind: 'DaemonSet', name: 'web', apiVersion: 'apps/v1' }] } })).not.toBe(hiddenKey(first));
  expect(hiddenStorageKey('one')).not.toBe(hiddenStorageKey('two'));
  const saved = parseHidden(JSON.stringify([hiddenKey(first)]));
  expect(saved.has(hiddenKey(replacement))).toBe(true);
  saved.delete(hiddenKey(replacement));
  expect(saved.size).toBe(0);
});

test('unresolved ownership and standalone pods use exact pod instances', () => {
  for (const status of ['unresolved', 'standalone']) {
    expect(hiddenKey(pod('first', status))).not.toBe(hiddenKey(pod('replacement', status)));
    expect(hiddenKey(pod('first', status))).not.toBe(hiddenKey({ ...pod('first', status), uid: 'new' }));
  }
});

test('stored hiding preferences are bounded and validated', () => {
  expect(parseHidden(null).size).toBe(0);
  for (const raw of ['{', '{}', '[1]', JSON.stringify(Array(4097).fill('a')), JSON.stringify(['a'.repeat(4097)]), ' '.repeat(1024 * 1024 + 1)]) expect(() => parseHidden(raw)).toThrow();
});
