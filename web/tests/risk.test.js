import { expect, test } from 'bun:test';
import { rankPods } from '../src/risk';

const pod = (name, score, unknown = 0) => ({ name, namespace: 'demo', risk: { score, unknown } });

test('highest risk leads and incomplete zero is never ranked as a verified zero', () => {
  const pods = [pod('clean', 0), pod('partial', 0, 6), pod('high', 55), pod('critical', 80)];
  expect(rankPods(pods, 'risk').map(p => p.name)).toEqual(['critical', 'high', 'partial', 'clean']);
  expect(pods[0].name).toBe('clean');
});

test('review mode prioritizes coverage gaps and name mode stays alphabetical', () => {
  const pods = [pod('critical', 80), pod('partial', 20, 2), pod('another', 5)];
  expect(rankPods(pods, 'review').map(p => p.name)).toEqual(['partial', 'critical', 'another']);
  expect(rankPods(pods, 'name').map(p => p.name)).toEqual(['another', 'critical', 'partial']);
});
