import type { Pod } from './types';

export function rankPods(pods: Pod[], mode: string): Pod[] {
  return [...pods].sort((a, b) => {
    const review = Number(b.risk.unknown > 0) - Number(a.risk.unknown > 0);
    if (mode === 'review' && review) return review;
    if (mode !== 'name' && a.risk.score !== b.risk.score) return b.risk.score - a.risk.score;
    if (mode !== 'name' && review) return review;
    return `${a.namespace}/${a.name}`.localeCompare(`${b.namespace}/${b.name}`);
  });
}
