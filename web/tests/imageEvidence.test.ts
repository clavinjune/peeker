import { expect, test } from 'bun:test';
import { imageScanFor, type ImageClassification } from '../src/imageEvidence';

test('image evidence binds to the observed digest, not a previously scanned mutable tag', () => {
  const classification: ImageClassification = { status: 'not-distroless', summary: 'Shell found', platform: 'linux/arm64', osPackages: 1, tools: [], limitations: 'Package inventory only', digest: 'example/app@sha256:old' };
  const old = { image: 'example/app:latest', status: 'complete', startedAt: '2026-11-11T12:00:00Z', classification };
  expect(imageScanFor('example/app@sha256:new', [old])).toBeUndefined();
  expect(imageScanFor('example/app:latest', [old])).toBe(old);
  expect(imageScanFor('mirror/app@sha256:old', [old])).toBe(old);
  expect(imageScanFor('example/other:latest', [old])).toBeUndefined();
  const recent = { ...old, startedAt: '2026-11-11T13:00:00Z' };
  expect(imageScanFor('example/app:latest', [old, recent])).toBe(recent);
  expect(imageScanFor('example/app:latest', [{ ...recent, status: 'running' }])).toBeUndefined();
});
