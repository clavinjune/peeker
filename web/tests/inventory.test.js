import { expect, test } from 'bun:test';
import { createElement } from 'react';
import { renderToString } from 'react-dom/server';
import { MantineProvider } from '@mantine/core';
import { RiskBadge } from '../src/Security';
import { initialNamespace, rowWindow } from '../src/inventory-state';

test('initial scope never implicitly selects every namespace', () => {
  expect(initialNamespace(['zeta', 'default', 'alpha'])).toBe('default');
  expect(initialNamespace(['zeta', 'alpha'])).toBe('alpha');
  expect(initialNamespace([])).toBe('default');
});

test('virtual rows remain bounded and preserve scroll height', () => {
  for (const scroll of [0, 600, 4000, 7400]) {
    const window = rowWindow(100, scroll);
    expect(window.end - window.start).toBeLessThanOrEqual(14);
    expect(window.before + (window.end - window.start) * 80 + window.after).toBe(8000);
    expect(window.end).toBeGreaterThan(window.start);
  }
  expect(rowWindow(0, 0)).toEqual({ start: 0, end: 0, before: 0, after: 0 });
});

test('pending risk never displays a scored zero or no findings', () => {
  const html = renderToString(createElement(MantineProvider, null, createElement(RiskBadge, { risk: { level: 'pending', score: 0, unknown: 0 } }))).replaceAll('<!-- -->', '');
  expect(html).toContain('— · pending');
  expect(html).not.toContain('No findings');
  expect(html).not.toContain('0 ·');
});
