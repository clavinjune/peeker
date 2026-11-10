import { expect, test } from 'bun:test';
import { readTraffic } from '../src/traffic-stream';
import type { TrafficView } from '../src/types';

test('stream decoder handles split UTF-8 and multiple events', async () => {
  const bytes = new TextEncoder().encode('data: {"status":"live","message":"peer → pod"}\n\ndata: {"status":"ended"}\n\n');
  const stream = new ReadableStream({ start(controller) { for (const byte of bytes) controller.enqueue(new Uint8Array([byte])); controller.close(); } });
  const views: TrafficView[] = [];
  await readTraffic(new Response(stream, { headers: { 'content-type': 'text/event-stream' } }), view => views.push(view));
  expect(views.map(view => view.status)).toEqual(['live', 'ended']);
  expect(views[0].message).toBe('peer → pod');
});

test('preflight denial remains explicit and invalid responses fail', async () => {
  const views: TrafficView[] = [];
  await readTraffic(Response.json({ status: 'denied', message: 'Denied' }), view => views.push(view));
  expect(views[0].status).toBe('denied');
  await expect(readTraffic(new Response('<html>'), () => {})).rejects.toThrow('unavailable');
});

test('oversized stream updates are bounded and the reader is canceled', async () => {
  let canceled = false;
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('data: ' + 'x'.repeat(256 * 1024))); }, cancel() { canceled = true; } });
  await expect(readTraffic(new Response(stream, { headers: { 'content-type': 'text/event-stream' } }), () => {})).rejects.toThrow('size limit');
  expect(canceled).toBe(true);
});
