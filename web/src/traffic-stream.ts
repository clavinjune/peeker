import type { TrafficView } from './types';

export async function readTraffic(response: Response, update: (view: TrafficView) => void) {
  if (response.headers.get('content-type')?.includes('application/json')) {
    const data = await response.json();
    if (!data.status) throw new Error(data.error || 'Traffic stream unavailable');
    update(data as TrafficView);
    return;
  }
  if (!response.ok || !response.body || !response.headers.get('content-type')?.includes('text/event-stream')) throw new Error('Traffic stream unavailable');
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      let end: number;
      while ((end = buffer.indexOf('\n\n')) >= 0) {
        if (end > 256 * 1024) throw new Error('Traffic update exceeds its size limit');
        const event = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (event.startsWith('data: ')) update(JSON.parse(event.slice(6)) as TrafficView);
      }
      if (buffer.length > 256 * 1024) throw new Error('Traffic update exceeds its size limit');
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
}
