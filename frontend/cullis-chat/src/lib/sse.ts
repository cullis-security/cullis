/**
 * SSE parser for Cullis Chat.
 *
 * `EventSource` cannot speak POST / custom headers, so we drive the
 * stream off `fetch` + `ReadableStream`. Frame format follows the
 * EventSource spec (RFC + WHATWG): events delimited by a blank line,
 * "event:" / "data:" prefixes, optional "id:" / "retry:" we ignore.
 *
 * The Cullis Ambassador emits these event names:
 *   - default (no `event:` line)   chat.completion.chunk
 *   - tool_call_start              { tool: string }
 *   - tool_call_end                { tool: string, latency_ms: number }
 *   - cullis_audit                 AuditTrace
 * plus the literal terminator `data: [DONE]`.
 */

import type { AuditTrace, ChatRole } from './types';

export interface ChatChunk {
  id: string;
  object: 'chat.completion.chunk';
  model: string;
  choices: { index: number; delta: { content?: string; role?: ChatRole }; finish_reason: string | null }[];
  cullis_audit?: AuditTrace;
}

export type SSEEvent =
  | { kind: 'chunk'; chunk: ChatChunk }
  | { kind: 'tool_start'; tool: string }
  | { kind: 'tool_end'; tool: string; latency_ms: number }
  | { kind: 'audit'; audit: AuditTrace }
  | { kind: 'done' }
  | { kind: 'unknown'; raw: string };

export async function* parseSSE(stream: ReadableStream<Uint8Array>, signal?: AbortSignal): AsyncGenerator<SSEEvent> {
  const reader = stream.getReader();
  const decoder = new TextDecoder('utf-8');
  let buf = '';

  try {
    while (true) {
      if (signal?.aborted) {
        await reader.cancel();
        return;
      }
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });

      // Split on blank-line boundary (\n\n). Trailing partial event stays in buf.
      let idx;
      while ((idx = buf.indexOf('\n\n')) !== -1) {
        const block = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const ev = parseEventBlock(block);
        if (ev) yield ev;
      }
    }
    // Flush any tail
    buf += decoder.decode();
    if (buf.trim()) {
      const ev = parseEventBlock(buf);
      if (ev) yield ev;
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* lock may already be released */
    }
  }
}

function parseEventBlock(block: string): SSEEvent | null {
  let event = 'message';
  const dataLines: string[] = [];

  for (const rawLine of block.split('\n')) {
    if (rawLine.startsWith(':')) continue; // comment
    const colon = rawLine.indexOf(':');
    if (colon === -1) continue;
    const field = rawLine.slice(0, colon);
    let value = rawLine.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);

    if (field === 'event') event = value;
    else if (field === 'data') dataLines.push(value);
    // Ignore id / retry / others.
  }

  const data = dataLines.join('\n');

  if (data === '[DONE]') return { kind: 'done' };
  if (!data) return null;

  let payload: unknown;
  try {
    payload = JSON.parse(data);
  } catch {
    return { kind: 'unknown', raw: data };
  }

  switch (event) {
    case 'tool_call_start':
      if (isObj(payload) && typeof payload.tool === 'string') {
        return { kind: 'tool_start', tool: payload.tool };
      }
      return null;
    case 'tool_call_end':
      if (isObj(payload) && typeof payload.tool === 'string' && typeof payload.latency_ms === 'number') {
        return { kind: 'tool_end', tool: payload.tool, latency_ms: payload.latency_ms };
      }
      return null;
    case 'cullis_audit':
      return { kind: 'audit', audit: payload as AuditTrace };
    case 'message':
    default:
      return { kind: 'chunk', chunk: payload as ChatChunk };
  }
}

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object';
}
