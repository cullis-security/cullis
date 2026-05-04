/**
 * Browser-side API client. Talks only to same-origin /api/* endpoints
 * (the Astro server proxies to the Ambassador). Never reaches out to
 * :7777 directly; that boundary lives in the cookie + middleware.
 */

import { parseSSE, type SSEEvent } from './sse';
import type {
  ChatCompletionRequest,
  ChatCompletionResponse,
  Model,
  Principal,
} from './types';

const PROXY_ROOT = '/api/proxy';

class ApiError extends Error {
  constructor(public status: number, public payload: unknown) {
    super(`api error ${status}`);
  }
}

async function jsonFetch<T>(input: string, init?: RequestInit): Promise<T> {
  const res = await fetch(input, {
    credentials: 'same-origin',
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    let payload: unknown = null;
    try {
      payload = await res.json();
    } catch {
      payload = await res.text();
    }
    throw new ApiError(res.status, payload);
  }
  return (await res.json()) as T;
}

/** POST /api/session/init — must be called once at boot to mint the cookie. */
export async function initSession(): Promise<{ ok: boolean; ttl: number }> {
  return jsonFetch('/api/session/init', { method: 'POST', body: '{}' });
}

/** GET /api/session/whoami — fetches the resolved principal. */
export async function whoami(): Promise<{ ok: true; principal: Principal } | Principal> {
  // The server returns either {ok, principal} (fallback) or the principal
  // shape directly (forwarded from Ambassador /v1/whoami). Normalise.
  const raw = await jsonFetch<unknown>('/api/session/whoami');
  if (raw && typeof raw === 'object' && 'principal' in (raw as Record<string, unknown>)) {
    return raw as { ok: true; principal: Principal };
  }
  return raw as Principal;
}

/** GET /v1/models via proxy. */
export async function listModels(): Promise<Model[]> {
  const res = await jsonFetch<{ object: string; data: Model[] }>(
    `${PROXY_ROOT}/v1/models`,
  );
  return res.data;
}

/** POST /v1/chat/completions (non-streaming). Used as a fallback. */
export async function chatCompletion(
  request: ChatCompletionRequest,
): Promise<ChatCompletionResponse> {
  return jsonFetch<ChatCompletionResponse>(`${PROXY_ROOT}/v1/chat/completions`, {
    method: 'POST',
    body: JSON.stringify({ ...request, stream: false }),
  });
}

/**
 * POST /v1/chat/completions with `stream: true`. Yields SSE events
 * (chunk, tool_start, tool_end, audit, done) until the stream closes
 * or `signal` aborts.
 */
export async function* chatCompletionStream(
  request: ChatCompletionRequest,
  signal?: AbortSignal,
): AsyncGenerator<SSEEvent> {
  const res = await fetch(`${PROXY_ROOT}/v1/chat/completions`, {
    method: 'POST',
    credentials: 'same-origin',
    signal,
    headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
    body: JSON.stringify({ ...request, stream: true }),
  });
  if (!res.ok || !res.body) {
    let payload: unknown = null;
    try {
      payload = await res.json();
    } catch {
      try {
        payload = await res.text();
      } catch {
        /* ignore */
      }
    }
    throw new ApiError(res.status, payload);
  }
  yield* parseSSE(res.body, signal);
}

export { ApiError };
export type { SSEEvent };
