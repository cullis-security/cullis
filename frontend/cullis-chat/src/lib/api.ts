/**
 * Browser-side API client. Talks same-origin to:
 *
 *   /api/session/init     — mint the session cookie
 *   /api/session/whoami   — resolved principal (ADR-020 shape)
 *   /v1/models            — model list (Ambassador)
 *   /v1/chat/completions  — chat (Ambassador, sync + SSE)
 *
 * After ADR-019 Phase 8a + 8b the SPA no longer goes through an
 * Astro `/api/proxy/*` translator: ``require_bearer`` on the
 * Ambassador (``cullis_connector/ambassador/auth.py``) accepts
 * either ``Authorization: Bearer`` OR the ``cullis_local_session``
 * cookie, so the browser can hit ``/v1/*`` directly with the cookie
 * the SPA minted via ``/api/session/init``.
 *
 * Topology routing (dev / Frontdesk container / desktop installer)
 * lives outside this file; here every call is a same-origin relative
 * URL and whoever serves the SPA is responsible for routing
 * ``/api/session/*`` and ``/v1/*`` to the Connector.
 */

import { parseSSE, type SSEEvent } from './sse';
import type {
  ChatCompletionRequest,
  ChatCompletionResponse,
  InboxMessage,
  InboxSendRequest,
  InboxSendResponse,
  Model,
  Principal,
} from './types';

/**
 * Inbox base path. The spec at `imp/insurance-demo-spec.md` originally
 * named this `/v1/egress/message/*`; the broker today exposes
 * `/v1/inbox/*` (see `app/inbox/router.py`). Tracked as a BLOCKED:
 * note in the spec — flip this constant when the rename lands and
 * everything else just works.
 */
const INBOX_BASE = '/v1/inbox';

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

/** GET /api/session/whoami — fetches the resolved principal.
 *
 * After Phase 8b-2a both single and shared mode return the same
 * ADR-020 wrapped shape, so this is now a pure passthrough.
 */
export async function whoami(): Promise<{ ok: boolean; principal: Principal }> {
  return jsonFetch<{ ok: boolean; principal: Principal }>('/api/session/whoami');
}

/** GET /v1/models — direct to Ambassador via session cookie auth. */
export async function listModels(): Promise<Model[]> {
  const res = await jsonFetch<{ object: string; data: Model[] }>('/v1/models');
  return res.data;
}

/** POST /v1/chat/completions (non-streaming). Used as a fallback. */
export async function chatCompletion(
  request: ChatCompletionRequest,
): Promise<ChatCompletionResponse> {
  return jsonFetch<ChatCompletionResponse>('/v1/chat/completions', {
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
  const res = await fetch('/v1/chat/completions', {
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

// ─── Inbox surface (ADR-020 Phase 4) ──────────────────────────────────

/** GET /v1/inbox — list messages addressed to the caller. */
export async function listInbox(opts?: {
  since?: string;
  limit?: number;
  includeArchived?: boolean;
}): Promise<InboxMessage[]> {
  const qs = new URLSearchParams();
  if (opts?.since) qs.set('since', opts.since);
  if (opts?.limit !== undefined) qs.set('limit', String(opts.limit));
  if (opts?.includeArchived) qs.set('include_archived', 'true');
  const suffix = qs.toString();
  const url = suffix ? `${INBOX_BASE}?${suffix}` : INBOX_BASE;
  return jsonFetch<InboxMessage[]>(url);
}

/** POST /v1/inbox/send — enqueue a message to a Cullis principal. */
export async function sendInboxMessage(
  req: InboxSendRequest,
): Promise<InboxSendResponse> {
  return jsonFetch<InboxSendResponse>(`${INBOX_BASE}/send`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

/** POST /v1/inbox/{msg_id}/ack — mark delivered. */
export async function ackInboxMessage(
  msgId: string,
  online: boolean = false,
): Promise<{ acked: boolean; msg_id: string }> {
  const url = `${INBOX_BASE}/${encodeURIComponent(msgId)}/ack${online ? '?online=true' : ''}`;
  return jsonFetch<{ acked: boolean; msg_id: string }>(url, { method: 'POST' });
}

/** POST /v1/inbox/{msg_id}/archive — soft hide. */
export async function archiveInboxMessage(
  msgId: string,
): Promise<{ archived: boolean; msg_id: string }> {
  return jsonFetch<{ archived: boolean; msg_id: string }>(
    `${INBOX_BASE}/${encodeURIComponent(msgId)}/archive`,
    { method: 'POST' },
  );
}

export { ApiError, INBOX_BASE };
export type { SSEEvent };
