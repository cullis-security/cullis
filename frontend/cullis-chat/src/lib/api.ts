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
  ConversationDetail,
  ConversationSummary,
  InboxMessage,
  InboxSendRequest,
  InboxSendResponse,
  Model,
  Principal,
  StoredMessage,
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

/** Source of the model list the Ambassador returned.
 *
 * `live` — the Mastio answered and the list reflects the org's
 * configured AI providers (Anthropic catalog + dynamic Ollama tags +
 * future Vertex/Bedrock/etc).
 *
 * `fallback` — the Mastio call failed (network, mTLS, no cert, etc.)
 * and the dropdown is showing the hardcoded `advertised_models`
 * compiled-in defaults. The SPA renders a warning so the user
 * understands why "the model I configured isn't here".
 */
export type ModelsSource = 'live' | 'fallback';

export interface ModelsResult {
  data: Model[];
  source: ModelsSource;
  error?: string;
}

/** GET /v1/models — direct to Ambassador via session cookie auth.
 *
 * The Ambassador embeds a `cullis_meta.source` discriminator in the
 * response (additive to the OpenAI envelope, ignored by upstream
 * clients). When the live Mastio fetch fails the ambassador returns
 * the hardcoded `advertised_models` with `source: "fallback"`; the
 * SPA surfaces that to the user instead of silently lying.
 */
export async function listModels(): Promise<ModelsResult> {
  const res = await jsonFetch<{
    object: string;
    data: Model[];
    cullis_meta?: { source?: string; error?: string };
  }>('/v1/models');
  const rawSource = res.cullis_meta?.source;
  const source: ModelsSource = rawSource === 'live' ? 'live' : 'fallback';
  // Legacy ambassador builds (pre-#657) don't ship cullis_meta — treat
  // the missing field as `live` to avoid spurious warnings on a stack
  // that simply hasn't been upgraded yet.
  const inferred: ModelsSource = rawSource === undefined ? 'live' : source;
  return {
    data: res.data,
    source: inferred,
    error: res.cullis_meta?.error,
  };
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

// ─── Conversation history (Sprint 1 Step 6 PR-B) ─────────────────────

const CONVERSATIONS_BASE = '/v1/conversations';

/** GET /v1/conversations, sidebar list, principal-scoped. */
export async function listConversations(
  opts?: { limit?: number; offset?: number },
): Promise<ConversationSummary[]> {
  const qs = new URLSearchParams();
  if (opts?.limit !== undefined) qs.set('limit', String(opts.limit));
  if (opts?.offset !== undefined) qs.set('offset', String(opts.offset));
  const suffix = qs.toString();
  const url = suffix ? `${CONVERSATIONS_BASE}?${suffix}` : CONVERSATIONS_BASE;
  return jsonFetch<ConversationSummary[]>(url);
}

/** POST /v1/conversations, create empty conversation. */
export async function createConversation(): Promise<ConversationSummary> {
  return jsonFetch<ConversationSummary>(CONVERSATIONS_BASE, {
    method: 'POST',
    body: '{}',
  });
}

/** GET /v1/conversations/{id}, fetch one + its messages. */
export async function getConversation(id: string): Promise<ConversationDetail> {
  return jsonFetch<ConversationDetail>(
    `${CONVERSATIONS_BASE}/${encodeURIComponent(id)}`,
  );
}

/** PATCH /v1/conversations/{id}, rename title. */
export async function renameConversation(
  id: string, title: string | null,
): Promise<ConversationSummary> {
  return jsonFetch<ConversationSummary>(
    `${CONVERSATIONS_BASE}/${encodeURIComponent(id)}`,
    { method: 'PATCH', body: JSON.stringify({ title }) },
  );
}

/** DELETE /v1/conversations/{id}, soft delete. */
export async function deleteConversation(id: string): Promise<void> {
  const res = await fetch(
    `${CONVERSATIONS_BASE}/${encodeURIComponent(id)}`,
    { method: 'DELETE', credentials: 'same-origin' },
  );
  if (!res.ok && res.status !== 204) {
    throw new ApiError(res.status, await res.text());
  }
}

/** POST /v1/conversations/{id}/messages, append one message. */
export async function appendConversationMessage(
  id: string,
  msg: {
    role: 'user' | 'assistant' | 'tool' | 'system';
    content: string;
    tool_calls?: Array<{ name: string; latency_ms?: number; status?: string }>;
    trace_id?: string;
  },
): Promise<StoredMessage> {
  return jsonFetch<StoredMessage>(
    `${CONVERSATIONS_BASE}/${encodeURIComponent(id)}/messages`,
    { method: 'POST', body: JSON.stringify(msg) },
  );
}

export { ApiError, INBOX_BASE };
export type { SSEEvent };
