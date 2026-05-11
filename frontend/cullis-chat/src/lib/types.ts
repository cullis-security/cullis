/**
 * Shared types for Cullis Chat. Used by both the React island and
 * the Astro server-side endpoints (where applicable).
 */

/** ADR-020 — three principal categories. */
export type PrincipalType = 'user' | 'agent' | 'workload';

export interface Principal {
  spiffe_id: string | null;
  principal_type: PrincipalType;
  name: string;
  org: string;
  trust_domain: string | null;
}

export type ChatRole = 'user' | 'assistant' | 'system' | 'tool';

export interface ToolCallEvent {
  name: string;
  status: 'pending' | 'done';
  latency_ms?: number;
}

export interface ChatMessage {
  id: string;
  role: ChatRole;
  content: string;
  trace_id?: string;
  audit?: AuditTrace;
  /** ms since epoch */
  createdAt: number;
  /** Streaming: server still appending content. */
  pending?: boolean;
  /** Tool calls observed during this turn, in arrival order. */
  toolCalls?: ToolCallEvent[];
  /** User clicked Stop while this assistant turn was streaming. */
  cancelled?: boolean;
  /** Non-fatal failure during streaming. Surfaced inline next to the partial
   *  content with a Retry button. Clears on retry. */
  error?: string;
}

export interface ToolCall {
  name: string;
  latency_ms?: number;
  args?: Record<string, unknown>;
  result_preview?: string;
}

export interface AuditTrace {
  trace_id: string;
  latency_ms: number;
  tools: ToolCall[];
  principal?: Pick<Principal, 'spiffe_id' | 'principal_type'>;
}

export interface Model {
  id: string;
  object?: string;
  owned_by?: string;
}

export interface ChatCompletionRequest {
  model: string;
  messages: { role: ChatRole; content: string }[];
  stream?: boolean;
}

export interface ChatCompletionResponse {
  id: string;
  object: string;
  model: string;
  choices: { index: number; message: { role: ChatRole; content: string }; finish_reason: string }[];
  cullis_audit?: AuditTrace;
}

/**
 * ADR-020 Phase 4 — REST inbox surface.
 *
 * Mirrors `app.inbox.router.InboxItem` (broker side). Field shape is
 * stable across single and shared mode: only `sender_principal_type`
 * may differ between flows (user/agent/workload).
 */
export interface InboxMessage {
  msg_id: string;
  sender_org_id: string;
  sender_principal_type: PrincipalType;
  sender_name: string;
  subject: string | null;
  body: string;
  delivery_state: 'pending' | 'delivered' | 'archived' | string;
  consent_id: string | null;
  enqueued_at: string;
  delivered_at: string | null;
  ttl_expires_at: string;
}

export interface InboxSendRequest {
  recipient_org_id: string;
  recipient_principal_type: PrincipalType;
  recipient_name: string;
  body: string;
  subject?: string;
  idempotency_key?: string;
}

export interface InboxSendResponse {
  msg_id: string;
  inserted: boolean;
  quadrant: string;
}

/** Inbox UI tabs — drives client-side filtering, not a server param. */
export type InboxTab = 'all' | 'unread' | 'sent' | 'drafts';
