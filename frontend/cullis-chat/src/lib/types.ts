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
