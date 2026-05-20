/**
 * TypeScript interfaces for the Agent Trust Network API.
 *
 * These mirror the Python Pydantic models in app/auth/models.py and
 * app/broker/models.py, plus additional types for the SDK client.
 */

// ── Auth ──────────────────────────────────────────────────────────

/** JWT payload issued by the broker after x509 + DPoP authentication. */
export interface TokenPayload {
  /** SPIFFE ID — spiffe://trust-domain/org/agent */
  sub: string;
  /** Internal ID — org::agent (DB primary key) */
  agent_id: string;
  /** Organization ID */
  org: string;
  /** Unix timestamp expiry */
  exp: number;
  /** Unix timestamp issued-at */
  iat: number;
  /** JWT ID — replay protection */
  jti: string;
  /** Capability scope from approved binding */
  scope: string[];
  /** DPoP confirmation: { jkt: "<jwk-thumbprint>" } */
  cnf?: { jkt: string } | null;
  /** Token type discriminator */
  token_type?: string;
  /** Actor claim for delegation */
  act?: Record<string, unknown>;
  /** Transaction type */
  txn_type?: string;
}

export interface TokenRequest {
  client_assertion: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// ── Sessions ──────────────────────────────────────────────────────

export type SessionStatusValue = "pending" | "active" | "closed" | "denied";

export interface SessionRequest {
  target_agent_id: string;
  target_org_id: string;
  requested_capabilities: string[];
  context?: Record<string, unknown>;
}

export interface SessionResponse {
  session_id: string;
  status: SessionStatusValue;
  initiator_agent_id: string;
  target_agent_id: string;
  created_at: string;
  expires_at?: string | null;
  message?: string | null;
}

export interface SessionStatus {
  session_id: string;
  status: SessionStatusValue;
  initiator_agent_id: string;
  target_agent_id: string;
}

// ── Messages ──────────────────────────────────────────────────────

export interface MessageEnvelope {
  session_id: string;
  sender_agent_id: string;
  payload: Record<string, unknown>;
  nonce: string;
  timestamp: number;
  signature: string;
  client_seq?: number | null;
}

export interface InboxMessage {
  seq: number;
  sender_agent_id: string;
  payload: Record<string, unknown>;
  nonce: string;
  timestamp: string;
  signature?: string | null;
  client_seq?: number | null;
}

// ── E2E Encryption ────────────────────────────────────────────────

/** Encrypted blob returned by encryptForAgent / expected by decryptFromAgent. */
export interface CipherBlob {
  ciphertext: string;
  encrypted_key: string;
  iv: string;
  /** Present only when the recipient key is EC (ECDH+HKDF wrapping). */
  ephemeral_pubkey?: string;
}

// ── RFQ (Request for Quote) ───────────────────────────────────────

export interface RfqRequest {
  capability_filter: string[];
  payload: Record<string, unknown>;
  timeout_seconds?: number;
}

export interface RfqResponse {
  rfq_id: string;
  status: string;
  created_at: string;
  expires_at: string;
  quotes: RfqQuote[];
}

export interface RfqQuote {
  agent_id: string;
  org_id: string;
  payload: Record<string, unknown>;
  submitted_at: string;
}

export interface RfqRespondRequest {
  payload: Record<string, unknown>;
}

// ── Transaction Tokens ────────────────────────────────────────────

export interface TransactionTokenRequest {
  txn_type: string;
  payload_hash: string;
  session_id?: string;
  counterparty_agent_id?: string;
}

export interface TransactionTokenResponse {
  transaction_token: string;
  token_type: string;
  expires_in: number;
}

// ── Registry ──────────────────────────────────────────────────────

export interface AgentResponse {
  agent_id: string;
  org_id: string;
  display_name: string;
  capabilities: string[];
  status?: string;
}

export interface AgentListResponse {
  agents: AgentResponse[];
}

// ── Client Options ────────────────────────────────────────────────

export interface BrokerClientOptions {
  /** Base URL of the broker (e.g. "https://broker.example.com") */
  baseUrl: string;
  /** HTTP request timeout in milliseconds (default: 10000) */
  timeoutMs?: number;
  // NB: there is intentionally no `verifyTls` option. Node's native
  // fetch does not expose a per-call TLS-verify toggle, and the
  // process-wide escape hatch (NODE_TLS_REJECT_UNAUTHORIZED=0) is
  // unsafe. For a broker with a private or self-signed CA, add the CA
  // PEM to Node's trust store via NODE_EXTRA_CA_CERTS=/path/to/ca.pem
  // — scoped to this process, verification stays ON for every other
  // connection. The Python SDK exposes `verify_tls=False` because
  // httpx supports per-client SSL contexts; the TS SDK cannot mirror
  // that surface without taking on a hard `undici` dependency.
}
