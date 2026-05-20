/**
 * @agent-trust/sdk: TypeScript SDK for Cullis.
 *
 * Main entry point, re-exports the public API.
 *
 * STATUS: BETA, legacy session API only. Exposes the 2025-Q4
 * session-based wire path (login / openSession / send / poll /
 * closeSession / RFQ). One-shot messaging (ADR-008), proxy login
 * (ADR-014), enrollment factories (ADR-011), AI gateway (ADR-017)
 * and the other surfaces present in the Python `cullis_sdk` are not
 * yet ported here (tracked as F-B-301). See the README "Surface
 * gaps" and "Roadmap" sections for the explicit delta and the
 * migration outlook before `cullis-sdk` v0.5 lands (~2026-08-15).
 */

// Client
export { BrokerClient } from "./client.js";

// Auth helpers
export {
  createClientAssertion,
  createDPoPProof,
  generateDPoPKeyPair,
  computeJwkThumbprint,
} from "./auth.js";
export type { DPoPKeyPair, DPoPProofOptions } from "./auth.js";

// Crypto helpers
export {
  signMessage,
  verifyMessageSignature,
  encryptForAgent,
  decryptFromAgent,
} from "./crypto.js";

// Utilities
export {
  canonicalJson,
  base64url,
  base64urlDecode,
  computePayloadHash,
} from "./utils.js";

// Types
export type {
  TokenPayload,
  TokenRequest,
  TokenResponse,
  SessionStatusValue,
  SessionRequest,
  SessionResponse,
  SessionStatus,
  MessageEnvelope,
  InboxMessage,
  CipherBlob,
  RfqRequest,
  RfqResponse,
  RfqQuote,
  RfqRespondRequest,
  TransactionTokenRequest,
  TransactionTokenResponse,
  AgentResponse,
  AgentListResponse,
  BrokerClientOptions,
} from "./types.js";
