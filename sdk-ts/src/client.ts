/**
 * BrokerClient: main class for agent-to-broker communication.
 *
 * Exposes the 2025-Q4 session-based wire path:
 * - x509 + DPoP authentication
 * - Session lifecycle (open, accept, close, list)
 * - E2E encrypted messaging (send + poll with auto-decrypt)
 * - Agent discovery
 * - RFQ flow
 * - Transaction tokens
 * - Automatic DPoP nonce handling with retry
 *
 * STATUS: legacy session API. The Python equivalents
 * (`CullisClient.login` / `open_session` / `send` / `close_session`)
 * are deprecated and scheduled for removal in `cullis-sdk` v0.5
 * (~2026-08-15). The canonical A2A surface is one-shot messaging
 * (ADR-008: `send_oneshot` + `receive_oneshot` + ACK), which this
 * SDK does not yet expose (tracked as F-B-301; see the README
 * "Surface gaps" and "Roadmap" sections). New TypeScript
 * integrations that can wait for parity should prefer `cullis_sdk`
 * (Python) and its `send_oneshot()` flow.
 */
import { readFile } from "node:fs/promises";
import type { KeyObject } from "node:crypto";
import type { JWK } from "jose";

import {
  createClientAssertion,
  createDPoPProof,
  generateDPoPKeyPair,
} from "./auth.js";
import {
  signMessage,
  verifyMessageSignature,
  encryptForAgent,
  decryptFromAgent,
} from "./crypto.js";
import type {
  BrokerClientOptions,
  SessionResponse,
  InboxMessage,
  AgentResponse,
  AgentListResponse,
  CipherBlob,
  RfqResponse,
  TransactionTokenResponse,
} from "./types.js";

// ── HTTP helpers ──────────────────────────────────────────────────

interface RequestOptions {
  body?: unknown;
  params?: Record<string, string> | [string, string][];
}

interface HttpResponse {
  status: number;
  headers: Headers;
  text: string;
  ok: boolean;
}

async function httpRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  options?: RequestOptions,
  timeoutMs = 10_000,
): Promise<HttpResponse> {
  let fullUrl = url;
  if (options?.params) {
    const searchParams = new URLSearchParams(
      Array.isArray(options.params) ? options.params : Object.entries(options.params),
    );
    fullUrl = `${url}?${searchParams.toString()}`;
  }

  const fetchOptions: RequestInit & { signal?: AbortSignal } = {
    method,
    headers: { ...headers, "Content-Type": "application/json" },
  };

  if (options?.body !== undefined) {
    fetchOptions.body = JSON.stringify(options.body);
  }

  // Node 18+ supports AbortSignal.timeout
  fetchOptions.signal = AbortSignal.timeout(timeoutMs);

  // TLS verification is always ON. Node's native fetch does not expose
  // a per-call verify toggle, so this SDK does not offer one. For a
  // broker with a private or self-signed CA, add the CA PEM to Node's
  // trust store via NODE_EXTRA_CA_CERTS=/path/to/ca.pem — scoped to
  // the current process, leaves verification enabled for every other
  // connection. Do NOT use NODE_TLS_REJECT_UNAUTHORIZED=0; it disables
  // verification process-wide and exposes every outbound HTTPS call.
  const response = await fetch(fullUrl, fetchOptions);
  const text = await response.text();

  return {
    status: response.status,
    headers: response.headers,
    text,
    ok: response.ok,
  };
}

// ── BrokerClient ──────────────────────────────────────────────────

const PUBKEY_CACHE_TTL_MS = 300_000; // 5 minutes

export class BrokerClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  private token: string | null = null;
  private signingKeyPem: string | null = null;

  // DPoP ephemeral key pair
  private dpopPrivateKey: KeyObject | null = null;
  private dpopPublicJwk: JWK | null = null;
  private dpopNonce: string | null = null;

  // Public key cache: agentId -> { pem, fetchedAt }
  private pubkeyCache = new Map<string, { pem: string; fetchedAt: number }>();

  // Client-side sequence numbers per session
  private clientSeq = new Map<string, number>();

  constructor(options: BrokerClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 10_000;

    // TLS verification is mandatory. The SDK no longer exposes a
    // `verifyTls` option (it used to throw on `false`, which was just
    // a misleading API). For brokers with a private or self-signed
    // CA, point Node at the CA PEM via NODE_EXTRA_CA_CERTS — process
    // scoped, verification stays ON everywhere else. See the README
    // "Self-signed / private CA" section.
  }

  // ── Authentication ───────────────────────────────────────────

  /**
   * Authenticate the agent via x509 client_assertion + DPoP proof.
   *
   * @param agentId  - Agent identifier
   * @param orgId    - Organization identifier
   * @param certPath - Path to PEM certificate file
   * @param keyPath  - Path to PEM private key file
   */
  async login(
    agentId: string,
    orgId: string,
    certPath: string,
    keyPath: string,
  ): Promise<void> {
    const keyPem = await readFile(keyPath, "utf-8");
    const certPem = await readFile(certPath, "utf-8");
    this.signingKeyPem = keyPem;

    // Build the client_assertion JWT
    const assertion = await createClientAssertion(agentId, orgId, certPem, keyPem);

    // Generate ephemeral DPoP key pair
    const dpopKeyPair = await generateDPoPKeyPair();
    this.dpopPrivateKey = dpopKeyPair.privateKey;
    this.dpopPublicJwk = dpopKeyPair.publicJwk;

    const tokenUrl = `${this.baseUrl}/v1/auth/token`;

    // First attempt — may fail with 401 + use_dpop_nonce
    let dpopProof = await this.buildDPoPProof("POST", tokenUrl);
    let resp = await httpRequest(
      "POST",
      tokenUrl,
      { DPoP: dpopProof },
      { body: { client_assertion: assertion } },
      this.timeoutMs,
    );

    this.updateNonce(resp.headers);

    // Retry once if server requires a nonce
    if (resp.status === 401 && resp.text.includes("use_dpop_nonce")) {
      dpopProof = await this.buildDPoPProof("POST", tokenUrl);
      resp = await httpRequest(
        "POST",
        tokenUrl,
        { DPoP: dpopProof },
        { body: { client_assertion: assertion } },
        this.timeoutMs,
      );
      this.updateNonce(resp.headers);
    }

    if (!resp.ok) {
      throw new Error(
        `Login failed (HTTP ${resp.status}): ${resp.text}`,
      );
    }

    const data = JSON.parse(resp.text) as { access_token: string };
    this.token = data.access_token;
  }

  // ── Discovery ────────────────────────────────────────────────

  /**
   * Search for agents by capability.
   */
  async discover(capabilities: string[]): Promise<AgentResponse[]> {
    const params: [string, string][] = capabilities.map((c) => [
      "capability",
      c,
    ]);
    // ADR-010 Phase 6a — cross-org discovery now lives under /v1/federation/.
    const resp = await this.authedRequest(
      "GET",
      "/v1/federation/agents/search",
      { params },
    );
    const data = JSON.parse(resp.text) as AgentListResponse;
    return data.agents ?? [];
  }

  // ── Sessions ─────────────────────────────────────────────────

  /**
   * Open a new session with a target agent.
   * Returns the session_id.
   */
  async openSession(
    targetAgentId: string,
    targetOrgId: string,
    capabilities: string[],
  ): Promise<string> {
    const resp = await this.authedRequest("POST", "/v1/broker/sessions", {
      body: {
        target_agent_id: targetAgentId,
        target_org_id: targetOrgId,
        requested_capabilities: capabilities,
      },
    });
    const data = JSON.parse(resp.text) as SessionResponse;
    return data.session_id;
  }

  /**
   * Accept a pending session.
   */
  async acceptSession(sessionId: string): Promise<void> {
    await this.authedRequest(
      "POST",
      `/v1/broker/sessions/${sessionId}/accept`,
    );
  }

  /**
   * Close an active session.
   */
  async closeSession(sessionId: string): Promise<void> {
    await this.authedRequest(
      "POST",
      `/v1/broker/sessions/${sessionId}/close`,
    );
  }

  /**
   * List sessions, optionally filtered by status.
   */
  async listSessions(
    statusFilter?: string,
  ): Promise<SessionResponse[]> {
    const params: Record<string, string> = {};
    if (statusFilter) {
      params.status = statusFilter;
    }
    const resp = await this.authedRequest("GET", "/v1/broker/sessions", {
      params,
    });
    return JSON.parse(resp.text) as SessionResponse[];
  }

  // ── Messaging ────────────────────────────────────────────────

  /**
   * Send an E2E encrypted, signed message through the broker.
   *
   * All messages are encrypted — plaintext is not allowed.
   */
  async send(
    sessionId: string,
    senderAgentId: string,
    payload: Record<string, unknown>,
    recipientAgentId: string,
  ): Promise<void> {
    if (!this.signingKeyPem) {
      throw new Error("Signing key not available — call login() first");
    }

    const nonce = crypto.randomUUID();
    const timestamp = Math.floor(Date.now() / 1000);

    // Client-side sequence number for E2E ordering integrity
    const clientSeq = this.clientSeq.get(sessionId) ?? 0;
    this.clientSeq.set(sessionId, clientSeq + 1);

    // Inner signature on plaintext (non-repudiation for the recipient)
    const innerSig = signMessage(
      this.signingKeyPem,
      sessionId,
      senderAgentId,
      nonce,
      timestamp,
      payload,
      clientSeq,
    );

    // Encrypt payload + inner signature with recipient's public key
    const recipientPubkey = await this.getAgentPublicKey(recipientAgentId);
    const cipherBlob = encryptForAgent(
      payload,
      recipientPubkey,
      sessionId,
      senderAgentId,
      innerSig,
      clientSeq,
    );

    // Outer signature on ciphertext (transport integrity for the broker)
    const outerSig = signMessage(
      this.signingKeyPem,
      sessionId,
      senderAgentId,
      nonce,
      timestamp,
      cipherBlob as unknown as Record<string, unknown>,
      clientSeq,
    );

    const envelope = {
      session_id: sessionId,
      sender_agent_id: senderAgentId,
      payload: cipherBlob,
      nonce,
      timestamp,
      signature: outerSig,
      client_seq: clientSeq,
    };

    const path = `/v1/broker/sessions/${sessionId}/messages`;

    // Retry up to 3 times on network errors
    let lastError: Error | null = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await this.authedRequest("POST", path, { body: envelope });
        return;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < 2) {
          await new Promise((resolve) => setTimeout(resolve, 2000));
        }
      }
    }
    throw new Error(
      `Failed to send message after 3 attempts: ${lastError?.message}`,
    );
  }

  /**
   * Poll for messages in a session. Automatically decrypts E2E messages.
   *
   * @param sessionId - Session to poll
   * @param after     - Sequence number to fetch messages after (default: -1 = all)
   */
  async poll(
    sessionId: string,
    after = -1,
  ): Promise<InboxMessage[]> {
    const path = `/v1/broker/sessions/${sessionId}/messages`;
    const resp = await this.authedRequest("GET", path, {
      params: { after: String(after) },
    });
    const messages = JSON.parse(resp.text) as InboxMessage[];

    // Decrypt each message in parallel (each may fetch the sender cert
    // from the registry; the pubkey cache de-duplicates per-agent
    // round trips within the TTL window).
    return Promise.all(messages.map((msg) => this.decryptPayload(msg, sessionId)));
  }

  /**
   * Get an agent's public key PEM from the registry (TTL-cached).
   *
   * Prefers ``cert_pem`` (full X.509) over ``public_key_pem`` (bare SPKI)
   * to match the Python SDK's behaviour. The H7 audit fix on
   * ``verifyMessageSignature`` rejects bare SPKI — callers that need to
   * verify inner signatures (e.g. ``decryptPayload``) require the full
   * cert. Older brokers that don't populate ``cert_pem`` still work for
   * encryption (``createPublicKey`` accepts both forms) but inner-sig
   * verification will fail loudly with a clear error.
   */
  async getAgentPublicKey(
    agentId: string,
    forceRefresh = false,
  ): Promise<string> {
    if (!forceRefresh) {
      const cached = this.pubkeyCache.get(agentId);
      if (cached && Date.now() - cached.fetchedAt < PUBKEY_CACHE_TTL_MS) {
        return cached.pem;
      }
    }
    // ADR-010 Phase 6a — public-key lookup served under /v1/federation/.
    const path = `/v1/federation/agents/${agentId}/public-key`;
    const resp = await this.authedRequest("GET", path);
    const data = JSON.parse(resp.text) as {
      cert_pem?: string | null;
      public_key_pem?: string | null;
    };
    const pem = data.cert_pem || data.public_key_pem;
    if (!pem) {
      throw new Error(
        `Registry returned no key material for ${agentId} ` +
          "(neither cert_pem nor public_key_pem)",
      );
    }
    this.pubkeyCache.set(agentId, {
      pem,
      fetchedAt: Date.now(),
    });
    return pem;
  }

  // ── RFQ (Request for Quote) ──────────────────────────────────

  /**
   * Create a Request for Quote broadcast.
   */
  async createRfq(
    capabilityFilter: string[],
    payload: Record<string, unknown>,
    timeoutSeconds?: number,
  ): Promise<RfqResponse> {
    const body: Record<string, unknown> = {
      capability_filter: capabilityFilter,
      payload,
    };
    if (timeoutSeconds !== undefined) {
      body.timeout_seconds = timeoutSeconds;
    }
    const resp = await this.authedRequest("POST", "/v1/broker/rfq", { body });
    return JSON.parse(resp.text) as RfqResponse;
  }

  /**
   * Respond to an RFQ with a quote.
   */
  async respondToRfq(
    rfqId: string,
    payload: Record<string, unknown>,
  ): Promise<void> {
    await this.authedRequest("POST", `/v1/broker/rfq/${rfqId}/respond`, {
      body: { payload },
    });
  }

  /**
   * Get the current status and quotes for an RFQ.
   */
  async getRfq(rfqId: string): Promise<RfqResponse> {
    const resp = await this.authedRequest("GET", `/v1/broker/rfq/${rfqId}`);
    return JSON.parse(resp.text) as RfqResponse;
  }

  // ── Transaction Tokens ───────────────────────────────────────

  /**
   * Request a transaction token from the broker.
   */
  async requestTransactionToken(
    txnType: string,
    payloadHash: string,
    options?: { sessionId?: string; counterpartyAgentId?: string },
  ): Promise<TransactionTokenResponse> {
    const body: Record<string, unknown> = {
      txn_type: txnType,
      payload_hash: payloadHash,
    };
    if (options?.sessionId) {
      body.session_id = options.sessionId;
    }
    if (options?.counterpartyAgentId) {
      body.counterparty_agent_id = options.counterpartyAgentId;
    }
    const resp = await this.authedRequest("POST", "/v1/auth/token/transaction", {
      body,
    });
    return JSON.parse(resp.text) as TransactionTokenResponse;
  }

  // ── Internal: Authenticated Requests ─────────────────────────

  /**
   * Make an authenticated request with DPoP headers and automatic nonce retry.
   */
  private async authedRequest(
    method: string,
    path: string,
    options?: RequestOptions,
  ): Promise<HttpResponse> {
    if (!this.token) {
      throw new Error("Not authenticated — call login() first");
    }

    const url = `${this.baseUrl}${path}`;
    const headers = await this.authHeaders(method, path);

    let resp = await httpRequest(
      method,
      url,
      headers,
      options,
      this.timeoutMs,
    );
    this.updateNonce(resp.headers);

    // Retry once if server requires a new nonce
    if (resp.status === 401 && resp.text.includes("use_dpop_nonce")) {
      const retryHeaders = await this.authHeaders(method, path);
      resp = await httpRequest(
        method,
        url,
        retryHeaders,
        options,
        this.timeoutMs,
      );
      this.updateNonce(resp.headers);
    }

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${resp.text}`);
    }

    return resp;
  }

  /**
   * Build Authorization + DPoP headers for an authenticated request.
   */
  private async authHeaders(
    method: string,
    path: string,
  ): Promise<Record<string, string>> {
    if (!this.token) {
      throw new Error("Not authenticated — call login() first");
    }
    const url = `${this.baseUrl}${path}`;
    const dpopProof = await this.buildDPoPProof(method, url, this.token);
    return {
      Authorization: `DPoP ${this.token}`,
      DPoP: dpopProof,
    };
  }

  /**
   * Generate a DPoP proof JWT for the given method and URL.
   */
  private async buildDPoPProof(
    method: string,
    url: string,
    accessToken?: string,
  ): Promise<string> {
    if (!this.dpopPrivateKey || !this.dpopPublicJwk) {
      throw new Error("DPoP key not initialized — call login() first");
    }
    return createDPoPProof(method, url, this.dpopPrivateKey, this.dpopPublicJwk, {
      accessToken,
      nonce: this.dpopNonce ?? undefined,
    });
  }

  /**
   * Extract and store DPoP-Nonce from response headers.
   */
  private updateNonce(headers: Headers): void {
    const nonce = headers.get("dpop-nonce");
    if (nonce) {
      this.dpopNonce = nonce;
    }
  }

  /**
   * Decrypt the payload of a received message if it is E2E encrypted,
   * AND verify the inner (plaintext) signature for non-repudiation.
   *
   * The inner signature is the only proof that the sender's *private*
   * key produced the plaintext: a compromised broker can substitute
   * the ciphertext after the AES-GCM key has been unwrapped, and AES-GCM
   * alone (which only authenticates against the broker-controllable
   * AAD) would not catch this. Skipping the inner-sig check would let
   * the broker forge messages silently, breaking the entire
   * non-repudiation property the protocol promises to recipients.
   *
   * Audit reference: L9-C1 (sdk-ts, 2026-05-08). Mirrors the Python
   * ``cullis_sdk.client._fetch_pubkey_proxy_then_broker`` +
   * ``verify_inner_signature`` pattern (cullis_sdk/client.py:2689).
   *
   * Throws on any cryptographic failure (decrypt or verify).
   */
  private async decryptPayload(
    msg: InboxMessage,
    sessionId: string,
  ): Promise<InboxMessage> {
    if (!this.signingKeyPem) {
      return msg;
    }

    const p = msg.payload;
    if (
      !p ||
      typeof p !== "object" ||
      !("ciphertext" in p)
    ) {
      return msg;
    }

    if (!sessionId) {
      return msg; // Cannot decrypt without session_id
    }

    const cipherBlob = p as unknown as CipherBlob;
    const senderAgentId = msg.sender_agent_id;
    const clientSeq = msg.client_seq;

    // 1. Decrypt — recovers both the plaintext payload AND the inner
    //    signature the sender produced over that plaintext.
    const [plaintextPayload, innerSignature] = decryptFromAgent(
      cipherBlob,
      this.signingKeyPem,
      sessionId,
      senderAgentId,
      clientSeq,
    );

    // 2. Fetch the sender's certificate (TTL-cached). H7 audit fix:
    //    ``verifyMessageSignature`` rejects bare SPKI — registry
    //    response must carry the full cert under ``cert_pem``.
    const senderCertPem = await this.getAgentPublicKey(senderAgentId);

    // 3. Convert the wire-side timestamp back into the seconds-since-epoch
    //    integer the sender signed against. The broker serialises its
    //    stored ``datetime`` as ISO-8601, but ``signMessage`` consumed an
    //    epoch int; we accept either shape so this stays robust to the
    //    broker normalising the field.
    const ts = parseTimestamp(msg.timestamp);

    // 4. Verify. Throws on cert/binding/signature failure — propagate
    //    rather than masking, since a verify failure means a forged
    //    plaintext (broker compromise) or a misconfigured peer.
    try {
      verifyMessageSignature(
        senderCertPem,
        innerSignature,
        sessionId,
        senderAgentId,
        msg.nonce,
        ts,
        plaintextPayload,
        clientSeq,
      );
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      throw new Error(
        `inner signature verification failed for message from ` +
          `${senderAgentId} (seq=${msg.seq}): ${reason}`,
      );
    }

    return { ...msg, payload: plaintextPayload };
  }
}

/**
 * Best-effort coercion of the wire ``timestamp`` field to seconds since
 * the Unix epoch (the integer form ``signMessage`` consumed at send).
 *
 * The broker's ``InboxMessage`` Pydantic model serialises a stored
 * ``datetime`` as ISO-8601, but the sender's inner-signature canonical
 * was built with ``Math.floor(Date.now()/1000)`` (an int). Accept both
 * shapes:
 *   - number → trusted as-is
 *   - numeric string → parsed as int
 *   - ISO-8601 string → parsed via ``Date.parse`` and floored to seconds
 */
function parseTimestamp(value: string | number): number {
  if (typeof value === "number") {
    return Math.floor(value);
  }
  if (/^-?\d+$/.test(value)) {
    return parseInt(value, 10);
  }
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    throw new Error(`Cannot parse message timestamp: ${value}`);
  }
  return Math.floor(ms / 1000);
}
