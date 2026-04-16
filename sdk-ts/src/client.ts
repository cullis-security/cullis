/**
 * BrokerClient — main class for agent-to-broker communication.
 *
 * Mirrors agents/sdk.py BrokerClient, including:
 * - x509 + DPoP authentication
 * - Session lifecycle (open, accept, close, list)
 * - E2E encrypted messaging (send + poll with auto-decrypt)
 * - Agent discovery
 * - RFQ flow
 * - Transaction tokens
 * - Automatic DPoP nonce handling with retry
 */
import { readFile } from "node:fs/promises";
import type { KeyObject } from "node:crypto";
import type { JWK } from "jose";

import {
  createClientAssertion,
  createDPoPProof,
  generateDPoPKeyPair,
} from "./auth.js";
import { signMessage, encryptForAgent, decryptFromAgent } from "./crypto.js";
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
  verifyTls = true,
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

  // Note: Node.js native fetch does not support disabling TLS verification
  // directly. For self-signed certs, set NODE_TLS_REJECT_UNAUTHORIZED=0
  // in the environment, or use a custom agent via undici.
  if (!verifyTls && typeof process !== "undefined") {
    // This is a hint for the user; the actual env var must be set externally
    // or use the NODE_TLS_REJECT_UNAUTHORIZED workaround.
  }

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
  private readonly verifyTls: boolean;
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
    this.verifyTls = options.verifyTls ?? true;
    this.timeoutMs = options.timeoutMs ?? 10_000;
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
      this.verifyTls,
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
        this.verifyTls,
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
    const resp = await this.authedRequest("GET", "/v1/registry/agents/search", {
      params,
    });
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

    // Decrypt each message
    return messages.map((msg) => this.decryptPayload(msg, sessionId));
  }

  /**
   * Get an agent's public key PEM from the registry (TTL-cached).
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
    const path = `/v1/registry/agents/${agentId}/public-key`;
    const resp = await this.authedRequest("GET", path);
    const data = JSON.parse(resp.text) as { public_key_pem: string };
    this.pubkeyCache.set(agentId, {
      pem: data.public_key_pem,
      fetchedAt: Date.now(),
    });
    return data.public_key_pem;
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
      this.verifyTls,
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
        this.verifyTls,
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
   * Decrypt the payload of a received message if it is E2E encrypted.
   */
  private decryptPayload(
    msg: InboxMessage,
    sessionId: string,
  ): InboxMessage {
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

    const [plaintextPayload] = decryptFromAgent(
      cipherBlob,
      this.signingKeyPem,
      sessionId,
      senderAgentId,
      clientSeq,
    );

    return { ...msg, payload: plaintextPayload };
  }
}
