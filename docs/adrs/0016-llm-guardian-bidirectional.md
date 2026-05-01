# ADR-016 — LLM Guardian: bidirectional content inspection via SDK cooperation

- **Status:** Proposed
- **Date:** 2026-05-01
- **Related:** ADR-006 (Trojan Horse standalone Mastio), ADR-011 (unified enrollment), ADR-013 (layered defence), ADR-014 (mTLS Connector ↔ Mastio)

## Context

Mastio is the per-org A2A proxy: every agent-to-agent message in the deployment passes through it. For **intra-org** traffic Mastio holds the key and can see plaintext, so it can apply policy (prompt-injection regex, PII redaction, etc.) inline. For **cross-org** traffic the message is end-to-end encrypted between sender SDK and receiver SDK; Mastio sees only the envelope. The brokerage (Court) sees even less — only metadata.

This leaves an enforcement gap: the moment a customer connects two organisations via Cullis, the most security-relevant traffic (cross-org) becomes the one we cannot inspect at the proxy. Today's choices are:

1. **Strip E2E** to let the proxy inspect cross-org messages. Defeats the point of the federated trust model and breaks the privacy promise to the counterparty org.
2. **Move enforcement to the agent runtime**. Each agent vendor would need to integrate a content firewall library; in practice this won't happen consistently across an organisation's agent fleet, and audit becomes impossible (each agent emits its own log format).
3. **Move enforcement to the SDK**. The SDK on each side already has the E2E key — it decrypts messages before handing them to the agent code, and encrypts agent output before sending. We make the SDK call the local Mastio for an inspection decision **after decrypting on receive** and **before encrypting on send**. Mastio sees plaintext only for the agent it owns; the counterparty key never leaves the counterparty SDK; E2E is preserved end-to-end.

Option 3 is the only one that closes the cross-org gap without breaking E2E, and it folds the intra-org case in for free (the SDK calls the same endpoint regardless of whether the peer is intra- or cross-org).

The other forcing constraint is **performance**. The 2026-04-23 nightly stress (`project_nightly_finding_dpop_concurrency`) showed the system is sensitive to per-message overhead: post-DPoP-fix throughput is ~35 rps with p99 ~497ms. A naive synchronous LLM-based content classifier in the hot path (200-500ms per call) would cut throughput by ~90%. Any inspection design must split fast deterministic checks (regex, role/scope, loop counters) from slow probabilistic checks (LLM-judge), and put only the fast set in the synchronous path.

## Decision

Adopt **SDK-mediated bidirectional inspection** with a **fast-path / slow-path** split.

### 1. Cooperation flow

```
Sender side:
  agent.send(msg)
    → SDK.encrypt(msg) — held in buffer
    → SDK.guardian_inspect(plaintext, direction=out, peer)
       → Mastio /v1/guardian/inspect → decision + signed ticket
    → if pass: SDK.send_to_mastio(ciphertext, ticket)
    → if redact: SDK.encrypt(redacted) + send
    → if block: raise GuardianBlocked(reason) → agent handles

Receiver side:
  Mastio.deliver(ciphertext) → SDK
    → SDK.decrypt(ciphertext) — held in buffer
    → SDK.guardian_inspect(plaintext, direction=in, peer)
       → Mastio /v1/guardian/inspect → decision + signed ticket
    → if pass: agent.on_message(plaintext, ticket)
    → if redact: agent.on_message(redacted, ticket)
    → if block: discard + audit, do not deliver
```

Mastio is the only component that holds the inspection rules; the SDK is a thin caller. Mastio is the only component that signs decisions; the agent runtime verifies the ticket before acting on the message (so a tampered SDK that skips the guardian call cannot deliver to a compliant agent).

### 2. Endpoint

`POST /v1/guardian/inspect` on Mastio. mTLS-authenticated with the calling agent's identity certificate (the same cert the SDK uses for `/v1/egress/*`). Body:

```json
{
  "direction": "in" | "out",
  "peer_agent_id": "string",
  "msg_id": "uuid",
  "content_type": "application/json+a2a-payload",
  "payload_b64": "base64-encoded plaintext"
}
```

Response:

```json
{
  "decision": "pass" | "redact" | "block",
  "ticket": "<JWT signed by Mastio's guardian key>",
  "ticket_exp": 1730483200,
  "redacted_payload_b64": "base64",
  "audit_id": "ulid",
  "reasons": [{"tool": "pii_egress", "match": "[REDACTED]"}]
}
```

The ticket is a short-lived JWT (`exp = now + 30s`) that includes `agent_id`, `peer_agent_id`, `msg_id`, `direction`, `decision`, `audit_id`. Mastio signs with `MCP_PROXY_GUARDIAN_TICKET_KEY` (HMAC-SHA256 with a per-instance key). The receiving agent verifies before acting.

### 3. Fast path / slow path split

The endpoint runs **fast-path tools synchronously** and **slow-path tools asynchronously**. The HTTP response includes only fast-path decisions; slow-path findings land in audit ~seconds later and trigger the alerting pipeline if they fire.

**Fast path (synchronous, target p50 < 10ms, p99 < 30ms):**

| Tool | Technique | Direction | Notes |
|---|---|---|---|
| Prompt-injection regex | compiled patterns (jailbreak, system-override, role-flip) | in | Pattern set ships with plugin; operator extends via dashboard. |
| Tool/capability escalation | allowlist by `(sender_role, peer_role, tool_name)` | in | Drops calls to tools outside the binding contract. |
| Loop detection | hop counter + msg-id dedup (Redis, 60s window) | in | Refuses delivery if same msg loops > N times. |
| PII patterns | regex (cards, SSN, emails, phones, MRN) | out | Redact-by-default; configurable. |
| Secret leak | high-confidence regex (AWS keys, GCP SA, Stripe, JWT, PEM) | out | Block-by-default. |
| Reach guard | binding lookup `(originator, peer, scope)` | both | Catches reflection attacks where A asks B to do cross-org work A doesn't have reach for. |

**Slow path (asynchronous, audit-only in v1):**

| Tool | Technique | Notes |
|---|---|---|
| LLM-judge | small classifier model (Llama Guard 1B locally, or Bedrock Guardrails / OpenAI Moderation API per operator choice) | Runs after the message has been delivered. Findings emit alerts but do not block. v2 may promote a subset to sync `enforce-strict` mode for high-risk binding lanes. |
| Topic-policy classifier | domain-specific classifier (banking compliance, healthcare HIPAA, etc.) | Customer-trained; ships as optional add-on plugin. |

Slow-path runs against a copy of the payload that the endpoint queues to a background worker pool (asyncio task queue, bounded). Because slow-path is audit-only the response time does not depend on it.

### 4. Modes

Per binding (default falls back to a global mode):

- `disabled`: SDK does not call the endpoint. Zero overhead. Opt-in for customers without compliance requirement.
- `audit-only`: All tools (fast + slow) run async, the endpoint returns `pass` immediately. Used for the first 2 weeks of every customer rollout to measure false-positive rate before turning on enforcement.
- `enforce-fast`: Fast-path runs sync, slow-path runs async. Default for production.
- `enforce-strict`: Fast-path + LLM-judge sync. Latency penalty 200-500ms. Reserved for explicitly opted-in high-risk lanes (e.g. cross-org bank-to-bank messages). Not the default.

Modes are configurable via the dashboard or `MCP_PROXY_GUARDIAN_MODE` env (global).

### 5. Idempotence cache

The endpoint hashes the first 1KB of the payload (sha256) and caches `(payload_hash, direction, peer) → decision` for 1h in Redis. Repeated payloads in agent workflows (heartbeats, retries, polling) skip the full check. Expected hit rate 30-60% based on prior intra-org traffic samples. Cache lookup adds ~0.5ms.

### 6. Trust model

The SDK is the entry point but is not trusted. Two reinforcements:

1. **Inspection ticket**: the receiving agent runtime verifies the JWT ticket signature (Mastio guardian key, distributed to agent processes via the same identity bundle that carries the org CA chain) and matches `msg_id` + `agent_id` + `direction`. A tampered SDK that returns a synthetic `pass` without calling Mastio cannot fabricate the signature.
2. **mTLS-attested call**: the `/v1/guardian/inspect` request authenticates the SDK's agent cert. Mastio cross-checks that the agent identity matches the `peer_agent_id` claimed in the response routing. A rogue agent cannot ask the guardian to inspect on behalf of another agent.

The threat model explicitly excludes a malicious agent runtime that strips ticket verification. That is the agent operator's responsibility (signed binaries, attested boot, SBOM gates) and not in scope for the guardian itself.

### 7. Rollout safety gates

Before any production cutover:

1. Nightly stress with `enforce-fast` ON for 24h, no failures.
2. End-to-end p99 latency < 1.3x baseline.
3. Throughput rps > 0.75x baseline.
4. Audit-only sweep on customer corpus shows fast-path false-positive rate < 5%.
5. Each tool documented with a rule reference, a positive example (block), a negative example (legitimate traffic that must not block).

If any gate fails, the customer remains in `audit-only` mode regardless of dashboard setting. The mode promotion to `enforce-fast` requires explicit operator confirmation in the dashboard with the gate report attached.

## Consequences

### Positive

- Closes the cross-org content-inspection gap without breaking E2E.
- Single source of truth for inspection rules (Mastio) regardless of intra/cross-org traffic shape.
- Audit format unified across all enforcement actions (one log shape, one queryable timeline).
- Customer can run audit-only forever for soft compliance use cases without paying enforcement latency cost.
- Composable with the existing plugin architecture (`mcp_proxy.plugins`): each tool is a plugin that registers into `mcp_proxy.guardian.registry`.

### Negative

- SDK breaking change. Old SDK versions ignore the guardian endpoint; rollout requires SDK upgrade across the customer's agent fleet. Mitigated by feature flag (`MCP_PROXY_GUARDIAN_ENABLED=0` default in the SDK; customer opts in when ready).
- Per-message overhead even in `enforce-fast` mode (~10ms p50, ~30ms p99). Acceptable for the agentic-workflow latency budget but visible.
- Two extra round-trips per message (sender side + receiver side) in `enforce-fast`. Intra-org HTTPS keep-alive keeps these at 1-3ms each.
- The trust model leans on the agent runtime to verify the ticket. Compromised runtime = bypass. We document this as a customer responsibility.
- The slow-path adds infrastructure (async queue, alerting pipeline, model hosting if local Llama Guard). Operationally this is non-trivial; we ship it as an optional plugin so customers without LLM-judge requirements skip it.

### Open questions deferred to implementation

- Concrete LLM-judge model choice (Llama Guard 1B locally vs Bedrock Guardrails vs OpenAI Moderation). Decided in Phase 4 of the rollout plan after benchmarking on a representative corpus.
- Distribution of the guardian ticket key to agent runtimes (separate bundle vs piggyback on org CA chain refresh). Resolved during Phase 1 implementation.
- Dashboard UX for rule editing — visual builder vs YAML editor vs both. Decided when Phase 6 starts.

## Implementation plan

See `docs/plans/llm-guardian-rollout-2026-05.md` for the seven-phase rollout, dependencies, effort estimates, and CI gates.
