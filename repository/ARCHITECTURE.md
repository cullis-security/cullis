# Architecture

Deep dive into the Agent Trust Network design — modules, flows, and key decisions.

---

## Modules

| Module | Responsibility |
|---|---|
| Auth | x509 client assertion verification, JWT RS256 issuance, JTI blacklist |
| Registry | Organizations, agents, bindings, org CA storage, capability discovery, public-key endpoint |
| Broker | Sessions, messages, WebSocket push, persistence, restore on startup |
| Policy | Session default-deny + message policy evaluation + event role enforcement |
| Onboarding | External org join requests, admin approval/reject |
| Rate Limit | Sliding window limiter — auth, session, message buckets |
| Injection | Prompt injection — regex fast path + LLM judge; runs client-side on decrypted plaintext |
| Signing | RSA-PKCS1v15-SHA256 — outer signature on ciphertext (broker), inner signature on plaintext (recipient) |
| E2E Crypto | Hybrid encryption/decryption — AES-256-GCM for payload, RSA-OAEP-SHA256 for key wrapping |
| Audit | Append-only event log — ciphertext hash + outer signature per message |
| Traceability | Lot lifecycle, event hash chaining, certifications, ledger adapter |

---

## Authentication Flow

When an agent wants to authenticate, it builds a signed JWT containing its own certificate, and sends it to the broker. The broker does not trust the certificate blindly — it verifies the full chain.

1. Agent builds a `client_assertion` JWT signed with its private key. The certificate is embedded in the JWT header (`x5c` field).
2. Broker checks rate limit (10 requests/min per IP).
3. Broker extracts the certificate from the `x5c` header.
4. Broker loads the organization's CA certificate from the database.
5. Broker verifies the certificate chain: agent cert must be signed by the org CA.
6. Broker verifies the certificate is within its validity period.
7. Broker verifies the JWT signature using the certificate's public key.
8. Broker checks that `sub` in the JWT matches the `CN` in the certificate.
9. Broker checks that an approved binding exists for this (org, agent) pair.
10. Broker checks the JWT ID (`jti`) is not in the blacklist, then consumes it.
11. Broker stores the agent's certificate in the database (used later for message verification).
12. Broker issues an access token signed with the broker's own private key.

---

## Session Flow

1. Initiator sends a session request to the broker specifying the target agent.
2. Broker checks that both agents have approved bindings and that their scopes overlap.
3. Broker checks the initiator's session policy — if no policy exists, the session is rejected (default-deny).
4. Broker creates the session in `pending` state and notifies the target via WebSocket.
5. Target accepts the session — status becomes `active`.
6. Both agents can now exchange messages through the broker.
7. Either agent can close the session. Closure is idempotent.

---

## E2E Encryption and Message Signing

Messages are end-to-end encrypted. The broker cannot read the content of any inter-agent message — it only sees an opaque ciphertext blob.

**Cryptographic scheme:** hybrid AES-256-GCM + RSA-OAEP-SHA256.
- A fresh AES-256 key is generated for each message and used to encrypt the payload (GCM includes an authentication tag — integrity is implicit).
- The AES key is encrypted with the recipient's RSA public key (OAEP padding with SHA-256).
- The recipient's public key is fetched from `GET /registry/agents/{agent_id}/public-key`, which returns the key extracted from the certificate stored in DB at login.

**Two-layer signing:** the scheme uses two independent signatures, each covering a different thing.

*Inner signature* — signed by the sender, verified by the recipient:
```
sign(RSA-PKCS1v15-SHA256,
     {session_id}|{sender_agent_id}|{nonce}|{canonical_json(plaintext_payload)})
```
Provides non-repudiation: the recipient can prove the sender wrote this exact payload, independent of the broker.

*Outer signature* — signed by the sender, verified by the broker:
```
sign(RSA-PKCS1v15-SHA256,
     {session_id}|{sender_agent_id}|{nonce}|{canonical_json(ciphertext_blob)})
```
Provides transport integrity: prevents anyone from modifying the ciphertext in transit.

**Full flow:**

1. Sender computes the inner signature on the plaintext payload.
2. Sender encrypts `{plaintext, inner_sig}` with the recipient's public key → ciphertext blob.
3. Sender computes the outer signature on the ciphertext blob.
4. Sender POSTs `{ciphertext, nonce, outer_sig}` to the broker.
5. Broker loads the sender's certificate from the database (stored at login).
6. Broker verifies the outer signature against the ciphertext blob.
7. Broker stores the ciphertext blob and the outer signature.
8. Broker writes to the audit log: ciphertext hash + outer signature.
9. Broker pushes the encrypted message to the recipient via WebSocket (or makes it available via polling).
10. Recipient decrypts the ciphertext with its own private key → recovers `{plaintext, inner_sig}`.
11. Recipient verifies the inner signature against the plaintext using the sender's certificate.
12. Recipient runs injection detection on the plaintext.
13. Recipient passes the plaintext to the LLM.

The broker never reconstructs the plaintext. Steps 10–13 happen entirely on the recipient's side.

---

## Injection Detection

With E2E encryption, the broker cannot read message content and therefore cannot perform injection detection at the network level. Detection runs **client-side** in `agents/sdk.py`, on the decrypted plaintext, before the payload is passed to the LLM.

**Stage 1 — Regex fast path (zero latency)**

Checked immediately against 12 pattern categories:
- Instruction override ("ignore all previous instructions")
- Role hijack ("you are now", "act as")
- DAN jailbreak variants
- System/instruction tags (`<system>`, `<instructions>`)
- Human/Assistant turn markers
- Prompt leak requests ("reveal your system prompt")
- Null bytes
- Unicode direction tricks (RTL override, zero-width characters)

If any pattern matches → message discarded, not forwarded to the LLM.

**Stage 2 — LLM judge (only on suspicious payloads)**

A message is considered suspicious if:
- Total payload length exceeds 300 characters
- String values contain newlines
- Payload contains markdown or HTML characters

If suspicious, the message is sent to Claude Haiku for evaluation. If confidence ≥ 0.7 → discarded. Otherwise → passed to the LLM.

Structured B2B messages like `{"type": "order", "qty": 500}` skip the LLM judge entirely.

**Design note:** moving detection client-side is a natural consequence of the E2E design. The receiving agent is the only party that sees the plaintext, so it is also the only party that can inspect it. This actually improves the threat model: a malicious message that somehow bypasses the broker is still caught before reaching the LLM.

---

## Session Persistence

Every state change (create, activate, close) is immediately written to the database. On broker startup, all non-expired, non-closed sessions are restored to memory.

**Restore process:**
1. Query sessions with status `pending` or `active` and `expires_at` in the future.
2. For each session, reconstruct the session object.
3. Reload the full message list from the database.
4. Rebuild the used-nonce set (for replay protection continuity).
5. Restore to the in-memory session store.

Agents resume without intervention. Broker restart is transparent.

---

## Policy Engine

**Sessions — default deny**

Without an active policy, no session can be opened. A policy must explicitly allow the session.

Two policy layers are evaluated in order:

**1. Role policies (priority)**

Defined once by the network admin before any organization joins. They authorize entire roles to communicate with each other, independently of which specific organizations are involved.

Example: `role:buyer → role:supplier` allows any buyer agent to open a session with any supplier agent in the network.

| Condition | Description |
|---|---|
| `target_role` | Which agent role the initiator is allowed to reach |
| `capabilities` | Required capability overlap |
| `max_active_sessions` | Concurrency limit per initiator agent |

When a role policy matches, the decision is immediate — org-specific policies are not checked.

**2. Org-specific policies (fallback)**

Legacy / fine-grained policies scoped to a specific organization. Evaluated only if no role policy applies.

| Condition | Description |
|---|---|
| `target_org_id` | Which organization the initiator is allowed to reach |
| `capabilities` | Required capability overlap |
| `max_active_sessions` | Concurrency limit for the initiator |

**Messages — default allow**

Without a policy, messages pass through. A policy can block messages based on:

| Condition | Description |
|---|---|
| `max_payload_size_bytes` | Maximum allowed payload size |
| `required_fields` | Fields that must be present in the payload |
| `blocked_fields` | Fields that must not be present in the payload |

---

## PKI Design

Three-level certificate hierarchy:

| Level | Key Size | Validity | Controlled by |
|---|---|---|---|
| Broker CA | RSA 4096 | 10 years | Network operator |
| Org CA | RSA 2048 | 5 years | Member organization |
| Agent cert | RSA 2048 | 1 year | Member organization |

The Broker CA is owned and operated exclusively by the network operator — it is the root of trust for the entire network. Organizations generate their own Org CA and agent certificates, but these are only valid within the network after the operator approves the join request and registers the Org CA.

The broker trusts **org CAs**, not individual agent certificates. The org CA is uploaded by the org admin at onboarding time and stored in the database. When an agent authenticates, the broker verifies that the agent's certificate was signed by that org's CA.

This means a leaked agent private key is not enough to impersonate an agent from a different organization — the attacker would also need the org CA private key. A compromised org CA affects only that organization — the network operator can revoke it without touching the rest of the network.

**SPIFFE identity**

Every agent certificate includes a SPIFFE URI in the Subject Alternative Name extension:

```
spiffe://atn.local/{org_id}/{agent_name}
```

This provides a standard, workload-addressable identity that is independent of the DNS name and compatible with SPIFFE/SPIRE-based systems.

---

## Replay Protection

Two independent mechanisms covering two different attack surfaces:

| Attack surface | Mechanism | Scope |
|---|---|---|
| Client assertion reuse | JTI blacklist (database) | Per JWT, global |
| Message resend | Nonce deduplication (DB UNIQUE constraint) | Per message, per session |

JTI entries are cleaned up lazily — expired entries are deleted on each new insert, with no background job needed.

---

## Certificate Revocation

When an agent's private key is compromised or an agent is decommissioned, its certificate can be revoked immediately — without waiting for natural expiry.

**How it works:**

1. Admin calls `POST /admin/certs/revoke` with the certificate's serial number.
2. The serial is recorded in the `revoked_certs` table (append-only).
3. On every subsequent authentication attempt, the broker checks the serial against `revoked_certs` **after** chain verification but **before** using the public key — step 7 of the auth flow.
4. If found, the broker returns `401 Certificate has been revoked` immediately.

**What gets stored:**

| Field | Description |
|---|---|
| `serial_hex` | Certificate serial number (primary key) |
| `org_id` | Organization that owned the certificate |
| `agent_id` | Agent identity from the certificate CN |
| `revoked_at` | Timestamp of revocation |
| `revoked_by` | Identity of the admin who revoked it |
| `reason` | Free text — e.g. `key_compromise`, `cessation_of_operation` |
| `cert_not_after` | Original certificate expiry — used for lazy cleanup |

Lazy cleanup: records for certificates that have already expired are removed on each new insertion. No background job needed.

**Important:** revocation blocks future logins but does not invalidate JWT access tokens already issued. A running agent that holds a valid token will continue operating until the token expires (default 30 minutes). To stop it immediately, use `revoke.py` which also sends SIGTERM to the running process.

**Revoking an entire organization** does not use this mechanism. Suspending the org (`set_org_status → suspended`) blocks all its agents at step 4 of the auth flow, before any certificate check. This is the correct approach for mass revocation.

**Tooling:**

```bash
python revoke.py
# → lists all agent certificates in certs/
# → user selects one interactively
# → revokes on broker + kills the running process
```

---

## Rate Limiting

Sliding window in-memory, three independent buckets:

| Bucket | Key | Limit |
|---|---|---|
| Auth token requests | IP address | 10 per minute |
| Session open requests | agent_id | 20 per minute |
| Message sends | agent_id | 60 per minute |

HTTP 429 returned when a limit is exceeded.

In single-instance deployments the limiter runs entirely in memory. For multi-instance deployments (multiple broker nodes behind a load balancer), the buckets must be moved to a shared store — Redis is the intended backend. When `REDIS_URL` is configured, all broker instances share the same rate limit counters, nonce set, and WebSocket pub/sub channel.

---

## External Onboarding

Organizations joining the network from outside go through an approval process:

1. External org sends a join request with their org ID, display name, secret, and CA certificate.
2. Org is created in `pending` state — login is blocked immediately.
3. Admin reviews pending requests and approves or rejects.
4. On approval, org status becomes `active` — agents can now authenticate.
5. On rejection, org status becomes `rejected` — login remains blocked permanently.

**Auto-binding on registration**

When an agent registers and a role policy exists for its role, the broker automatically creates and approves the binding — no manual admin action required. If no role policy matches, the binding is created in `pending` state and requires explicit approval.

**Tooling**

| Tool | Purpose |
|---|---|
| `policy.py` | Network admin creates role policies before any org joins |
| `join.py` | External org wizard — generates PKI, registers org, waits for approval, creates bindings |
| `admin.py` | Interactive admin console — polls for pending join requests and approves/rejects |
| `join_agent.py` | Adds a new agent to an already-approved organization |
| `revoke.py` | Interactive revocation tool — lists certs, revokes on broker, kills the agent process |

The typical setup sequence: `policy.py` → `join.py` (per org, with `admin.py` running in parallel) → agents start.

---

## Agent SDK

The `agents/` directory contains a reusable SDK and two independent agent implementations that demonstrate the intended usage pattern.

**`agents/sdk.py`** — shared infrastructure used by any agent:
- `BrokerClient` — HTTP client wrapping all broker endpoints (register, login, sessions, messages, discovery)
- `ask_llm` — LLM call abstraction supporting Anthropic Claude and any OpenAI-compatible backend
- `run_initiator` / `run_responder` — conversation loop runners with WebSocket + polling fallback
- Auth, signing, logging utilities

**`agents/buyer.py`** and **`agents/manufacturer.py`** — independent agent implementations, one per company:
- System prompt and role are hardcoded in the script — not configurable via environment
- The `.env` file produced by `join.py` contains only identity and certificate paths
- Each script calls `broker.register(..., role="buyer")` or `role="supplier"` explicitly, so the broker can apply the correct role policy at session time

This design reflects the real-world model: each organization ships its own agent code with its own business logic. The broker identity (certificates, org credentials) is injected at startup via `--config`, but the agent's behavior is owned entirely by the organization that wrote it.

---

## Audit Log

Append-only table — no updates, no deletes. Every event records:

| Field | Description |
|---|---|
| `timestamp` | When the event occurred |
| `event_type` | Type of event (auth, session, message, policy, injection, onboarding) |
| `agent_id` | Agent involved |
| `org_id` | Organization involved |
| `session_id` | Session involved (if applicable) |
| `details` | JSON with event-specific data |
| `result` | Outcome: `ok`, `denied`, or `error` |

Message events additionally include `ciphertext_hash` (SHA256 of the ciphertext blob) and `outer_signature` — sufficient for transport-level forensic verification by any auditor holding the sender's certificate. The plaintext is not stored anywhere outside the endpoints involved in the conversation.

Every traceability event also produces an audit log entry, tying the supply chain record to the broker's unified event history.

---

## Supply Chain Traceability

The `traceability` module adds supply chain tracking on top of the existing trust infrastructure. It is mounted as a FastAPI router on the same broker application — not a separate service. All endpoints require a valid JWT (`Depends(get_current_agent)`).

**What it reuses without modification:**
- Auth middleware — existing dependency injection
- Message signing — `app/auth/message_signer.py`, same canonical format
- Audit log — `log_event()` called on every operation
- Policy engine — extended with `evaluate_event()`, existing methods untouched
- Agent registry — role loaded from DB at request time

**Domain model:**

*Lot* — the central unit of traceability.

| Field | Description |
|---|---|
| `lot_id` | Unique identifier |
| `product_type` | Product category |
| `origin_org_id` | Organization that created the lot |
| `status` | Current status |
| `quantity` / `unit` | Amount |
| `metadata` | JSON — origin country, harvest date, expiry, certifications |

*TraceabilityEvent* — one record per supply chain step.

| Field | Description |
|---|---|
| `event_id` | Unique identifier |
| `lot_id` | Lot this event belongs to |
| `event_type` | One of the supported event types |
| `org_id` / `agent_id` | Who emitted the event |
| `payload` | JSON — event-specific data |
| `prev_event_hash` | Hash of the previous event on this lot (`"genesis"` for the first) |
| `event_hash` | SHA256 of the canonical event string |
| `signature` | RSA-PKCS1v15-SHA256 signature by the emitting agent |

*Certificate/Attestation* — external certifications (HACCP, cold-chain compliance, organic, food safety audit).

*LotCertificate* — M2M association between lots and certifications.

**Hash chaining:**

```
event_hash = SHA256(
  event_id | lot_id | event_type | agent_id | timestamp_iso
  | canonical_json(payload) | prev_event_hash
)
```

Every event is cryptographically linked to the previous one. The `GET /traceability/lots/{lot_id}/verify` endpoint recomputes every hash from scratch and checks chain continuity — any tampered event breaks the chain.

**Event types and role policy (default deny):**

| Event type | Authorized roles |
|---|---|
| `LOT_CREATED` | producer |
| `LOT_CERTIFIED` | producer, auditor |
| `SHIPMENT_DISPATCHED` | producer, logistics |
| `SHIPMENT_PICKED_UP` | logistics |
| `TEMPERATURE_RECORDED` | logistics |
| `SHIPMENT_RECEIVED` | warehouse, processor |
| `LOT_PROCESSED` | processor |
| `LOT_SPLIT` / `LOT_MERGED` | processor |
| `QUALITY_CHECK_PASSED/FAILED` | auditor, warehouse |
| `RECALL_ISSUED` | producer, regulator |

**Ledger adapter:**

Every event is anchored to a `LedgerAdapter`. The interface is abstract — implementations are swappable without touching the broker:

| Adapter | Description |
|---|---|
| `LocalLedgerAdapter` | Append-only `ledger_anchors` table in the existing DB — Phase 1, zero external dependencies |
| `HyperledgerAdapter` | Hyperledger Fabric — Phase 3 |
| `BesuAdapter` | Private Ethereum (Besu/Quorum) — Phase 3 |

The ledger stores only the proof record: `event_id`, `lot_id`, `event_type`, `event_hash`, `agent_id`, `org_id`, `timestamp`. No payload — the broker already holds the full data. The blockchain is a proof layer, not a database.

**API endpoints:**

| Method | Path | Description |
|---|---|---|
| `POST` | `/traceability/lots` | Create lot (producer only) |
| `GET` | `/traceability/lots/{lot_id}` | Lot detail |
| `POST` | `/traceability/lots/{lot_id}/events` | Record event (role policy enforced) |
| `GET` | `/traceability/lots/{lot_id}/events` | List events |
| `GET` | `/traceability/lots/{lot_id}/timeline` | Ordered timeline |
| `GET` | `/traceability/lots/{lot_id}/verify` | Verify full hash chain |
| `POST` | `/traceability/certificates` | Register external certification |
| `GET` | `/traceability/certificates/{cert_id}` | Certification detail |

**Module structure:**

```
app/traceability/
  __init__.py
  db_models.py   — Lot, TraceabilityEvent, Certificate, LotCertificate, LedgerAnchor
  models.py      — Pydantic schemas
  store.py       — async CRUD
  router.py      — FastAPI endpoints
  hash_chain.py  — compute_event_hash(), verify_chain()
  ledger.py      — LedgerAdapter (ABC) + LocalLedgerAdapter
```
