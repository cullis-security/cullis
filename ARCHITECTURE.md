# Architecture

Deep dive into the Agent Trust Network design — modules, data flows, and key decisions.

---

## Modules

| Module | Path | Responsibility |
|---|---|---|
| Auth | `app/auth/` | x509 client assertion verify, JWT RS256 issue, JTI blacklist |
| Registry | `app/registry/` | Organizations, agents, bindings, org CA storage, capability discovery |
| Broker | `app/broker/` | Sessions, messages, WebSocket push, persistence, restore |
| Policy | `app/policy/` | Session default-deny + message policy evaluation |
| Onboarding | `app/onboarding/` | External org join requests, admin approval/reject |
| Rate Limit | `app/rate_limit/` | Sliding window limiter — auth, session, message buckets |
| Injection | `app/injection/` | Prompt injection detection — regex fast path + Haiku LLM judge |
| Signing | `app/auth/message_signer.py` | RSA-PKCS1v15-SHA256 sign + verify for every inter-agent message |
| Audit | `app/db/audit.py` | Append-only event log — payload hash + signature per message |

---

## Authentication Flow

```
Agent                          Broker
  │                               │
  │  1. Build client_assertion    │
  │     JWT RS256, signed with    │
  │     agent private key         │
  │     header: x5c=[agent cert]  │
  │                               │
  │──── POST /auth/token ────────→│
  │     { client_assertion }      │
  │                               │
  │                 2. Rate limit check (10 req/min per IP)
  │                 3. Extract cert from x5c header
  │                 4. Load org CA from DB
  │                 5. Verify cert chain (org CA → agent cert)
  │                 6. Verify cert validity period
  │                 7. Verify JWT signature with cert pubkey
  │                 8. Verify sub == CN in cert
  │                 9. Check approved binding for (org, agent)
  │                10. Verify jti not in blacklist, consume it
  │                11. Store agent cert_pem in DB
  │                               │
  │←── { access_token } ─────────│
  │    JWT RS256, signed by       │
  │    broker CA                  │
```

---

## Session Flow

```
buyer                          Broker                     manufacturer
  │                               │                               │
  │── POST /broker/sessions ─────→│                               │
  │   { target: manufacturer }    │── WS push: session_pending ──→│
  │                               │                               │
  │                               │←── POST /sessions/{id}/accept─│
  │                               │                               │
  │── POST /sessions/{id}/messages→│── WS push: new_message ─────→│
  │                               │                               │
  │←─────────── WS push: new_message ────────────────────────────│
  │                               │                               │
  │── POST /sessions/{id}/close ──→│                              │
  │                               │── WS push: session_closed ───→│
```

---

## Message Signing Flow

```
Agent A                         Broker
  │                               │
  │  1. canonical = session_id|sender|nonce|json(payload)
  │  2. signature = RSA-PKCS1v15-SHA256(canonical, priv_key)
  │                               │
  │──── POST .../messages ───────→│
  │     { payload, nonce,         │
  │       signature }             │
  │                               │  3. load cert_pem from DB
  │                               │  4. verify(signature, cert.pubkey)
  │                               │  5. store message + signature
  │                               │  6. audit_log(payload_hash, signature)
  │←── 202 Accepted ─────────────│
```

Canonical JSON uses `sort_keys=True, separators=(",",":")` — deterministic regardless of serialization order.

---

## Injection Detection Pipeline

```
Incoming message payload
         │
         ▼
   regex fast path ──── match → HTTP 400 (zero latency)
         │ no match
         ▼
   is_suspicious()?
   • payload > 300 chars
   • newlines in string values        ── no → store + forward
   • markdown/HTML present
         │ yes
         ▼
   Haiku LLM judge
   • confidence ≥ 0.7 → HTTP 400 + audit log
   • clean → store + forward
```

**Regex patterns (fast path):** instruction override, role hijack, DAN jailbreak, system tags, Human/Assistant tags, prompt leak, null bytes, unicode direction tricks (RTL, zero-width chars).

---

## Session Persistence

Every session state change is immediately written to DB (write-through). On broker startup:

```
restore_sessions()
  │
  ├── Query sessions WHERE status IN ('pending', 'active') AND expires_at > now
  ├── For each session:
  │   ├── Reconstruct Session object
  │   ├── Reload message list from session_messages
  │   └── Rebuild used_nonces set
  └── Restore to in-memory SessionStore
```

Agents resume without intervention. Broker restart is transparent.

---

## Policy Engine

**Sessions: default-deny**
No policy = session rejected. A policy must explicitly allow the session with matching conditions:
- `target_org_id`: which org the initiator can reach
- `capabilities`: required scope overlap
- `max_active_sessions`: concurrency limit

**Messages: default-allow**
No policy = message passes. A policy can block with:
- `max_payload_size_bytes`
- `required_fields`: must be present in payload
- `blocked_fields`: must not be present in payload

---

## PKI Design

Three-level hierarchy:

```
Broker CA (RSA 4096, 10 years)          ← generated once, controls the network
├── Org CA (RSA 2048, 5 years)          ← generated per organization
│   └── Agent cert (RSA 2048, 1 year)   ← generated per agent
```

The broker trusts **org CAs**, not individual agent certificates. When an agent authenticates:
1. Org CA is loaded from DB (uploaded by org admin at onboarding)
2. Chain is verified: agent cert must be signed by that org's CA
3. `org_id` is extracted from the cert's `O` (Organization) field — not from the JWT claim

This means: a compromised agent private key is useless without the org CA private key. And `.env` alone is not enough to impersonate an agent.

---

## Rate Limiting

Sliding window in-memory per bucket:

| Bucket | Key | Limit |
|---|---|---|
| `auth.token` | IP address | 10 req/min |
| `broker.session` | agent_id | 20 req/min |
| `broker.message` | agent_id | 60 req/min |

HTTP 429 returned when exceeded.

---

## Replay Protection

Two separate mechanisms for two different attack surfaces:

| Vector | Mechanism | Scope |
|---|---|---|
| Client assertion reuse | JTI blacklist (DB) | Per-JWT, global |
| Message resend | Nonce deduplication (DB UNIQUE) | Per-session |

JTI entries are lazily cleaned up on each new insert (expired JTIs deleted before adding the new one) — no background job needed.

---

## External Onboarding

```
External Org                    Broker                   Admin
     │                             │                        │
     │── POST /onboarding/join ───→│ (org status: pending)  │
     │                             │                        │
     │                             │←── GET /admin/orgs/pending ──│
     │                             │                        │
     │                             │←── POST /admin/orgs/{id}/approve ─│
     │                             │ (org status: active)   │
     │                             │                        │
     │── POST /auth/token ────────→│ (now allowed)          │
```

Login is blocked for orgs in `pending` or `rejected` state — checked in `x509_verifier.py` before issuing any token.

---

## Audit Log

Append-only table. Every event records: `timestamp`, `event_type`, `agent_id`, `org_id`, `session_id`, `details` (JSON), `result` (ok/denied/error).

Events covered: auth token issued/denied, session created/accepted/closed, message forwarded/blocked, policy evaluated, injection blocked, onboarding join/approve/reject.

Message events include `payload_hash` (SHA256) and `signature` — sufficient for forensic verification by any auditor with the sender's certificate.
