# Agent Trust Network

> Federated trust broker for inter-organizational AI agents.

Agent Trust Network is an authentication and policy broker that enables AI agents from different organizations to communicate securely — with verified identities, explicit authorization, controlled scopes, and a full audit trail.

Think of it as ADFS, but for AI agents across organizational boundaries.

---

## Why

There is no standard for authenticated, auditable, policy-controlled communication between AI agents of different organizations. Every integration today is ad hoc, unverifiable, and brittle.

Agent Trust Network provides:

- **Verified identity** — every agent authenticates with an x509 certificate signed by its organization's CA
- **Explicit authorization** — org admins approve which agents can operate and with what scope (binding)
- **Policy enforcement** — session-level rules define who can talk to whom (default-deny)
- **Non-repudiation** — append-only audit log on every event
- **Replay protection** — JWT jti blacklist on every client assertion + per-message nonce enforcement
- **Persistent sessions** — sessions survive broker restart; agents resume without user intervention
- **Rate limiting** — per-agent and per-IP sliding window limits on auth, sessions, and messages
- **End-to-end message encryption** — payload encrypted with recipient's public key (AES-256-GCM + RSA-OAEP); the broker is a blind forwarder and cannot read message content
- **Message signing (two layers)** — inner signature on plaintext (non-repudiation, verified by recipient); outer signature on ciphertext (transport integrity, verified by broker)
- **Agent discovery** — agents can search for counterparties by capability across organizations
- **External onboarding** — organizations join the network via a self-service wizard (`join.py`), pending TrustLink admin approval
- **Multi-LLM backend** — agents can run on any OpenAI-compatible LLM (Ollama, vLLM, OpenAI, Azure) or Anthropic Claude; configured per-agent in `.env`

---

## Architecture

```
Org A (buyer)                    Broker                   Org B (manufacturer)
─────────────                ─────────────────            ────────────────────
procurement-agent  ──────→   /auth/token (x509)  ←──────  sales-agent
                             /broker/sessions
                             /broker/ws (push)
                             /policy/rules
                             /registry/bindings
                             /db/audit
```

### PKI

```
Broker CA (RSA 4096)
├── Org CA manufacturer (RSA 2048)
│   └── sales-agent cert (RSA 2048)
└── Org CA buyer (RSA 2048)
    └── procurement-agent cert (RSA 2048)
```

Each agent holds a certificate signed by its organization's CA. The broker verifies the full chain before issuing any session token.

---

## Modules

| Module | Path | Responsibility |
|---|---|---|
| Auth | `app/auth/` | x509 client assertion verify, JWT RS256 issue, JTI blacklist |
| Registry | `app/registry/` | Organizations, agents, bindings, org CA storage, capability discovery, public-key endpoint |
| Broker | `app/broker/` | Sessions, messages, WebSocket push, persistence, restore |
| Policy | `app/policy/` | Session default-deny + message policy evaluation |
| Onboarding | `app/onboarding/` | External org join requests, admin approval/reject |
| Rate Limit | `app/rate_limit/` | Sliding window limiter — auth, session, message buckets |
| Injection | `app/injection/` | Prompt injection detection — regex fast path + Haiku LLM judge (client-side, not broker) |
| Signing | `app/auth/message_signer.py` | RSA-PKCS1v15-SHA256 sign + verify — outer (broker) and inner (recipient) |
| E2E Crypto | `app/e2e_crypto.py` | AES-256-GCM + RSA-OAEP hybrid encryption/decryption for inter-agent messages |
| Audit | `app/db/audit.py` | Append-only event log — includes ciphertext hash + outer signature per message |

---

## Quick Start

### Prerequisites

```bash
nix-shell   # loads Python 3.11 + pip + virtualenv
```

Or manually:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Internal demo (bootstrap)

```bash
# 1. Generate broker CA
python generate_certs.py

# 2. Start broker
./run.sh &

# 3. Bootstrap: register orgs, approve bindings, create policies
sleep 2 && python bootstrap.py

# 4. Start agents (two separate terminals)
./agent.sh --config agents/manufacturer.env   # responder (h24)
./agent.sh --config agents/buyer.env          # initiator
```

### External organization onboarding (join.py)

For organizations joining the network from outside:

```bash
# On the external machine — interactive wizard
python join.py
# Prompts for: broker URL, org ID, display name, secret, contact email, agent IDs
# Generates x509 certs, sends join request, waits for admin approval

# TrustLink admin approves (separate terminal)
curl -s -X POST http://<broker>/admin/orgs/<org_id>/approve \
     -H 'x-admin-secret: <ADMIN_SECRET>'

# join.py detects approval, creates bindings, prints agent start command
python agents/client.py --config certs/<org_id>/<agent_id>.env
```

### LLM backend configuration

By default agents use Anthropic Claude. To use any OpenAI-compatible backend, set in the agent's `.env`:

```bash
# Ollama (local)
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama3.2
LLM_API_KEY=not-needed

# OpenAI
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o
LLM_API_KEY=sk-...

# Anthropic (default — leave LLM_BASE_URL empty)
LLM_MODEL=claude-sonnet-4-6
ANTHROPIC_API_KEY=sk-ant-...
```

### Reset (clean demo)

```bash
./reset.sh                # drops Postgres tables + removes certs/
python generate_certs.py  # regenerate broker CA
```

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
  │                 3. Extract cert from x5c
  │                 4. Load org CA from DB
  │                 5. Verify cert chain (org CA → agent cert)
  │                 6. Verify cert validity period
  │                 7. Verify JWT signature with cert pubkey
  │                 8. Verify sub == CN in cert
  │                 9. Check approved binding for (org, agent)
  │                10. Verify jti not in blacklist, consume it
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

## End-to-End Encryption and Message Signing

Messages are end-to-end encrypted: the broker is a blind forwarder and cannot read the content of any inter-agent message.

**Cryptographic scheme:** hybrid AES-256-GCM (payload) + RSA-OAEP-SHA256 (AES key wrapping).

**Two-layer signing:**
- **Inner signature** — sender signs the plaintext payload; only the recipient can verify it after decrypting (non-repudiation)
- **Outer signature** — sender signs the ciphertext blob; the broker verifies it before forwarding (transport integrity)

```
Agent A                              Broker                          Agent B
  │                                     │                               │
  │  1. inner_sig = sign(plaintext)     │                               │
  │  2. cipher = encrypt(plaintext      │                               │
  │             + inner_sig,            │                               │
  │             B.pubkey)               │                               │
  │  3. outer_sig = sign(cipher)        │                               │
  │──── POST .../messages ────────────→ │                               │
  │     { cipher, nonce, outer_sig }    │                               │
  │                                     │  4. verify(outer_sig, A.cert) │
  │                                     │  5. store cipher + outer_sig  │
  │                                     │  6. audit_log(hash, outer_sig)│
  │←── 202 Accepted ────────────────── │                               │
  │                                     │── WS push: new_message ──────→│
  │                                     │                               │  7. decrypt(cipher, B.privkey)
  │                                     │                               │  8. verify(inner_sig, A.cert)
```

**What this guarantees:**
- The broker cannot read any message payload — it only sees an opaque encrypted blob
- The outer signature prevents the broker from forwarding tampered ciphertext
- The inner signature gives the recipient proof of origin, independent of the broker
- The audit log entry contains `ciphertext_hash` + `outer_signature` — sufficient for transport-level forensics

**Recipient public key** is fetched via:
```
GET /registry/agents/{agent_id}/public-key
```
The public key is extracted from the certificate stored in DB at login time.

---

## Security — Threat Model

| Threat | Mitigation |
|---|---|
| Agent impersonation | x509 cert + chain verification against org CA |
| Replay on authentication | JTI blacklist: each client assertion consumed once, stored until expiry |
| Replay on message | Nonce UUID consumed once per session (in-memory + DB UNIQUE constraint) |
| Unauthorized agent | Binding must be explicitly approved by org admin |
| Cross-org impersonation | org_id extracted from cert O field, checked against registry |
| Out-of-scope capability | Scope enforced on every session open |
| Unauthorized session | Policy engine: session default-deny, explicit allow required |
| Fake CA | Org CA uploaded by org admin separately, stored in broker DB |
| Runaway agent / DoS | Rate limiting: 10 auth/min per IP, 20 sessions/min and 60 msg/min per agent |
| Broker restart data loss | Session persistence: write-through SQLite, automatic restore on startup |
| Broker reading message content | E2E encryption: AES-256-GCM + RSA-OAEP; broker sees only ciphertext |
| Ciphertext tampering in transit | Outer RSA signature on ciphertext blob — broker verifies before storing |
| Message repudiation | Inner RSA signature on plaintext — verified by recipient after decryption |
| Prompt injection via payload | Detection moved client-side (sdk.py); broker blind to plaintext by design |
| Audit log tampering | Ciphertext SHA256 hash + outer signature stored in audit log |

---

## Tests

```bash
pytest tests/ -v
```

**136/136 passing** — coverage: auth, registry, broker, policy engine, x509 chain verification, session persistence, rate limiting, injection detection (unit), E2E encryption, message signing (inner + outer), discovery, onboarding, role-based policy, certificate revocation.

PKI in tests is ephemeral and in-memory (injected via `conftest.py`) — no filesystem dependency.

---

## Stack

| Component | Technology |
|---|---|
| API | Python 3.11, FastAPI, Uvicorn |
| Auth | JWT RS256 (python-jose), x509 (cryptography) |
| Database | SQLAlchemy async + PostgreSQL (asyncpg) / SQLite for tests |
| Messaging | REST + WebSocket (websockets) |
| AI Agents | Anthropic Claude (default) or any OpenAI-compatible LLM |
| Tests | pytest-asyncio |

---

## Roadmap

- [x] Broker base — JWT RS256, registry, audit log
- [x] Organizations + mandatory binding + scope enforcement
- [x] Policy engine — session default-deny, message default-allow
- [x] WebSocket push notifications
- [x] Claude agents — initiator/responder roles, B2B negotiation demo
- [x] x509 authentication — PKI, client assertion, chain verification
- [x] JTI blacklist — full replay protection server-side
- [x] Persistent sessions — survive broker restart, automatic restore + agent resume
- [x] Rate limiting — sliding window per agent and per IP
- [x] Prompt injection detection — regex fast path + Haiku LLM judge (unit-tested; client-side enforcement)
- [x] Message signing — RSA-PKCS1v15-SHA256, broker verifies outer sig on ciphertext, inner sig verified by recipient
- [x] E2E message encryption — AES-256-GCM + RSA-OAEP hybrid; broker is a blind forwarder
- [x] PostgreSQL — production database with asyncpg, Docker container
- [x] Agent discovery — capability-based cross-org search
- [x] Responder h24 — infinite loop, handles multiple sessions without restarting
- [x] External onboarding — `join.py` wizard, pending/approved/rejected states, admin approval API
- [x] Multi-LLM backend — OpenAI-compatible API support (Ollama, vLLM, OpenAI, Azure, ...)
- [x] Role-based policy — auto-binding on agent registration, role-to-role session policy
- [x] Certificate revocation — `revoked_certs` table, check in x509 verifier, `revoke.py` CLI

---

## Demo

See [`showcase/`](showcase/) for the full demo log (PKI generation, bootstrap, broker, agents) — files `07-demo-*.md`.
