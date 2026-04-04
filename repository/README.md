# Agent Trust Network

> Managed trust network for inter-organizational AI agents.

---

## The Problem

Today, when two companies want their AI agents to communicate, there is no standard way to do it securely. Every integration is custom-built, unverifiable, and brittle. There is no way to prove who an agent is, control what it can do, or audit what happened.

Agent Trust Network is a managed network infrastructure operated by a single trusted authority. Organizations connect their agents to the network — they do not run their own broker. The operator guarantees identity, authorization, and a full audit trail for every interaction between agents across organizational boundaries.

---

## What It Provides

**Identity** — every agent has an x509 certificate signed by its organization, with a SPIFFE URI as its workload identity. The broker verifies the full chain before allowing anything.

**Authorization** — org admins explicitly approve which agents can operate and with what capabilities. No approval, no access.

**Policy** — role-based rules define who can talk to whom across the entire network. A network admin defines `role:buyer → role:supplier` once; every buyer agent can then reach every supplier agent without per-org configuration. Default is deny: without an explicit policy, no session opens.

**Audit** — every event is logged with a cryptographic signature. Messages cannot be altered after the fact, not even by the broker.

**Supply chain traceability** — a dedicated module lets authenticated agents record lot events (creation, shipment, processing, recall) with cryptographic hash chaining. Every event is signed by the emitting agent and linked to the previous event on the same lot. A tamper-evident local ledger anchors event hashes; the adapter is designed to be swapped with a permissioned blockchain (Hyperledger Fabric, Besu) without touching the rest of the code.

**Security in depth** — replay protection, rate limiting, prompt injection detection, persistent sessions that survive broker restarts.

**Openness** — agents can run on any LLM: Anthropic Claude, OpenAI, Ollama, or any OpenAI-compatible backend.

---

## How It Works (Simple View)

```
Org A (buyer)                    Broker                   Org B (manufacturer)
─────────────                ─────────────────            ────────────────────
procurement-agent  ──────→   verifies identity  ←──────  sales-agent
                             checks policy
                             forwards encrypted messages
                             logs everything
```

1. The network operator defines role policies once (`role:buyer → role:supplier`)
2. Each organization joins the network — generates its own agent certificates, submits a join request, waits for operator approval
3. Agents authenticate with x509 certificates — no passwords, no API keys shared with other organizations
4. The broker enforces policy, inspects every message, and logs everything
5. Neither organization needs to trust the other directly — they both trust the network operator

For a technical deep dive into the flows and design decisions, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Threat Model

| Threat | What the broker does |
|---|---|
| Agent impersonation | Verifies x509 certificate chain against the org's CA |
| Replay attacks | Blacklists used JWT IDs; enforces unique nonce per message |
| Unauthorized agent | Requires explicit binding approval from org admin |
| Scope violation | Enforces capabilities from approved binding, not from client claims |
| Unauthorized session | Default-deny policy engine — no policy means no session |
| Broker reading message content | Messages are E2E encrypted (AES-256-GCM + RSA-OAEP) — the broker sees only ciphertext |
| Ciphertext tampering in transit | Outer RSA signature on the ciphertext blob — broker verifies before storing |
| Message repudiation | Inner RSA signature on the plaintext — verified by the recipient after decryption |
| Prompt injection via payload | Detection runs client-side on decrypted plaintext before passing to the LLM |
| DoS | Rate limiting per agent and per IP |
| Broker restart | Sessions persist to DB and restore automatically on startup |
| Compromised agent key | Certificate revocation blocks the cert immediately; `revoke.py` also kills the running process |
| Lot event tampering | Hash chaining links every traceability event to the previous one; any modification breaks the chain |
| Unauthorized lot event | Role-based policy (evaluate_event) — only authorized roles can emit each event type |

---

## Status

- 136/136 tests passing
- Full demo: two Claude agents negotiating a B2B order across two organizations
- Stack: Python 3.11, FastAPI, PostgreSQL, x509, JWT RS256, WebSocket

---

## Roadmap

- [x] x509 authentication and PKI
- [x] Organization registry and mandatory binding
- [x] Policy engine — session default-deny
- [x] WebSocket push notifications
- [x] Replay protection — JTI blacklist + per-message nonce
- [x] Persistent sessions
- [x] Rate limiting
- [x] Prompt injection detection (client-side)
- [x] Message signing — two layers: outer on ciphertext (broker), inner on plaintext (recipient)
- [x] End-to-end message encryption — AES-256-GCM + RSA-OAEP; broker is a blind forwarder
- [x] PostgreSQL
- [x] Agent discovery by capability
- [x] External onboarding wizard
- [x] Multi-LLM backend support
- [x] Certificate revocation
- [x] Role-based policy engine — network-wide `role:buyer → role:supplier` rules
- [x] SPIFFE workload identity in x509 SAN
- [x] Agent role registry and automatic binding approval
- [ ] Supply chain traceability — lot events, hash chaining, ledger adapter
- [ ] MCP proxy — authorize and audit tool calls
- [ ] Admin dashboard
- [ ] Redis + horizontal scaling

---

## Feedback & Contact

If you work on AI agent infrastructure, multi-agent systems, or enterprise security and want to discuss the design — open an issue or reach out directly.
