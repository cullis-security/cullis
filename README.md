# Agent Trust Network

> Federated trust broker for inter-organizational AI agents.

---

## The Problem

Today, when two companies want their AI agents to communicate, there is no standard way to do it securely. Every integration is custom-built, unverifiable, and brittle. There is no way to prove who an agent is, control what it can do, or audit what happened.

Agent Trust Network is a broker that sits between organizations and solves exactly this — verified identities, explicit authorization, and a full audit trail for every interaction between agents.

Think of it as ADFS, but for AI agents across organizational boundaries.

---

## What It Provides

**Identity** — every agent has an x509 certificate signed by its organization. The broker verifies the full chain before allowing anything.

**Authorization** — org admins explicitly approve which agents can operate and with what capabilities. No approval, no access.

**Policy** — session-level rules define who can talk to whom. Default is deny: without an explicit policy, no session opens.

**Audit** — every event is logged with a cryptographic signature. Messages cannot be altered after the fact, not even by the broker.

**Security in depth** — replay protection, rate limiting, prompt injection detection, persistent sessions that survive broker restarts.

**Openness** — agents can run on any LLM: Anthropic Claude, OpenAI, Ollama, or any OpenAI-compatible backend.

---

## How It Works (Simple View)

```
Org A (buyer)                    Broker                   Org B (manufacturer)
─────────────                ─────────────────            ────────────────────
procurement-agent  ──────→   verifies identity  ←──────  sales-agent
                             checks policy
                             inspects messages
                             logs everything
```

1. Each organization registers with the broker and uploads its CA certificate
2. Org admins approve which agents can operate and what they can do
3. Agents authenticate with x509 certificates — no passwords, no API keys
4. The broker enforces policy, inspects every message, and logs everything
5. Neither organization needs to trust the other directly — they both trust the broker

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
| Prompt injection | Regex fast path + LLM judge on every inter-agent message |
| Message tampering | Every message is signed by the sender; broker verifies before storing |
| DoS | Rate limiting per agent and per IP |
| Broker restart | Sessions persist to DB and restore automatically on startup |

---

## Status

- 94/94 tests passing
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
- [x] Prompt injection detection
- [x] Message signing and non-repudiation
- [x] PostgreSQL
- [x] Agent discovery by capability
- [x] External onboarding wizard
- [x] Multi-LLM backend support
- [ ] A2A protocol integration (Agent2Agent, Linux Foundation)
- [ ] MCP proxy — authorize and audit tool calls
- [ ] Certificate revocation
- [ ] Admin dashboard
- [ ] Redis + horizontal scaling

---

## Feedback & Contact

This is a research project. If you work on AI agent infrastructure, multi-agent systems, or enterprise security and want to discuss the design — open an issue or reach out directly.

Code available on request.
