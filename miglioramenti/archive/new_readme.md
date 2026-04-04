# Agent Trust Network (ATN)

> A Federated Trust Router and Credential Broker for inter-organizational AI agents, aligned with emerging IETF standards (WIMSE & CB4A).

---

## The Problem: Credential Sprawl & Trust Boundaries

Today, AI agents are mostly deployed inside isolated organizational boundaries. As these semi-autonomous systems begin to interact across organizations, a critical security challenge emerges: **Credential Sprawl**.

Agents are given long-lived API keys or static OAuth tokens to communicate. This creates standing privileges that aggregate access across many services, turning agents and AI gateways into high-value compromise targets. Furthermore, organizations cannot blindly trust external agents without explicit, real-time control over what those agents are authorized to do.

---

## The Solution: Federated Trust Router

Agent Trust Network (ATN) solves this by acting as a **Credential Broker for Agents (CB4A)**. It physically separates two responsibilities that traditional systems conflate:

- The **Broker** is the **Credential Delivery Point (CDP)**: it verifies cryptographic identity, enforces transport integrity, and delivers short-lived credentials. It never stores business policies.
- Each **Organization** is its own **Policy Decision Point (PDP)**: it exposes a webhook that the broker calls in real time. The organization's internal IT systems decide allow or deny — the broker only enforces the outcome.

This separation means the network operator has zero visibility into organizational business logic, and organizations have zero dependency on a centralized policy engine.

### Architecture

```
                              Task Request Envelope
Org A Agent  ──────────→  [ Credential Broker (CDP) ]  ──────────→  Org B Agent
                                  (Trust Router)
                                       ↑↓  ↑↓
                     [ Org A PDP Webhook ]  [ Org B PDP Webhook ]
                       (Org A IT system)      (Org B IT system)
```

**Flow:**
1. Agent A submits a session request with a signed Task Request Envelope (identity + capabilities).
2. The Broker verifies the cryptographic workload identity (x509 + SPIFFE).
3. The Broker calls both organizations' PDP webhooks with the request context.
4. Only if **both** return `allow`, the Broker issues short-lived, narrowly scoped credentials.
5. All decisions are recorded in an immutable audit ledger.

---

## Core Capabilities (Implemented)

### 1. Workload Identity — WIMSE aligned
Agents authenticate via a **3-tier PKI model**: Broker CA → Org CA → Agent Certificate. Each agent carries a SPIFFE-style identity (`spiffe://trust-domain/org/agent`) embedded in the x509 SAN. No passwords. No API keys.

### 2. End-to-End Encrypted Messaging
The broker **never reads message plaintext**. Every message uses a hybrid encryption scheme:
- **AES-256-GCM** for payload encryption (with session-bound AAD — prevents cross-session replay)
- **RSA-OAEP-SHA256** for key encapsulation
- **Two-layer RSA-PSS signing**: inner signature for non-repudiation (recipient verifies sender), outer signature for transport integrity (broker verifies sender before forwarding)

### 3. Immutable Audit Trail
Every authentication, session, and policy decision is recorded in an **append-only cryptographic ledger** — no UPDATE or DELETE operations on audit records. Acts as a neutral notary for inter-organizational disputes.

### 4. Enterprise KMS Integration
The broker's root signing key never lives on disk in production. ATN implements a **KMS Adapter pattern**:

```
KMS_BACKEND=local   → filesystem (dev/test)
KMS_BACKEND=vault   → HashiCorp Vault KV v2 (default in Docker)
KMS_BACKEND=azure   → Azure Key Vault         (add provider, swap env var)
KMS_BACKEND=aws     → AWS KMS                 (add provider, swap env var)
```

HashiCorp Vault ships in the default `docker-compose.yml`. Changing the backend requires zero code changes — only a different environment variable.

### 5. Real-Time WebSocket Messaging
Agents receive session invitations and messages via **WebSocket push** with automatic fallback to REST polling. The broker pushes events; agents do not poll.

### 6. Prompt Injection Defense
Every inter-agent message passes through a two-stage detection pipeline:
- **Regex fast path** — blocks known injection patterns with zero latency
- **LLM judge** (optional, Anthropic API) — semantic analysis for novel attacks

---

## Roadmap

| Feature | Status |
|---------|--------|
| x509 PKI + SPIFFE identity | ✅ Implemented |
| JWT RS256 access tokens | ✅ Implemented |
| E2E AES-256-GCM + RSA-OAEP | ✅ Implemented |
| Two-layer RSA-PSS message signing | ✅ Implemented |
| Immutable audit log | ✅ Implemented |
| WebSocket real-time push | ✅ Implemented |
| Rate limiting | ✅ Implemented |
| Prompt injection detection | ✅ Implemented |
| KMS Adapter (Vault KV v2) | ✅ Implemented |
| PDP Webhook (external org policies) | ✅ Implemented |
| Redis Pub/Sub (horizontal scaling) | 🔜 Next |
| DPoP (RFC 9449) token binding | ✅ Implemented |
| OpenTelemetry observability | 🔜 Planned |

---

## Deployment

ATN is designed for **private hub** or **managed network** deployments:

```bash
# One-command setup (PKI + Docker + Vault + bootstrap)
./setup.sh

# Services started:
#   Broker    http://localhost:8000
#   Vault     http://localhost:8200
#   Postgres  localhost:5432
#   Redis     localhost:6379
```

**Cloud-agnostic by design.** No dependency on AWS, Azure, or GCP APIs. Runs on any server, on-premise or cloud — including the private datacenter of a bank.

---

## Positioning

ATN is not a traditional Identity Provider (Okta) nor a standard API Gateway. It is purpose-built for the AI era:

| | Traditional IAM | AI Proxy/Gateway | **ATN** |
|---|---|---|---|
| Identity model | Human users, static roles | API keys, OAuth tokens | Workload x509 + SPIFFE |
| Policy location | Centralized | Centralized | **Federated (each org)** |
| Credential lifetime | Long-lived | Long-lived | **Short-lived, scoped** |
| Message security | None | TLS only | **E2E encrypted + signed** |
| Audit | Logs | Logs | **Cryptographic ledger** |
| On-premise | Sometimes | Rarely | **Always** |

If agents are to operate securely across organizations, we need a way to trust them, control them, and audit them — without centralizing power in a single operator. ATN provides the infrastructure to make this possible.
