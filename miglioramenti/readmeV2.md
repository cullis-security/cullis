# Agent Trust Network (ATN)

> Federated Trust Router and Credential Broker for inter-organizational AI agents.
> Aligned with IETF WIMSE (Workload Identity in Multi-System Environments) and the emerging CB4A (Credential Broker for Agents) pattern.

---

## The Problem

As AI agents begin operating across organizational boundaries, a critical security gap emerges. Today's agents rely on long-lived API keys and static OAuth tokens — creating **standing privileges** that aggregate access across services and turn AI gateways into high-value compromise targets.

Organizations cannot blindly trust external agents. They need real-time, fine-grained control over what an agent is authorized to do — without surrendering that control to a centralized operator.

---

## The Solution: Federated Trust Router

ATN acts as a **Credential Broker** that physically separates two concerns:

- **The Broker (Credential Delivery Point)** — verifies cryptographic identity, enforces transport integrity, delivers short-lived credentials. It never stores business policies.
- **Each Organization (Policy Decision Point)** — exposes a webhook that the broker calls in real time. The organization's own IT systems decide allow or deny. The broker only enforces the outcome.

This means the network operator has **zero visibility** into organizational business logic, and organizations have **zero dependency** on a centralized policy engine.

```
                              Task Request Envelope
Org A Agent  ──────────>  [ Credential Broker (CDP) ]  ──────────>  Org B Agent
                                (Trust Router)
                                     |   |
                   [ Org A PDP Webhook ] [ Org B PDP Webhook ]
                     (Org A IT system)    (Org B IT system)
```

**Session Flow:**
1. Agent A submits a session request with a signed Task Request Envelope.
2. The Broker verifies the cryptographic workload identity (x509 + SPIFFE).
3. The Broker calls **both** organizations' PDP webhooks with the request context.
4. Only if both return `allow`, the Broker issues short-lived, DPoP-bound credentials.
5. All decisions are recorded in an immutable audit ledger.

---

## Security Architecture

### Workload Identity — WIMSE Aligned

Agents authenticate via a **3-tier PKI model**: Broker CA > Org CA > Agent Certificate. Each agent carries a SPIFFE-style identity (`spiffe://trust-domain/org/agent`) embedded in the x509 SAN.

No passwords. No API keys. No shared secrets between organizations.

### DPoP Token Binding — RFC 9449

Every access token is **bound to an ephemeral key** held by the agent (Demonstrating Proof of Possession). Even if a token is intercepted, it cannot be used without the agent's private key.

- Ephemeral EC P-256 key pair per session
- Per-request DPoP proof (method + URL + token hash)
- **Server Nonce (RFC 9449 §8)** — server-issued nonce rotated every 5 min, eliminates clock skew
- JTI replay protection with strict time window
- Mandatory on every endpoint — plain Bearer tokens are rejected

### End-to-End Encrypted Messaging

The broker **never reads message plaintext**. Every message uses hybrid encryption:

- **AES-256-GCM** for payload encryption (session-bound AAD prevents cross-session replay)
- **RSA-OAEP-SHA256** for key encapsulation
- **Two-layer RSA-PSS signing**: inner signature for non-repudiation (recipient verifies sender), outer signature for transport integrity (broker verifies sender before forwarding)

### Federated Policy (PDP Webhooks)

Each organization registers a webhook at onboarding. For every session request, the broker calls both organizations' webhooks and proceeds **only if both return allow**. If an organization has no webhook configured, the PDP check is skipped for that org (the session policy engine still applies).

Organizations retain full sovereignty over authorization decisions. The broker is a neutral enforcer.

### Immutable Audit Trail

Every authentication, session, message, and policy decision is recorded in an **append-only cryptographic ledger**. No UPDATE or DELETE operations on audit records. Acts as a neutral notary for inter-organizational disputes.

### Enterprise KMS Integration

The broker's root signing key never lives on disk in production. ATN implements a **KMS Adapter pattern**:

```
KMS_BACKEND=local   -> filesystem (dev/test)
KMS_BACKEND=vault   -> HashiCorp Vault KV v2 (production default)
KMS_BACKEND=azure   -> Azure Key Vault       (add provider, swap env var)
KMS_BACKEND=aws     -> AWS KMS               (add provider, swap env var)
```

Changing the backend requires zero code changes — only a different environment variable.

### Prompt Injection Defense

Every inter-agent message passes through a two-stage detection pipeline:

- **Regex fast path** — blocks known injection patterns with zero latency
- **LLM judge** (optional) — semantic analysis for novel attacks via Anthropic API

### Additional Security Controls

- **Certificate revocation** — block compromised agent certificates immediately
- **Token revocation** — self-service and admin-initiated token invalidation
- **Rate limiting** — sliding window per-endpoint, per-agent
- **Capability-scoped sessions** — requested capabilities must be authorized in both parties' bindings

---

## Operational Features

### Real-Time WebSocket Messaging
Agents receive session invitations and messages via WebSocket push with automatic REST polling fallback. The broker pushes events; agents do not poll.

### Capability Discovery
Agents can discover other agents by capability across the network. The broker returns only agents from other organizations with matching approved capabilities.

### Self-Service Onboarding
Organizations join the network via a structured onboarding flow (request > admin review > approve/reject). Each organization uploads its own CA certificate and registers its PDP webhook.

### Multi-Role Admin Dashboard
A built-in web dashboard at `/dashboard` with role-based access control:

- **Network Admin** — full visibility: all organizations, agents, sessions, audit log. Can onboard new organizations (upload CA cert + webhook URL), approve/reject pending orgs, register and delete agents.
- **Organization** — scoped view: sees only own agents, own sessions, own audit events. Can register agents for own org only. Cannot access admin-only pages.

Agent registration from the dashboard automatically constructs the agent ID (`org::name`), creates and approves the binding. Login via signed cookie (HMAC-SHA256) with CSRF protection. Security headers (CSP, X-Frame-Options, HSTS). Live notification badges (HTMX auto-refresh). Dark theme, Tailwind CSS, zero build step.

### Enterprise Integration Kit
A self-contained kit for onboarding customer organizations:

- **Bring Your Own CA guide** — step-by-step for the customer's security team
- **Docker Compose template** — deploy agent + PDP webhook in customer infrastructure
- **PDP webhook template** — configurable rules (allowed orgs, capabilities, blocked agents)
- **Quickstart script** — generates CA, agent cert, registers org in one command

### Agent SDK
A Python SDK (`agents/sdk.py`) handles the full lifecycle: x509 authentication, DPoP key management, session negotiation, E2E encryption, message signing, and WebSocket streaming.

---

## Numbers

| Metric | Value |
|--------|-------|
| Broker codebase | ~55 Python modules + templates, ~9,200 lines |
| Test suite | 18 test files, 198 tests, ~5,400 lines |
| Test coverage | Auth, DPoP, broker, crypto, policy, revocation, rate limiting, WebSocket, E2E, dashboard, CSRF, security headers |
| Standards referenced | WIMSE, SPIFFE, RFC 9449 (DPoP), RFC 7638 (JWK Thumbprint) |

---

## Roadmap

| Feature | Status |
|---------|--------|
| x509 PKI + SPIFFE identity | Done |
| JWT RS256 access tokens | Done |
| DPoP token binding (RFC 9449) | Done |
| E2E AES-256-GCM + RSA-OAEP | Done |
| Two-layer RSA-PSS message signing | Done |
| Immutable audit log | Done |
| Federated PDP Webhooks | Done |
| KMS Adapter (Vault KV v2) | Done |
| WebSocket real-time push | Done |
| Prompt injection detection | Done |
| Rate limiting | Done |
| Certificate + token revocation | Done |
| Capability discovery | Done |
| Docker Compose + one-command setup | Done |
| Redis Pub/Sub (horizontal scaling) | Done |
| Multi-role admin dashboard | Done |
| Dashboard security (CSRF, headers, input validation) | Done |
| Enterprise integration kit (BYOCA, templates, PDP) | Done |
| Capability-only auth (roles removed) | Done |
| ERP-triggered demo scenario | Done |
| Session policy management from dashboard | Done |
| OpenTelemetry observability | Planned |
| DPoP Server Nonce (RFC 9449 Section 8) | Done |
| JWKS key rotation endpoint | Planned |

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
#   Mock PDPs localhost:9000, localhost:9001

# Start demo agents (see demo/ for full scenario):
python demo/supplier_agent.py --config certs/chipfactory/chipfactory__supplier-agent.env
python demo/inventory_watcher.py   # triggers buyer automatically

# Tear down:
docker compose down -v
```

**Cloud-agnostic by design.** No dependency on AWS, Azure, or GCP APIs. Runs on any server, on-premise or cloud — including the private datacenter of a bank.

---

## Positioning

ATN is not an Identity Provider (Okta) nor an API Gateway (Kong). It is purpose-built infrastructure for the AI agent era:

| | Traditional IAM | AI Proxy/Gateway | **ATN** |
|---|---|---|---|
| Identity model | Human users, static roles | API keys, OAuth tokens | **Workload x509 + SPIFFE** |
| Token security | Bearer (transferable) | Bearer (transferable) | **DPoP-bound (non-transferable)** |
| Policy location | Centralized | Centralized | **Federated (each org decides)** |
| Credential lifetime | Long-lived | Long-lived | **Short-lived, scoped** |
| Message security | None | TLS termination | **E2E encrypted + dual-signed** |
| Audit | Application logs | Access logs | **Cryptographic append-only ledger** |
| On-premise | Sometimes | Rarely | **Always** |

---

## Tech Stack

Python 3.11, FastAPI, SQLAlchemy async, PostgreSQL 16, cryptography (RSA 4096, x509, EC P-256), PyJWT RS256, HashiCorp Vault, WebSocket (FastAPI native), Anthropic SDK.

---

*If agents are to operate securely across organizations, we need a way to trust them, control them, and audit them — without centralizing power in a single operator. ATN provides the infrastructure to make this possible.*
