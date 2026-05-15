---
title: "Threat model"
description: "STRIDE threat model for the Cullis Mastio bundle and Court federation: system boundaries, trust assumptions, per-component threats, mitigations in place, and residual risks."
category: "Security"
order: 1
updated: "2026-05-15"
---

# Threat model

This document is a self-driven threat model of the Cullis Mastio
bundle and the Cullis Court federation broker. It is written for
security reviewers (CISO, blue-team architects, customer security
engineering) who need to convince themselves that the components they
are about to install on their infrastructure have been reasoned about
adversarially, that the mitigations claimed are present in code, and
that the residual risks are stated honestly.

It is **not** a substitute for a third-party penetration test. We
intend to commission one once the first paying customer engagement
funds it. Until then, this document plus the public `/security-review`
output on every merged PR, the supply-chain attestations on every
released artefact, and the audit-log hash chain that ships in the
bundle are the artefacts we expect a reviewer to inspect.

Every claim in the per-component sections below has been
cross-checked against the codebase by a verification pass on
2026-05-15. Where a stated mitigation is partial, aspirational, or
implemented differently from the design intent, we say so explicitly
inline ("on the roadmap", "today: …", "we do not currently …") and
list the corresponding gap in the open-items table at the end of the
document. We would rather call out a real gap here than have a
reviewer discover it.

## Scope

In scope:

- **Cullis Court** (`app/`), the federation broker.
- **Cullis Mastio** (`mcp_proxy/`), the per-organisation agent gateway.
- **Cullis Connector** (`cullis_connector/`), the end-user desktop
  client.
- **Cullis SDK** (`cullis_sdk/`, `sdk-ts/`), the libraries agents and
  applications link against.
- The enterprise plugins shipped in
  `ghcr.io/cullis-security/cullis-mastio-enterprise` (SAML SSO, cloud
  KMS providers, RBAC multi-admin, 4-eyes approval, LLM Guardian,
  audit export to S3/Datadog, SCIM 2.0).

Out of scope (treated as trust assumptions, see below):

- The operating system and container runtime hosting the bundle.
- The TLS PKI used to terminate edge connections.
- The downstream LLM providers reached through the embedded AI
  gateway (Anthropic, OpenAI, Bedrock, Vertex, Ollama).
- Identity providers federated through SAML SSO or SPIRE.
- The HashiCorp Vault deployment used as KMS in production, or the
  cloud KMS service used as alternative (AWS KMS, Azure Key Vault,
  GCP KMS): we assume the operator has secured them per the vendor's
  hardening guide.

## Audience

Two readers:

- **A reviewing CISO or security architect** evaluating whether the
  Cullis Mastio bundle is fit to live next to their existing fleet,
  carrying identity and policy decisions for AI agents that touch
  internal data. This reader wants STRIDE coverage, explicit residual
  risks, and references to the code where mitigations live.
- **An operator on the customer side** running the bundle. This reader
  wants to know which trust assumptions they are inheriting, what
  they must configure correctly, and what failure modes they are
  expected to monitor.

If you fit either profile and a section reads as marketing rather than
as analysis, that is a bug. File an issue against
`cullis-security/cullis`.

## Methodology

The model uses **STRIDE** (Spoofing, Tampering, Repudiation,
Information disclosure, Denial of service, Elevation of privilege) per
trust boundary. For each component we:

1. Describe the data flow that crosses the boundary.
2. Enumerate STRIDE threats relevant to that flow.
3. Reference the mitigation already in code, with the architectural
   decision record (ADR), pull request, or operational runbook that
   establishes it.
4. Call out residual risk: the part of the threat that the mitigation
   does **not** cover, and what compensating control we expect the
   operator to provide.

The component list maps to the seven boundaries in the
`imp/enterprise-production-ready-plan.md` hardening track step H3.

## System boundaries

```
              ┌──────────────────────────────────────────────┐
              │                  Operator                    │
              │   (deploys + monitors + holds license JWT)   │
              └────────────────────┬─────────────────────────┘
                                   │ admin dashboard (HTTPS+CSRF+httponly)
                                   ▼
┌────────────────────────────────────────────────────────────────────┐
│                 Org A                                              │
│                                                                    │
│   ┌───────────┐    DPoP+JWT     ┌────────────────────────────┐     │
│   │   Agent   │  ◀──────────▶   │      Cullis Mastio         │     │
│   │  (SDK)    │   cert pinning  │  (mcp_proxy, FastAPI)      │     │
│   └───────────┘                 │                            │     │
│                                 │   ┌─────────────────┐      │     │
│   ┌───────────┐                 │   │   PDP + policy  │      │     │
│   │   User    │   browser SSO   │   │  (default-deny  │      │     │
│   │ (Frontdesk│  ◀───────────▶  │   │   session)      │      │     │
│   │  /Connect)│                 │   └─────────────────┘      │     │
│   └───────────┘                 │                            │     │
│                                 │   ┌─────────────────┐      │     │
│   ┌───────────┐                 │   │  AI gateway     │      │     │
│   │  MCP tool │  reverse proxy  │   │  (embedded      │      │     │
│   │  upstream │  ◀───────────▶  │   │   LiteLLM)      │      │     │
│   │ (Slack...)│                 │   └─────────────────┘      │     │
│   └───────────┘                 │                            │     │
│                                 │   ┌─────────────────┐      │     │
│                                 │   │  Audit log      │      │     │
│                                 │   │ (append-only,   │      │     │
│                                 │   │  hash chain)    │      │     │
│                                 │   └────────┬────────┘      │     │
│                                 │            │ KMS calls     │     │
│                                 │            ▼               │     │
│                                 │   ┌─────────────────┐      │     │
│                                 │   │ KMS backend     │      │     │
│                                 │   │ (Vault / cloud  │      │     │
│                                 │   │  KMS / fs dev)  │      │     │
│                                 │   └─────────────────┘      │     │
│                                 └────────────┬───────────────┘     │
│                                              │ federation HTTPS    │
└──────────────────────────────────────────────┼─────────────────────┘
                                               ▼
                          ┌──────────────────────────────────┐
                          │           Cullis Court           │
                          │  (federation broker + registry)  │
                          │                                  │
                          │  - cross-org A2A routing         │
                          │  - org/agent registry            │
                          │  - audit chain anchor            │
                          └────────────────┬─────────────────┘
                                           │ federation HTTPS
                                           ▼
                                    ┌─────────────┐
                                    │   Org B     │
                                    │  Mastio …   │
                                    └─────────────┘
```

Each labelled arrow is a trust boundary; we enumerate STRIDE per
arrow class in the per-component sections below.

## Trust assumptions

The threat model is only meaningful relative to what we treat as
trusted. The following are **assumed correct** and not analysed
further in this document:

| Assumption | Why we make it | What you should verify |
|---|---|---|
| Host OS not compromised; container runtime enforces process isolation | We rely on standard Linux + containerd / Docker semantics. Cullis cannot defend against a root-shell on the host. | Standard OS hardening (CIS benchmark or equivalent). Drop privileges on the runtime, run rootless if possible. |
| TLS PKI not subverted | The bundle's nginx sidecar terminates TLS using a cert issued from the operator's chain. We trust the chain. | Use a CA your security team accepts; rotate on the CA's schedule; monitor CT logs for the issued cert. |
| Container image signature path is honest | Sigstore + Rekor transparency log is consulted at pull time. We assume `cosign verify` is genuinely run and not bypassed. | Run cosign verify in your CI before promotion, not just at first deploy. See `operate/enterprise-install.md`. |
| Downstream LLM providers are not actively malicious | The embedded AI gateway forwards requests to Anthropic, OpenAI, etc. We assume they behave per their docs. | Pin the API key per agent (see ADR-017). Use the LLM Guardian plugin if you need outbound content filtering. |
| Vault / cloud KMS are correctly deployed | If you choose Vault or cloud KMS as the Org CA private key store, that vault is what stops a Mastio host compromise from also leaking the org root key. | Apply the vendor hardening guide; rotate KMS keys on your schedule; restrict IAM policy to the smallest possible verbs. See `operate/vault-org-ca.md`. |
| The license JWT is delivered to the operator out-of-band | Cullis Inc. mints the JWT signed with a private key held in our 1Password vault. Delivery is via 1Password or signed email. | Verify the JWT signature matches the baked public key fingerprint `ba7a212359b2263220ca0ee89490fdc96fa9cd0f3c977e9d5b09a580109bbe28` before importing. |
| NTP is configured on the host | Every JWT (DPoP proof, license, federation) has a `nbf`/`exp` window. Heavy clock drift breaks signature verification. | Run chrony / systemd-timesyncd; alert on drift > 30 s. |

Anything below this line assumes the above hold.

## Component: agent authentication

### Data flow

- Agent enrolment via one of three paths: device-code (Connector
  desktop, `POST /v1/enrollment/start`), BYOCA (enterprise
  customer-issued cert via SPIRE or internal PKI,
  `POST /v1/admin/agents/enroll/byoca`), or Frontdesk first-boot
  (browser SSO, ADR-021).
- Steady-state requests sign a **DPoP proof** (RFC 9449) bound to the
  per-agent keypair; the proxy validates `htu` (target URL), `htm`
  (HTTP method), `iat` (issued-at), and the `ath` claim binding to
  the access token, with `cnf.jkt` thumbprint matching enforced on
  the access token itself (`mcp_proxy/auth/dpop.py`).
- Where the customer prefers a transport-layer proof the proxy
  supports **client-cert pinning** via a SHA-256 DER digest of the
  presented certificate (`mcp_proxy/auth/client_cert.py`). This is
  pinning, not formal RFC 8705 §3 `cnf.x5t#S256` token-level
  binding; we treat it as defence in depth rather than a substitute
  for DPoP.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of an agent identity | Attacker presents a stolen API key | DPoP proof requires the matching private key; key is never sent over the wire. SDK stores it in OS keychain on Connector, in `certs/` mode 0600 on server agents. | If the host is compromised and the private key file is exfiltrated, the attacker can impersonate until the cert is rotated. Rotation is admin-only via the dashboard form (`rotate_agent_cert` in `app/registry/store.py`); no public REST endpoint is currently exposed. |
| Spoofing of an enrolment | Attacker tricks the proxy into enrolling a hostile agent | Three orthogonal paths; each requires possession of a one-shot enrolment token (Connector), a customer-signed cert (BYOCA), or interactive admin approval (Frontdesk). No path is purely network-reachable without prior trust. | An admin who clicks "enrol" on a hostile request will enrol the hostile agent. The admin dashboard surfaces the public key fingerprint pre-approval (PR #687). |
| Tampering with the DPoP proof | Replay a captured proof from elsewhere | Redis-backed JTI cache rejects any DPoP `jti` seen in the configured window (`dpop_jti_store.py` `_DEFAULT_TTL = 300` seconds = 5 minutes; `SET NX EX` semantics). `htu` is checked literally including scheme + host + port: an MITM that strips port 9443 fails. | Replay protection cold-starts empty; first-N requests in the window after a proxy restart have lower replay protection until the cache fills. We do not currently warm the cache from a persistent store. |
| Repudiation by an agent | Agent claims it never made a call | Each call is signed end-to-end (DPoP) and logged to the append-only audit log with `agent_id`, action, tool name, status, request ID, and duration. The audit row identifies the agent by registry ID rather than by raw DPoP `jkt` thumbprint; the thumbprint is validated at request time but is not currently denormalised into each audit row. The log hash-chains to a Court anchor. | If the agent claims key compromise, the audit chain attributes the call to the agent's registry ID, which in turn is bound at enrolment time to the key. Customers needing per-person attribution should pair Cullis with their IdP (SAML SSO plugin) so that user-principal is bound to the agent enrolment. Denormalising `jkt` into the audit row is on the roadmap. |
| Information disclosure of the API key on enrolment | Key shipped over an insecure channel | API key (`sk_local_*`) is shown once on first-boot UI; later retrieval requires admin auth on the same machine. Connector `show-token` CLI prompts for OS keychain unlock. | A screenshot of the first-boot UI leaks the key. We rely on operator hygiene; SECURITY.md mandates immediate rotation if the key is ever pasted into a chat tool. |
| DoS via enrolment flood | Attacker hammers `/v1/enrollment/start` | Both `/v1/enrollment/start` (5 per minute per IP) and `/v1/enrollment/{id}/status` (60 per minute per IP) are rate-limited since PR #698 (H4 finding). Court federation endpoints (cross-org CSR) are rate-limited per source IP and per target org in the same PR. | A compromised admin token bypasses the rate limit. The 4-eyes plugin (`feature: four_eyes`) gates a configured list of admin actions but **does not currently gate enrolment**; the list today is `policies.save`, `pki.rotate_ca`, `mastio_key.rotate`, `vault.migrate_keys`, `users.delete`, `agents.delete`. Adding enrolment to the gated set is a planned extension. |
| Elevation of privilege | Agent claims a role it was not enrolled with | Roles are stored on the registry record server-side; the agent cannot include a role claim that overrides what the registry says. PDP looks up the registry, not the proof. | A SQL-injection or registry-tampering vector would defeat this. We mitigate with parameterised queries throughout (SQLAlchemy), `/security-review` on every PR (H4), and the audit chain providing forensic detection. |

### References

- `mcp_proxy/dpop.py`, `mcp_proxy/auth/`
- ADR-013 (layered defence), ADR-020 (user principal + 4 quadrants),
  ADR-021 (Frontdesk shared mode + per-user KMS)
- PR #687 (MCP resource registration hardening), PR #698 (Court CSR
  workload caller + federation rate-limit)

## Component: registry

### Data flow

The registry is the SQLite (standalone) or Postgres (federated, prod)
table behind every PDP decision. It holds: agent enrolment records
(public key, cert thumbprint, role, org), org identity records (cert
chain, federation URL, public key, anchor URL), and user principal
records (per ADR-020/021).

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing via stale registry entry | Decommissioned agent's record left active | The dashboard surfaces last-seen time and a one-click revoke. Cert thumbprint pinning means even a copy of the old key with the right fingerprint is rejected after revocation. | Customers who never click revoke leave attack surface up. We do not auto-expire records, intentionally; an expired record breaking a real production agent is a higher-cost failure mode. Operational guidance is in `operate/runbook.md`. |
| Tampering with a record (privilege escalation) | Attacker rewrites a role field directly in the DB | SQLAlchemy uses parameterised queries throughout. Write paths are admin-only (CSRF + httponly cookie + `MCP_PROXY_ADMIN_SECRET`). The audit log captures every write with the admin's principal. | Host root can rewrite the SQLite file directly. The hash chain in the audit log makes after-the-fact tampering detectable; live tampering without writing to the chain is detectable when the next chain link fails to verify against Court's anchor. |
| Tampering with a federation org record | Attacker swaps an org's federation URL or public key | Org records are signed by the Court at registration time; the Mastio caches them with TTL and re-validates against Court on cache expiry (`FederationCatalog`, PR #622). | A long-lived TTL hides a malicious swap. Default TTL is 5 minutes; operators can shorten it via env. |
| Repudiation of a registry write | Admin claims they did not change a record | Every write goes through the dashboard signed cookie + audit log entry. The audit entry includes the admin's user principal and a hash of the changeset. | Same as before: hash chain detects retroactive deletion. Live forgery would require both DB write + audit log write + Court anchor manipulation, which is outside the bundle's trust boundary. |
| Information disclosure of registry contents | Read access leaks agent metadata | On Court, the public endpoint `GET /v1/federation/orgs/{id}/mastio-url` returns only the fields needed for federation routing (`mastio_url`); `/v1/registry/orgs/{id}` requires admin auth and is the only path to private fields. Mastio itself does not expose a public registry read endpoint. | A misconfigured nginx that proxies admin endpoints to the public listener would leak. The shipping bundle's nginx config separates `:9443` (public TLS) from admin paths via auth middleware; do not edit this without re-running the security review. |
| Denial of service via registry growth | Attacker creates many junk records | Enrolment endpoints are rate-limited (PR #698). On the broker side `agent_id` is indexed in `AgentRecord` (`app/registry/store.py`); `cert_thumbprint` is **not** currently indexed, and the Mastio-side `InternalAgent` schema has no explicit indexes today. Pathological growth degrades query latency before it degrades disk; indexing is a planned hardening. | An attacker with valid admin credentials can still flood. The 4-eyes plugin gates a small set of admin actions but does not gate enrolment today (see above). |
| Elevation of privilege | Reading the registry to discover an admin token | The registry never stores secrets in plaintext. Admin tokens are bcrypt-hashed and looked up by O(1) prefix to avoid both timing leaks and the event-loop stall that the legacy full-scan path produced (PR #306). | Hash leakage allows offline attack; bcrypt cost factor 12 mitigates but does not eliminate. Rotation policy is in `operate/rotate-keys.md`. |

### References

- `mcp_proxy/db.py`, `app/registry/`
- PR #306 (DPoP concurrency fix + constant-time lookup)
- PR #622 (FederationCatalog with TTL cache)
- PR #687 (MCP resource registration hardening)

## Component: MCP proxy (reverse proxy + DPoP gateway)

### Data flow

Agents call MCP tool endpoints through Cullis Mastio rather than
directly. The proxy:

1. Validates the DPoP proof and the access token against the registry.
2. Consults the PDP (policy decision point) for `(agent, session,
   tool, model, server)` allow/deny.
3. Reverse-proxies to the upstream MCP server, stripping or rewriting
   headers as policy dictates.
4. Writes the call + result hash to the audit log.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of an upstream MCP server | DNS or middlebox attack redirects to a hostile MCP | Per-tool upstream URL is configured by the org admin and stored in the registry. The bundle calls upstream over TLS with the operator's trust store. | If the operator pins by URL but never by cert / SPKI hash, a CA misissuance is in scope. Optional: configure `allowed_domains` per ADR-029 to constrain. |
| Tampering with the request en route | Attacker between proxy and upstream rewrites headers | TLS between Mastio and upstream is the default; outbound HTTP is gated by a per-tool domain allow-list (`mcp_proxy/tools/http_whitelist.py`, `WhitelistedTransport`). Explicit `Authorization` and `Cookie` header stripping at the forwarder layer is **not** implemented today; the proxy relies on the per-tool registry holding the upstream credential and not propagating client headers verbatim. Closing this to an explicit deny-list is on the roadmap. | A vulnerable upstream that trusts other headers (e.g. `X-Forwarded-User`) is in scope; document your trust contract per upstream. Until the explicit header strip lands, treat the upstream allow-list as the primary boundary. |
| Tampering with the policy decision | Attacker forces the PDP to allow | PDP is in-process; calls to an out-of-process PDP webhook are timeout-bounded at 5 s and **fail-deny on timeout** (`app/policy/webhook.py:75` `_WEBHOOK_TIMEOUT = 5.0`, `except httpx.TimeoutException: return WebhookDecision(allowed=False, ...)`). Decision inputs (tool name, principal type, model, target, session ID, reason) are written into the audit `details` JSON, which then participates in the entry-level SHA-256 chain (no separate pre-computed `decision_inputs_hash` field today). | A compromised in-process PDP code path skips the webhook and is the same threat as code-tampering on the Mastio container. The mitigation is at the image-integrity layer (cosign + SBOM). |
| Repudiation of a tool call | Agent claims the call was not theirs | Every tool call is logged with `agent_id`, action, tool name, status, detail, request ID, and duration. The audit log hash chains via `entry_hash`/`previous_hash` (SHA-256), and the chain head is anchored at Court for federated installs. | Audit writes happen after the call has been authorised and dispatched; an audit-write failure is logged but does **not** block the call. Adding a configurable audit-fail-deny mode is a planned hardening (currently aspirational, not in code). DPoP `jti` and proof public-key fingerprint are not denormalised into the audit row today; correlation requires cross-referencing the request log. |
| Information disclosure via the proxy | A proxied response leaks sensitive content to the agent | Cullis does not classify content; we forward what the upstream returns. The LLM Guardian plugin (enterprise) can rewrite or block outbound content via six tools and five judges. | Without LLM Guardian, content classification is the operator's responsibility. The proxy adds no leak surface beyond what the upstream already exposes. |
| Denial of service against the proxy | Agent flood overwhelms the process | nginx upstream keep-alive pool + Connection plumbing keep the proxy responsive at ~2 kRPS sustained (see `operate/capacity-planning.md`). Container resource limits (4 CPU / 2 GiB RAM, PR #699) cap the blast radius on the host. | A motivated attacker with valid credentials can saturate. A per-agent / per-API-key rate limiter is implemented at the proxy layer (`tests/test_mcp_proxy_rate_limit.py` exercises it); exposing it as a per-tool policy knob in the PDP `tool_rules` schema is partly aspirational (the `rate_limit` field is present in the scope model but not enforced from policy). The customer-path smoke gate validates the enrolment + chat path on every PR, not specifically the rate-limit path. |
| Elevation of privilege via header injection | Agent injects an `X-Cullis-Admin: true`-shaped header expecting it to be honoured | The proxy's authentication path derives the agent and org identity from the DPoP proof / cert pin against the registry, not from request headers. No code path elevates privileges based on a client-supplied header. Adding an explicit middleware strip + set of trusted `X-Cullis-*` headers is on the roadmap. | A custom plugin or upstream middleware that introduces a trusting header is in scope. Document the contract with each upstream; until the explicit strip lands, the mitigation is "trust derivation never reads client headers" rather than "client headers are scrubbed". |

### References

- `mcp_proxy/proxy_router.py`, `mcp_proxy/middleware/`
- ADR-029 (tool-level PDP, dual-allow cross-org)
- PR #687 (MCP resource registration, allow-list default,
  aggregator double-wrap fix)
- PR #697 (nginx upstream keep-alive)
- PR #699 (container resource limits)

## Component: AI gateway (embedded LiteLLM)

### Data flow

ADR-017: Mastio embeds LiteLLM `< 2.0` as the AI gateway for outbound
LLM calls (`/v1/llm/...`). The gateway terminates an OpenAI-shaped or
Anthropic-shaped client request, applies per-agent rate limits and key
selection, and forwards to the configured upstream provider.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of the gateway | Agent thinks it is calling Anthropic, hits a proxy | The gateway runs in-process inside Mastio (`mcp_proxy/ai_gateway.py` calls `litellm.acompletion()` directly); no extra hop. The upstream URL is operator-configured; upstream **credentials** are encrypted at rest using Fernet (`mcp_proxy/secret_encrypt.py`). The Fernet master key is **not** KMS-backed today: it lives in `MCP_PROXY_SECRET_ENCRYPTION_KEY_B64` (env) or is auto-generated and stored in the `proxy_config` table. HSM-backed encryption is a documented future enterprise extension (see `secret_encrypt.py:23` and the open-items table below). | If the operator points the upstream to an attacker-controlled URL, no Cullis mitigation helps. Use TLS pinning at the bundle's outbound boundary (NetworkPolicy in k8s, host firewall on VPS). If you need HSM-grade protection of the Fernet master key today, mount the env var from a secrets-manager such as Vault Agent. |
| Tampering with the prompt or response | A man-in-the-middle alters the LLM payload | The gateway terminates TLS to the upstream; we do not re-encrypt or sign payloads. Customers needing payload integrity guarantees on the wire should run their own provider proxy with their own pinning. | This is a known limitation of any LLM gateway: prompt/response signing is not standardised. We default-deny on TLS errors. |
| Repudiation | Agent denies sending a prompt | Every LLM call is audited identically to a tool call (per-agent, per-DPoP-jti, with a hash of the prompt and response). | The prompt hash is one-way: we cannot reproduce the prompt from the log. This is intentional (privacy / no plaintext retention by default), but means a forensic investigation must rely on the *agent's* logs for prompt reconstruction. |
| Information disclosure of API keys | The gateway logs the upstream API key | Mastio's gateway never logs the upstream API key. Several competing AI gateways (Portkey, Helicone, OpenRouter) do log upstream keys to their telemetry endpoint as part of their value proposition; we explicitly do not. | Operator-side observability (Promtail, etc.) that scrapes the gateway's stderr could pick up the key if the upstream emits it in an error message. We sanitise known upstream error patterns; new upstreams should be reviewed. |
| Information disclosure of prompts | Sensitive content sent to an upstream the customer does not control | The customer chooses the upstream. Cullis does not redact by default. LLM Guardian (enterprise plugin) provides redaction rules. | Without Guardian, redaction is the customer's responsibility. This is by design: Cullis is infrastructure, not a content classifier. |
| DoS via expensive prompt | Agent issues a 100k-token prompt repeatedly | Per-agent rate limit + per-agent budget enforcement (the gateway tracks `token_count` per request and refuses past a configurable budget). | Token budget is configurable; an operator who sets it to infinity inherits the cost risk. Default is finite. |
| Elevation of privilege via prompt injection | Agent persuades the gateway to forward to a different upstream | Routing decisions are made server-side from the registry, not from the request body. Prompt injection cannot redirect the gateway. | Prompt injection against the *upstream LLM* can still cause it to misbehave; this is the upstream's responsibility (and partly the customer's via Guardian). |

### References

- ADR-017 (embedded LiteLLM)
- `mcp_proxy/ai_gateway/`

## Component: plugin sandbox (enterprise plugins)

### Data flow

The enterprise image (`cullis-mastio-enterprise`) loads up to nine
plugins via setuptools entry points
(`cullis.mastio_plugins` group): SAML SSO, cloud KMS providers (AWS,
Azure, GCP), RBAC multi-admin, 4-eyes approval, LLM Guardian, audit
export to S3, audit export to Datadog, SCIM 2.0.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of a plugin (malicious package) | A package with the same entry-point name is installed alongside | Plugins are baked into the enterprise image at build time; the image is cosign-signed (keyless OIDC Sigstore) and the SBOM lists every package + version. Operators who run `pip install` inside a deployed container void the signature. | Custom builds bypass the signed image. Operators who fork should run cosign on their own image. |
| Tampering with a plugin at runtime | An attacker patches plugin code on disk | Containers run rootless (UID 10001 in both open-core and enterprise Dockerfiles). The image is built from a `python:3.11-slim` base; the SBOM and cosign attestation are checkable. A **read-only root filesystem is supported but not enabled by default** in the shipping Helm values (`readOnlyRootFilesystem: false`); enabling it requires the operator to also mount a writable `/tmp`. | The default-off read-only root is a gap; we recommend operators flip it on in environments where local-root container compromise is in scope. The data bind mount is always writable by design. |
| Repudiation of a plugin action | Admin approval (4-eyes) is denied | Every plugin action that mutates state goes through the same audit log as core actions: the approver's user principal is recorded, the time is signed, and the hash chains. | Off-image plugins (BYO) inherit no audit. We recommend customers using BYO write to the same audit sink. |
| Information disclosure via a plugin | A plugin (e.g. audit_export_s3) sends data to a wrong destination | The destination is configured per plugin; SAML metadata, S3 bucket URL, Datadog API endpoint each have explicit env vars. The audit log captures plugin configuration changes. | Mis-configuration sends data to the wrong place. The first-boot wizard validates plugin destinations are reachable, but cannot validate they are *correct*. |
| DoS via plugin | A misbehaving plugin blocks the event loop | Plugins are loaded into the Mastio FastAPI process; a CPU-bound plugin can starve other request paths. Container resource limits cap the host-level blast radius. | An in-process plugin is the highest-trust extension surface. Customers using BYO plugins should run them out-of-process via webhook (`PDP webhook` pattern) for stronger isolation. |
| Elevation of privilege | A plugin reads a secret it should not see | Plugins load into the Mastio process and have **full Python access** to the application: they can import `mcp_proxy.db`, read environment variables, and call any FastAPI route. There is no in-process sandbox today (no `PluginContext` field gating, no `SecretsBackend` mediating capability). Mitigation is at the supply-chain layer: plugins shipped in the enterprise image are reviewed before inclusion, the image is cosign-signed, and the SBOM lists every dependency. BYO plugins inherit no sandbox. | This is the largest residual risk on the plugin surface. Customers running BYO plugins should run them out-of-process via the webhook PDP pattern (separate container, separate identity, only the PDP HTTP contract exposed) for stronger isolation. An in-process capability-token model is on the roadmap. |

### References

- ADR-017 (AI gateway embedded)
- PR #685 (CLI `cullis-proxy migrate-org-ca-to-vault`)
- PR #689 (plugin replay-bypass hook for 4-eyes)
- PR #676 (plugin approval hook for 4-eyes)
- Enterprise repo (`cullis-security/cullis-enterprise`, private):
  `cullis_enterprise/mastio/`

## Component: license verifier

### Data flow

The enterprise image refuses to enable paid plugins unless it can
verify a JWT in `LICENSE_JWT` against the **RS256 public key baked
into the image at build time** (`mcp_proxy/license.py`,
`app/license.py`, PR #691).

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of a license | Attacker forges a JWT with paid features enabled | Verification uses RS256 against the baked pubkey (fingerprint SHA-256 DER `ba7a212359b2263220ca0ee89490fdc96fa9cd0f3c977e9d5b09a580109bbe28`); the private key is held by Cullis Inc. in a password-manager vault, with a single working-copy laptop. There is no fallback path that accepts an unsigned token. | Compromise of the priv-key bypasses the protection for every customer. We rotate annually and after any suspected exposure; the custody procedure is documented internally. |
| Tampering with the verifier | Attacker patches the verifier to always return true | The verifier code is baked in the cosign-signed image; tampering invalidates the cosign attestation. The verifier is exercised at every plugin-load and on every license refresh. | Custom builds bypass cosign. We recommend operators run cosign verify on every deploy, not just at first install (`operate/enterprise-install.md`). |
| Repudiation | Customer claims they never imported the license | License import via the admin dashboard is audit-logged with the admin principal; the import path is admin-only behind CSRF. | If the customer has multiple admins and they argue with each other about who imported the license, the audit log resolves it. |
| Information disclosure | The license JWT contains customer-identifying data | The JWT contains the customer org name, ACV tier, plugin entitlements, and an expiry. No secrets, no PII. The HTTP error response for license-related failures returns only `{error, feature, tier}`; the JWT itself is not surfaced. | We do **not** currently run an explicit JWT-aware sanitiser through every log path; exception messages logged at debug level may include payload context. The HTTP client-facing response is already minimal. Adding a dedicated JWT scrubber to the generic exception path is on the roadmap. |
| DoS via license rejection | A genuinely valid license fails verification | The verifier exits with a clear error code per case (expired, wrong signature, malformed). The first-boot wizard surfaces these specifically. | Clock-skew on the host causes false negatives on `nbf`/`exp`. We require NTP; we surface the failure mode in `operate/enterprise-install.md` troubleshooting. |
| Elevation of privilege | Patched verifier enables features that were not paid for | Cosign verify is the answer; the second answer is that the audit-log entry naming the paid features fired in the absence of a matching license JWT (i.e. a contradiction). Customers who care about this run cosign in CI. | We do not phone home for license validation. This is intentional (air-gap support) but means we trust the operator's image-integrity stance. |

### References

- PR #691 (bake prod RS256 pubkey)
- `mcp_proxy/license.py`, `app/license.py`

## Component: KMS backend

### Data flow

The org CA private key (used to sign agent certificates) can live in
three places, chosen at deploy time via `MCP_PROXY_KMS_BACKEND`:

- `local` (development default): the key is stored in the
  `proxy_config` table of the Mastio's own SQLite or Postgres
  database. This is **database-backed**, not a loose filesystem
  file.
- `vault` (production recommended): HashiCorp Vault KV v2 path
  (ADR-031).
- `cloud_kms_aws` / `cloud_kms_azure` / `cloud_kms_gcp` (enterprise
  plugins): the cloud provider's KMS API; the private key never
  leaves the KMS.

A **separate** env var, `MCP_PROXY_SECRET_BACKEND`, governs how
short-lived agent credentials are encrypted (env vs Vault). The
production-mode startup validator refuses `MCP_PROXY_SECRET_BACKEND=env`
in production but **does not currently refuse
`MCP_PROXY_KMS_BACKEND=local`**. We treat this as a documented gap:
operators running production should set both backends to `vault` (or
the cloud KMS plugin), and the startup validator should be extended
to enforce this. The capability is on the roadmap; the operator
runbook (`operate/vault-org-ca.md`) is the compensating control today.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of the KMS | Application points at an attacker-controlled Vault | The Vault URL is set at deploy time and pinned via the same trust store as the rest of the host's outbound TLS. AppRole auth + Vault token rotation are standard Vault hardening. | If the operator wires the wrong URL on day one, we cannot detect it. The first-boot wizard validates connectivity but not authenticity beyond TLS. |
| Tampering with stored keys | Attacker rewrites the KV v2 entry | Vault KV v2 is versioned; tampering is detectable by reading the version history. Cloud KMS providers (AWS/Azure/GCP) keep the key inside the HSM-backed service; no read endpoint exists. | A Vault compromise is the customer's exposure; we do not defend against it from inside Mastio. Cloud KMS is materially stronger here, hence its presence as an enterprise plugin. |
| Repudiation of a KMS operation | Operator denies signing a CSR | KMS calls are audited inside Mastio (caller, target key path, operation type). Vault's own audit log + cloud KMS CloudTrail / equivalent provide the second source of truth. | Aligning the two logs requires effort; we provide the field names but not an out-of-the-box correlation tool. |
| Information disclosure of the org CA private key | A compromised Mastio host reads the key | With `local`: the key is in the Mastio database; a host compromise that reaches the DB file reads it. With Vault: the host has only a short-TTL Vault token; the key material is held by Vault. With cloud KMS: the key never crosses the network unencrypted. | `local` mode is intended for development. The production-mode validator **does not refuse it today** (only `secret_backend=env` is refused). Operators running production must set `MCP_PROXY_KMS_BACKEND=vault` (or a cloud KMS plugin) and verify the chosen backend on the first-boot dashboard. The migration CLI (PR #685) moves an existing local-backed key into Vault. |
| DoS via KMS unavailability | Vault is down | Cert signing fails fast. The proxy `/health` reports the KMS status; cached certs continue to work until they expire. | Long Vault outages eventually expire all certs and disable agent enrolment. Operators should monitor Vault availability per the vendor's runbook. |
| Elevation of privilege via KMS misuse | Attacker requests signing of a CSR they did not generate | The KMS-side ACL allows only Mastio's role to call the signing verb; Mastio itself enforces that the CSR matches an authenticated admin request. The 4-eyes plugin can require a second admin signoff per CSR. | A compromised admin token bypasses Mastio's check (KMS still rate-limits and audits). 4-eyes is the recommended compensating control at the enterprise tier. |

### References

- ADR-031 (Vault as Org CA private key store)
- PR #684 (Vault KMS provider in-tree)
- PR #685 (CLI `migrate-org-ca-to-vault`)
- PR #686 (operator guide: `operate/vault-org-ca.md`)
- Refuse-to-start pattern: every secret-management gate validated in
  `validate_config(production)` raises rather than falling back to an
  insecure default. Applies to HMAC, JWT, rate-limit, replay store,
  and audit logger gates.

## Cross-cutting threats

### Supply chain

Every released image and bundle ships with:

- A **cosign signature** generated by GitHub Actions OIDC keyless
  signing; the certificate identity is verifiable against the
  workflow path `release-mastio-enterprise.yml@refs/tags/...` on
  `cullis-security/cullis-enterprise`.
- A **CycloneDX SBOM** generated by Syft, attached to the GitHub
  Release.
- A **Trivy scan** that gates HIGH/CRITICAL vulnerabilities with
  `ignore-unfixed=true`: vulnerabilities without an upstream fix are
  documented as residual rather than blocking the release. The
  Debian base image typically carries a small number of HIGH
  unfixed CVEs (libcap2, ncurses, systemd) that we list explicitly
  in each release's SBOM rather than blocking on.

Residual: Trivy `ignore-unfixed=true` is the default posture for the
enterprise image because Debian's base image often ships HIGHs without
an upstream patch (libcap2, ncurses, systemd). Customers who require a
zero-unfixed posture should rebuild from `cullis-mastio` source with
their own base image; the recipe is documented.

### Insider threat

We treat the bundle operator as semi-trusted: they can deploy, take
backups, and rotate keys. They can also read the data bind mount and
the SQLite file. The defences against an insider with operator
credentials are:

- **Audit chain**: every state-changing action goes into the
  append-only log, which hash-chains to a Court anchor. An insider
  who tampers with the log breaks the chain.
- **4-eyes plugin**: at the enterprise tier, a configured set of
  state-changing actions requires a second admin's signoff before
  they take effect. The currently gated set is `policies.save`,
  `pki.rotate_ca`, `mastio_key.rotate`, `vault.migrate_keys`,
  `users.delete`, `agents.delete`
  (`cullis_enterprise/mastio/rbac_multi_admin/quorum.py`). Agent
  enrolment, license import, and federation peering are **not**
  currently 4-eyes gated; extending the set is on the roadmap. See
  PR #676 / PR #689.
- **RBAC multi-admin plugin**: admins have scoped roles (audit-read,
  cert-rotate, plugin-config, etc.) rather than a single all-powerful
  bit. See the enterprise plugin docs.

Residual: a colluding pair of admins at the enterprise tier defeats
4-eyes. A single admin with all roles at the open-core tier has full
control by design.

### Key lifecycle

| Key | Lifetime | Rotation | Compromise recovery |
|---|---|---|---|
| Per-agent keypair (Connector / SDK) | Per enrolment | `/registry/agents/{id}/rotate-cert` or dashboard | Revoke + re-enrol the agent. Existing DPoP proofs are immediately rejected (cert thumbprint mismatch). |
| Org CA private key | Long-lived (years) | Manual via the dashboard `migrate-org-ca` or via cert rotation | New CA + bulk re-enrol of every agent. Painful by design; documented in `operate/rotate-keys.md`. |
| Dashboard admin secret | Long-lived | Rotate via env + restart | Re-issue all admin tokens. Use `MCP_PROXY_DASHBOARD_SIGNING_KEY` rotation. |
| License JWT signing key | Annual (Cullis-side) | Annual ceremony; new prod image bakes the new pubkey | Roll the priv-key, re-mint every active customer's JWT, ship a new image tag, ask operators to re-deploy. We treat this as an emergency procedure. |
| KMS / Vault tokens | Per Vault policy (short TTL) | Automated by Vault | Vault revokes; Mastio retries with a fresh token. |

### Audit log integrity

- Append-only schema: a database trigger raises an exception on
  `UPDATE` or `DELETE` against `audit_log` (`alembic/versions/
  r8m9n0o1p2q3_audit_append_only.py`), both on SQLite and Postgres.
- Each entry has an `entry_hash` (SHA-256 of canonical
  representation) and a `previous_hash` linking to the prior entry
  (`alembic/versions/7f54c1eb5e89_add_audit_log_hash_chain.py`).
- A background worker (`app/audit/tsa_worker.py`) anchors the
  current chain head into Court's `AuditTsaAnchor` table every
  `audit_tsa_interval_seconds` (default **3600 seconds = 60
  minutes**, configurable).
- An auditor verifying the chain replays from genesis and compares
  the periodic anchors against Court's record.

Residual: an attacker who controls **both** the Mastio host **and**
Court can rewrite history. We document the federation-level Byzantine
fault tolerance assumption in ADR-013 (layered defence); customers
who need stronger guarantees should run their own Court instance and
not federate, or peer Cullis with an external append-only log such
as their SIEM.

### Time-of-check / time-of-use across federation

A request crossing org boundaries goes
`Org A agent → Mastio A → Court → Mastio B → upstream`. The trust
decision is made at Mastio A (does my org allow this peer?) and at
Mastio B (does my org accept this caller?). Between those two
decisions the federation catalogue may change (an org may be
de-listed).

Mitigation: the `FederationCatalog` cache TTL is short (default 5
minutes, configurable) and Mastio re-validates the peer record on
cache expiry. Mid-request peer revocation is not currently
interrupted; the in-flight call completes, future calls are denied.
This is a known residual; instrumenting Court → Mastio push
invalidation is a P2 item on the roadmap.

## Residual risk summary

The threats this model does **not** mitigate:

- **Host compromise**: root on the Mastio host reads everything on the
  data bind mount. KMS (Vault or cloud KMS) raises the bar for the
  org CA key; everything else is in scope.
- **Compromised license signing key**: a single Cullis-side key
  custody failure affects every customer of that build. Annual
  rotation + 1Password custody is what we commit to; HSM-backed
  signing is a P2 item once funded.
- **Colluding admins at enterprise tier**: 4-eyes assumes the two
  admins are not the same person and not colluding.
- **Upstream LLM provider behaviour**: Cullis is not a content
  classifier. The LLM Guardian plugin closes part of this gap;
  prompt-injection defence at the *upstream* is the upstream's
  responsibility.
- **Sybil federation**: Court accepts any registered org by default.
  Customers who want a whitelist must configure
  `MCP_PROXY_FEDERATION_ALLOWLIST` (see `operate/runbook.md`).
- **Quantum-resistant cryptography**: not in scope yet. RSA-4096,
  ECDSA P-256, and RSA-OAEP-SHA256 are the current primitives.
- **Side-channels on bcrypt**: cost factor 12; we treat this as
  meeting OWASP 2024 guidance but not as eliminating offline attacks
  on a leaked hash.

## Open items (planned hardening)

| Item | Status | Tracking |
|---|---|---|
| Third-party penetration test (LoA) | Deferred until first paid engagement | Roadmap |
| HSM-backed license signing (YubiHSM2 / CloudHSM) | P2 | `imp/enterprise-production-ready-plan.md` |
| Reproducible builds + dep lockfile | P1 | Roadmap |
| Push-invalidation on Court → Mastio peer revocation | P2 | Roadmap |
| Image CVE watcher scheduled job | P2 | Roadmap |
| Quantum-resistant primitives review | Not started | Tracking AI Act / DORA guidance |
| Production-mode validator: refuse `MCP_PROXY_KMS_BACKEND=local` | P1 | Roadmap |
| Public REST endpoint for cert rotation (`/registry/agents/{id}/rotate-cert`) | P2 | Today rotation is dashboard-form-only |
| Denormalise DPoP `jkt` thumbprint into audit row | P2 | Roadmap |
| Configurable audit-fail-deny mode | P1 | Roadmap |
| Explicit `Authorization` / `Cookie` strip at upstream forwarder | P1 | Today: per-tool registry-stored credential + domain allow-list |
| Explicit middleware strip of inbound `X-Cullis-*` headers | P2 | Trust derivation does not read client headers, but a defence-in-depth strip is planned |
| `cert_thumbprint` index in registry schema | P2 | Roadmap |
| HSM-backed Fernet master key for AI gateway secret encryption | P2 | Today: env or auto-generated DB-stored |
| In-process plugin sandbox (`PluginContext` capability tokens) | P2 | Today: plugins have full Python access; supply chain is the boundary |
| Extend 4-eyes gate to cover enrolment / license import / federation peering | P1 | Today: 6 admin actions gated; enrolment / license / federation are not |
| Dedicated JWT scrubber on the generic exception path | P3 | Today: HTTP responses for license errors are already minimal |
| Customer-path smoke gate: add rate-limit scenario | P3 | Today: enrolment + chat reply only |

## References

- `SECURITY.md` (responsible disclosure, severity-tier SLA)
- `operate/capacity-planning.md` (DoS resistance baseline)
- `operate/disaster-recovery.md` (backup + restore runbook)
- `operate/enterprise-install.md` (cosign + SBOM verification recipe)
- `operate/vault-org-ca.md` (KMS migration to Vault)
- ADR-013, ADR-017, ADR-019, ADR-020, ADR-021, ADR-029, ADR-030,
  ADR-031 (`docs/adrs/`)
- The internal security review report:
  `imp/security-review-2026-05-14.md` (local-only; redacted summary
  available on request to `security@cullis.io`)
