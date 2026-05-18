# Cullis threat model (public)

**Audience:** CISOs, security architects, blue-team engineers, and
customer due diligence reviewers evaluating Cullis before a pilot.

**Status:** Version 1.0, published 2026-05-18. Quarterly review.
Next review: 2026-08-18.

**Contact:** security@cullis.io for clarifications, scope challenges,
or threat reports that fall under coordinated disclosure (see
[SECURITY.md](../../SECURITY.md)).

---

## 1. Introduction

Cullis is a zero-trust identity, policy, and audit substrate for AI
agents acting inside and across organisations. The product is composed
of three deployable components (Court, Mastio, Connector) plus two
SDKs (Python, TypeScript), and ships as both an open-core build and a
commercial enterprise build.

This document is the **public catalog** of threats Cullis has reasoned
about, the mitigations present in code, and the threats explicitly
**not** covered today (with the roadmap or compensating control). It
is intended for review before a pilot, not as a substitute for a
third-party penetration test (planned, funded by the first paid
engagement).

For a STRIDE walkthrough of each Cullis component (data flow per
trust boundary, mitigation per spoofing/tampering/repudiation/info
disclosure/DoS/elevation), see the deeper companion document on the
public site: [cullis.io threat model deep-dive](https://cullis.io/security/threat-model/).
That document is generated from the same source tree
(`site/src/content/docs/security/threat-model.md`) and is the
component-level analysis. This file is the customer-facing summary
and threat catalog.

### Why a public threat model

Customers performing security due diligence on agent identity
infrastructure need:

- A clear statement of what Cullis defends against.
- An equally clear statement of what it does **not** defend against,
  with the roadmap.
- A reference to the code or ADR that establishes each mitigation,
  not just an assertion.

A vendor that cannot articulate the residual risk is, in practice,
asking the customer to accept unbounded liability. This document
exists to remove that ambiguity.

### Versioning

| Version | Date       | Notes                                                            |
|---------|------------|------------------------------------------------------------------|
| 1.0     | 2026-05-18 | First publication. Aligns with Wave 1-A PKI hardening (PR #788). |

Future revisions will append rows here and update the "Next review"
date in the document header.

---

## 2. Trust model and components

### 2.1 Three components

| Component        | Path in repo        | Audience           | Responsibility                                                                 |
|------------------|---------------------|--------------------|--------------------------------------------------------------------------------|
| Cullis Court     | `app/`              | Network operator   | Federation broker, cross-org A2A routing, org registry, audit chain anchor.    |
| Cullis Mastio    | `mcp_proxy/`        | Org admin          | Agent enrolment, policy decision point, local audit, MCP reverse proxy, embedded AI gateway. |
| Cullis Connector | `cullis_connector/` | End user           | User identity (OIDC + WebAuthn Phase 2), MCP-to-Cullis bridge, dashboard at :7777. |

A single Mastio can be operated in **standalone** mode (air-gapped,
intra-org only, no Court attached) or **federated** mode (attached to
a Court, reaches Mastios in other orgs). The same binary supports
both; the operator flips a flag, no agent re-enrolment.

### 2.2 Four typed principals (ADR-020)

Every authenticated identity in Cullis falls into one of four typed
principals, each with its own cert SAN format and capability surface:

| Principal type | SAN format                         | Issued by                                  | Example                          |
|----------------|------------------------------------|--------------------------------------------|----------------------------------|
| `agent`        | `spiffe://<org>/agent/<id>`        | Mastio Intermediate CA                     | Long-lived autonomous service.   |
| `user`         | `spiffe://<org>/user/<sub>`        | Mastio Intermediate CA (via Connector SSO) | Human via Connector / Frontdesk. |
| `workload`     | `spiffe://<org>/workload/<id>`     | Mastio Intermediate CA (via SPIRE)         | CI job, batch process, SPIFFE-issued workload. |
| `mcp_resource` | `spiffe://<org>/mcp/<server>`      | Mastio Intermediate CA                     | A registered MCP server endpoint. |

The PDP and audit log derive authority from this typed principal,
not from any client-supplied header. See ADR-020 for the rationale.

### 2.3 Four interaction quadrants

Cross-component traffic falls into one of four quadrants, each with
its own policy gate and audit semantics:

| Quadrant | Caller    | Callee    | Typical example                                  |
|----------|-----------|-----------|--------------------------------------------------|
| A2A      | agent     | agent     | Autonomous agent in Org A invokes a tool exposed by Org B. |
| A2U      | agent     | user      | Agent proactively requests confirmation from a human. |
| U2A      | user      | agent     | Human (via Frontdesk chat) asks an agent to act. |
| U2U      | user      | user      | Cross-org introduction or message between principals. |

A2A and A2U cross-org calls are dual-allow: both orgs' PDPs must
authorise the call (ADR-029). Intra-org calls go through a single PDP.

### 2.4 Deployment modes

| Mode        | Court              | Mastio   | Connector | Use case                                                          |
|-------------|--------------------|----------|-----------|-------------------------------------------------------------------|
| Standalone  | absent             | yes      | optional  | Single-org, air-gapped, no cross-org federation.                  |
| Federated   | yes (shared)       | yes      | optional  | Cross-org A2A, registry sync, anchor of audit chains across orgs. |
| Frontdesk   | optional           | yes      | yes (shared) | Multi-user chat container in front of a single Mastio (ADR-019). |

---

## 3. Threats covered (in scope)

| Threat                                              | Mitigation                                                                                                                 | Reference                                                              |
|-----------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| Agent identity spoofing                             | mTLS with cert thumbprint pinning at Mastio, SPIFFE SAN bound to enrolment record.                                         | ADR-014, `mcp_proxy/auth/client_cert.py`                               |
| DPoP token theft                                    | RFC 9449 proof-of-possession: every request signed with the agent's ephemeral key, JWK thumbprint pinned to access token (`cnf.jkt`). | RFC 9449, `mcp_proxy/auth/dpop.py`                                     |
| Replay attack on DPoP proofs                        | Redis-backed JTI cache, 5-minute TTL, `SET NX EX` semantics. `htu` checked literally including scheme + host + port.       | `mcp_proxy/auth/dpop_jti_store.py`                                     |
| Audit chain tampering (write side)                  | Append-only schema enforced by a database trigger that raises on UPDATE/DELETE against `audit_log`, on both SQLite and Postgres. | `alembic/versions/r8m9n0o1p2q3_audit_append_only.py`                   |
| Audit chain tampering (retroactive)                 | Per-org SHA-256 hash chain (`entry_hash`, `previous_hash`). Chain head anchored to Court's `AuditTsaAnchor` every 60 minutes (configurable). | `alembic/versions/7f54c1eb5e89_add_audit_log_hash_chain.py`, `app/audit/tsa_worker.py` |
| Federation cross-org impersonation                  | Counter-signature: Mastio peer pubkey pinned at registration, every cross-org call signed by both Mastios.                | ADR-009                                                                |
| Org Root CA compromise via insider DB read          | Org Root private key stored Fernet-encrypted in `pki_key_store` (PBKDF2-HMAC-SHA256 600k + Fernet). Cold root: key not in memory at steady state, only unsealed for rare ops (mint Intermediate, rotate Intermediate, generate CA bundle), with audit row per unseal. | ADR-033 PKI three-tier, PR #788                                        |
| Mastio Intermediate CA compromise                   | Auto-rotation watcher signs new Intermediate from the Org Root; old leaves continue to verify against the new chain via the published CA bundle. 5-year validity, rotation hooks tested in CI. | PR #788, `mcp_proxy/egress/agent_manager.py`                           |
| Mastio Leaf (federation) compromise                 | Manual rotation via dashboard with 7-day grace; new key propagated to peer Mastios via Court ContinuityProof.              | ADR-009, dashboard `migrate-org-ca`                                    |
| Agent cert compromise                               | Revocation via dashboard form `rotate_agent_cert` invalidates the cert immediately; pinning rejects the old thumbprint. Grace-period transition (Wave 2 in progress) allows the agent to log in with either old or new cert during a configurable window before old is purged. | `app/registry/store.py`, Wave 2 fix 7 (in progress)                    |
| nginx server TLS cert expiry                        | Runtime watcher renews the cert before expiry and SIGHUP-reloads nginx; 90-day validity. Wave 2 fix 6 lands the watcher.   | `mcp_proxy/egress/agent_manager.py`, Wave 2 fix 6 (in progress)        |
| Tool capability bypass (privileged builtin)         | Post-LLM capability gate: every tool dispatch checks the typed principal's capabilities. Builtins fail closed by default. | PR #730, `mcp_proxy/tools/executor.py`                                 |
| PDP webhook timeout / failure                       | 5-second hard timeout, fail-deny on timeout. The decision row in the audit log records the timeout and the deny outcome. | `app/policy/webhook.py:75`                                             |
| Frontdesk shared-mode user impersonation (Phase 1)  | Mastio emits a structured audit warning on every request the Frontdesk forwards on behalf of a user that has not yet bound a WebAuthn credential. Operators alert on volume / off-hours patterns. | ADR-033 Frontdesk, `docs/runbooks/frontdesk-shared-hardening.md`       |
| Frontdesk shared-mode user impersonation (Phase 2)  | WebAuthn-bound session tokens: the user's browser signs a challenge with a FIDO2 authenticator, the assertion is included in the session token, the Mastio verifies it before honouring the on-behalf-of header. | PR #789, ADR-033 Phase 2                                               |
| Enrolment without proof-of-possession               | `pop_signature` field mandatory on `POST /v1/enrollment/start`. Connector signs `"enrollment-pop:v1\|<pubkey-sha256-hex>"` with the enrolling key. The transition window where the field was optional has closed. | PR #787, `mcp_proxy/auth/enrollment.py`                                |
| Enrolment endpoint flood                            | Rate-limited (5 starts per minute per IP, 60 status polls per minute per IP). Court federation CSR endpoints rate-limited per source IP and per target org. | PR #698                                                                |
| Registry record tampering (write side)              | All admin writes go through CSRF + httponly cookie + `MCP_PROXY_ADMIN_SECRET`. Every write logs to the audit chain with the admin principal. | `mcp_proxy/dashboard/`                                                 |
| AI gateway API key disclosure                       | Mastio's gateway never logs upstream API keys. Upstream credentials are Fernet-encrypted at rest (`MCP_PROXY_SECRET_ENCRYPTION_KEY_B64`); planned move to HSM-backed Fernet master key is tracked as P2. | `mcp_proxy/ai_gateway/`, `mcp_proxy/secret_encrypt.py`                 |
| Plain Bearer tokens                                 | The proxy rejects any request authenticated with `Authorization: Bearer ...` that is not paired with a valid DPoP proof. | `mcp_proxy/auth/dpop.py`                                               |
| Dashboard CSRF / clickjacking                       | Cookie HMAC-SHA256 with `httponly` + `secure` + `samesite=lax`. CSRF token per-session, constant-time verify on every POST. X-Frame-Options DENY, CSP, X-Content-Type-Options nosniff, Referrer-Policy on every admin response. | `app/dashboard/session.py`, `mcp_proxy/dashboard/`                     |
| License JWT forgery                                 | RS256 verification against a public key baked into the image at build time (fingerprint pinned). No fallback path that accepts an unsigned token. | PR #691, `mcp_proxy/license.py`                                        |

---

## 4. Threats not covered (out of scope, with rationale)

This section is deliberately explicit. A reviewer who finds a gap
should be able to see whether we know about it, what compensating
control we expect the operator to apply, and what the roadmap is.

| Threat                                                          | Why out of scope today                                                                                                                                                            | Compensating control / roadmap                                                                                                            |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| Host OS compromise                                              | Cullis runs as a process inside a container. Root on the host reads everything on the data bind mount, including encrypted PKI material if the operator's encryption-key env var is in scope. | OS hardening (CIS benchmark or equivalent), rootless container runtime, KMS-backed encryption key (Vault Agent) so that the env var is not on disk. |
| Container RCE / supply-chain attack on Mastio dependencies      | Cullis does not currently run a runtime SBOM verification step inside the container. Reproducible builds are on the roadmap.                                                       | Cosign-signed images, Trivy scan in CI (ignore-unfixed=true with explicit residual disclosure in each release), CycloneDX SBOM per release, customer-side cosign verify on every deploy. P1 roadmap: reproducible builds + dependency lockfile. |
| Quantum-resistant cryptography                                  | Cullis uses classical primitives today (ECDSA P-256, RSA-PSS, AES-256-GCM, RSA-OAEP-SHA256, ECDH P-256, SHA-256). Hybrid PQC is on the roadmap, gated by upstream library maturity. | See [`docs/security/post-quantum-roadmap.md`](./post-quantum-roadmap.md). Phase 0 (positioning, monitoring NIST FIPS 203/204/205 + IETF drafts) is active. Phase 1a triggers when pyca/cryptography ships ML-KEM stable, liboqs-python installs cleanly on NixOS, or a concrete buyer signal arrives. |
| Social engineering of the Connector admin / org admin           | Cullis cannot defend against an admin who clicks "approve" on a hostile enrolment request, or who pastes an API key into a chat tool.                                              | The admin dashboard surfaces the public key fingerprint pre-approval (PR #687). SECURITY.md mandates immediate rotation if a key is ever leaked. 4-eyes enterprise plugin gates a configured set of admin actions; extending the set to enrolment is on the P1 roadmap. |
| Colluding admins at the enterprise tier                         | The 4-eyes plugin assumes the two admins are not the same person and not colluding. A colluding pair defeats it.                                                                   | Operational separation of duties + RBAC multi-admin plugin (scoped roles). Audit chain provides forensic detection.                       |
| Insider holding both Mastio DB access **and** `MCP_PROXY_DB_ENCRYPTION_KEY` | The at-rest encryption envelope is keyed off this env var. An insider with both reads the Org Root key in cleartext.                                                                 | Mount the env var from a secrets manager (Vault Agent) so the value is not on disk and is rotated independently of the DB. KMS-backed envelope (cloud KMS plugin) raises the bar further.   |
| Court availability denial-of-service                            | Federation in degraded mode (Court unreachable) blocks cross-org A2A and registry sync. There is no auto-failover Court today.                                                     | Operators who require active-active federation should peer Mastios via Court mirror (P2 roadmap) or scale Court horizontally behind a load balancer. Standalone mode is unaffected.       |
| GDPR right-to-be-forgotten on audit chain entries               | The audit chain is append-only by design; deleting a row breaks the chain.                                                                                                         | Architectural roadmap: redact-by-tombstone proposal (P3, not started). Until then, operators store only the minimum personal data the regulator allows in an append-only artefact. We surface the `on_behalf_of_user_id` field but do not bind PII directly. |
| WebAuthn enforcement on Frontdesk shared mode                   | Phase 1 (current default) is **warn** during the migration window. Without WebAuthn, a compromised Frontdesk container can impersonate any user.                                  | Phase 2 (PR #789) lands the cryptographic fix. Customers who require it today set `MCP_PROXY_WEBAUTHN_REQUIRED=true` in `proxy.env`. See [`docs/runbooks/frontdesk-shared-hardening.md`](../runbooks/frontdesk-shared-hardening.md). |
| Sybil federation (open Court accepts any registered org)        | Court accepts any registered org by default. A motivated attacker can register hostile orgs.                                                                                       | Set `MCP_PROXY_FEDERATION_ALLOWLIST` to a closed list of trusted peer orgs (operator runbook). Court-side admission policy is on the P2 roadmap.                                          |
| Downstream LLM provider behaviour (Anthropic, OpenAI, etc.)     | Cullis is infrastructure, not a content classifier. Prompt injection against the upstream LLM is the upstream's responsibility.                                                    | The enterprise LLM Guardian plugin provides outbound content filtering and inbound prompt classification. Customers without Guardian own the content boundary.                            |
| Side channels on bcrypt admin token storage                     | We use bcrypt cost factor 12 (OWASP 2024 guidance). A leaked hash is offline-attackable.                                                                                           | Rotation policy in `operate/rotate-keys.md`. Move to argon2id is on the P3 roadmap.                                                                                                       |

---

## 5. Cryptographic primitives and standards

| Primitive                          | Use                                                                | Standard                                  |
|------------------------------------|--------------------------------------------------------------------|-------------------------------------------|
| ECDSA P-256                        | Per-agent identity cert signing, DPoP proof signing (ES256).        | NIST FIPS 186-4, NIST P-256.              |
| RSA-PSS-SHA256                     | E2E inner + outer signature (legacy classical path).                | RFC 8017.                                 |
| AES-256-GCM                        | E2E payload, audit log encrypted columns.                          | NIST FIPS 197, NIST SP 800-38D.           |
| RSA-OAEP-SHA256                    | E2E key encapsulation.                                              | RFC 8017.                                 |
| ECDH P-256                         | TLS 1.3 key exchange.                                               | NIST SP 800-56A.                          |
| PBKDF2-HMAC-SHA256 (600k) + Fernet | Org Root and Mastio Intermediate private keys at rest (`pki_key_store`). | NIST SP 800-132 (PBKDF2), Fernet spec.    |
| SHA-256                            | Audit hash chain, JWK thumbprint (RFC 7638), cert thumbprint pinning. | NIST FIPS 180-4.                          |
| DPoP                               | Token binding on every authenticated endpoint.                      | RFC 9449.                                 |
| mTLS cert-bound tokens             | Transport-layer hybrid binding (optional, defence in depth).         | RFC 8705 section 3.                       |
| JWK thumbprint                     | DPoP `cnf.jkt` claim binding the access token to the proof key.     | RFC 7638.                                 |
| WebAuthn / FIDO2                   | User-bound session assertion on Frontdesk shared mode (Phase 2).    | W3C WebAuthn Level 2, FIDO2 CTAP2.        |
| SPIFFE                             | Typed principal SAN format for agent / user / workload identity.    | SPIFFE specs.                             |
| PQC (planned, hybrid)              | ML-KEM-768 KEM and ML-DSA-65 sig, hybrid with X25519 / ECDSA. Phase 1a, gated by upstream. | NIST FIPS 203, FIPS 204, FIPS 205.        |

See [`docs/security/post-quantum-roadmap.md`](./post-quantum-roadmap.md) for the PQC migration plan.

---

## 6. Trust boundaries

Each labelled boundary below is enforced by a distinct mechanism. A
defect in one boundary does not collapse the others.

- **Court to Mastio (cross-org federation).** Authenticated by the
  Mastio's pinned peer public key, registered with Court at first
  federation. Every cross-org call counter-signed by the Mastio
  (ADR-009).
- **Mastio to Mastio (intra-federation A2A).** Routed through Court;
  same counter-sig and dual-allow PDP gate.
- **Mastio to Connector.** mTLS RFC 8705 with the Connector's
  client cert; the Mastio pins the Connector's thumbprint at first
  enrolment.
- **Connector to User.** Local OIDC handshake for first login, then
  short-lived session tokens. Phase 2 adds WebAuthn assertion on
  every session refresh (PR #789).
- **Mastio to Agent.** mTLS + DPoP. The mTLS layer is pinning-based
  defence in depth; the DPoP proof is the formal binding.
- **Mastio to MCP resource (external).** Outbound to the per-tool
  upstream URL, gated by the per-tool domain allow-list
  (`mcp_proxy/tools/http_whitelist.py`), TLS terminated against
  the operator's trust store. Per-tool credential is bound at
  registration and never propagated from client headers.

---

## 7. Key lifecycle

| Key                          | Validity   | Rotation                                                          | Compromise recovery                                                                  |
|------------------------------|------------|-------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| Org Root CA                  | 15 years   | Manual only, no automation today (intentional, coupled to PQC Phase 1a; see post-quantum-roadmap.md section 8). Cold root: private key not in memory at steady state, unsealed for rare ops with audit row per unseal. | New Org Root + rebuild Intermediate + bulk re-enrol every agent. Painful by design, documented in `operate/rotate-keys.md`. |
| Mastio Intermediate CA       | 5 years    | Auto-rotation watcher (Wave 1-A, PR #788). New Intermediate signed by Org Root, old leaves continue to verify against the chain via the published CA bundle. | Rotate the Intermediate (no Org Root unseal needed for the leaf chain to keep working). Existing leaves remain valid; new leaves issued by the new Intermediate. |
| Mastio Leaf (federation)     | 1 year     | Manual via dashboard `migrate-org-ca` form, 7-day grace, propagation to peer Mastios via Court ContinuityProof. | Revoke the leaf, issue a new one, push ContinuityProof to peers, audit chain captures the rotation event. |
| Agent leaf cert              | 1 year     | Manual via dashboard `rotate_agent_cert` form. Wave 2 fix 7 adds API endpoint + grace period (24-48 h configurable) so the agent transitions without an enrolment outage. | Revoke + re-enrol the agent. Existing DPoP proofs are immediately rejected (thumbprint mismatch). Grace period covers the transition window. |
| nginx server TLS cert        | 90 days    | Runtime watcher renews + SIGHUP-reloads nginx (Wave 2 fix 6, in progress). | Force-renew via the watcher's CLI; SIGHUP path is the same as auto-renew. |
| User OIDC session cert       | 1 hour     | Client-driven refresh from the IdP JWT.                            | Token expires on its own; revocation via the IdP's standard flow.                  |
| WebAuthn credential          | Long-lived (per browser / authenticator) | Revocable per principal via the dashboard.                          | Revoke the credential; the user re-binds a new authenticator at next login.        |
| Dashboard admin secret       | Long-lived | Rotate via env + restart (`MCP_PROXY_DASHBOARD_SIGNING_KEY`).      | Re-issue all admin tokens; old session cookies fail HMAC verification.             |
| License JWT signing key      | Annual     | Annual ceremony, new prod image bakes the new pubkey, customers re-deploy. | Roll the priv-key, re-mint every active customer's JWT, ship a new image tag. Emergency procedure.  |
| KMS / Vault tokens           | Per Vault policy (short TTL) | Automated by Vault.                                               | Vault revokes; Mastio retries with a fresh token.                                  |

---

## 8. Audit trail integrity

- **Append-only schema.** A database trigger raises on UPDATE or
  DELETE against `audit_log`, on both SQLite and Postgres
  (`alembic/versions/r8m9n0o1p2q3_audit_append_only.py`). No code
  path writes around this trigger.
- **Per-entry hash chain.** Each row has an `entry_hash` (SHA-256 of
  the canonical representation) and a `previous_hash` linking to
  the prior entry. Replay verification reads the chain from genesis
  and recomputes the hashes.
- **Court anchor.** A background worker (`app/audit/tsa_worker.py`)
  writes the current chain head into Court's `AuditTsaAnchor` table
  every `audit_tsa_interval_seconds` (default 3600, configurable).
  Federated installs use the Court anchor as the second source of
  truth for chain-head verification.
- **Dual-write (federated mode).** Every cross-org event is
  replicated to Court's `mastio_audit_replica` table at the time of
  the request. Dispute resolution between two orgs uses the Court
  copy as the neutral third witness.
- **Export and verify.** Bundles include a CLI tool that walks the
  exported chain, recomputes hashes, and reports the first divergent
  row if any.

**Residual:** an attacker controlling **both** the Mastio host **and**
Court can rewrite history. We document this Byzantine assumption in
ADR-013 (layered defence). Customers needing stronger guarantees
should peer Cullis with an external append-only sink (SIEM, S3
Object Lock, blockchain anchor) or run their own Court without
federation.

---

## 9. Incident response posture

Coordinated disclosure, severity classification, response SLAs, and
the response runbook live in:

- [`SECURITY.md`](../../SECURITY.md): how to report a vulnerability,
  acknowledgment and triage SLAs, supported version matrix, safe
  harbour.
- [`docs/runbooks/incident-response.md`](../runbooks/incident-response.md):
  severity classification (Sev 1 through Sev 4), response procedure
  per severity, customer notification template, public disclosure
  template.

Top-line SLAs:

| Phase                      | Target                                              |
|----------------------------|-----------------------------------------------------|
| Acknowledgment             | within 48 hours                                     |
| Initial triage             | within 7 days                                       |
| Fix for CRITICAL (CVSS >=9)| within 7 days                                       |
| Fix for HIGH (CVSS 7-8.9)  | within 14 days                                      |
| Fix for MEDIUM             | within 30 days                                      |
| Public disclosure          | 90 days after report, or upon coordinated release   |

---

## 10. Compliance mapping (preview)

Cullis is built with regulated-industry deployments in mind (DORA,
NIS2, AI Act, GDPR). Full compliance mapping documents are tracked
on the roadmap and will land in `docs/compliance/` once each
regulation's applicable controls are mapped to Cullis features:

| Framework      | Status                                               | Cullis surface                                                                 |
|----------------|------------------------------------------------------|--------------------------------------------------------------------------------|
| DORA           | Roadmap (Q3 2026, banking pilot dependency)         | ICT third-party risk register, append-only audit log, incident reporting flow. |
| NIS2           | Roadmap (Q4 2026)                                    | Identity governance, audit retention, supply-chain attestations.               |
| EU AI Act      | Roadmap (Q4 2026)                                    | Agent identity, audit trail, human-in-the-loop (A2U quadrant).                 |
| GDPR DPIA      | Roadmap (Q3 2026)                                    | Lawful basis per quadrant, retention controls, right-to-be-forgotten plan.     |
| SOC 2 Type II  | Deferred until first paid engagement                 | Audit chain, key custody, change management.                                   |

This document does **not** claim compliance with any of the above; it
states what surface Cullis exposes that a customer's compliance team
can map against. The mapping itself is the customer's
responsibility, with our support.

---

## 11. Related documents

- [`SECURITY.md`](../../SECURITY.md): responsible disclosure policy,
  supported versions, safe harbour.
- [`docs/runbooks/incident-response.md`](../runbooks/incident-response.md):
  internal IR playbook for Sev 1 through Sev 4 events.
- [`docs/security/post-quantum-roadmap.md`](./post-quantum-roadmap.md):
  PQC strategy, five-phase roadmap, upstream blockers, spike
  validation numbers.
- [`docs/runbooks/frontdesk-shared-hardening.md`](../runbooks/frontdesk-shared-hardening.md):
  Frontdesk shared-mode hardening checklist, Phase 1 audit warning,
  Phase 2 WebAuthn.
- [`docs/architecture/byoca-current-state.md`](../architecture/byoca-current-state.md):
  BYOCA (Bring Your Own CA) implementation status and gap.
- [cullis.io threat model deep-dive](https://cullis.io/security/threat-model/):
  STRIDE walkthrough per component, source in
  `site/src/content/docs/security/threat-model.md`.
- ADR-009 (counter-sig federation), ADR-014 (mTLS Connector to
  Mastio), ADR-017 (embedded LiteLLM AI gateway), ADR-019 (Cullis
  Frontdesk), ADR-020 (typed principals + four quadrants), ADR-021
  (Frontdesk shared mode + per-user KMS), ADR-029 (tool-level PDP),
  ADR-031 (Vault as Org CA KMS backend), ADR-033 (PKI three-tier
  hardening), ADR-033 (Frontdesk shared-mode threat model). Public
  ADRs are in `docs/adrs/`; ADRs with commercial-sensitive content
  are internal-only in `imp/adrs/`.

---

## 12. Revision history

| Version | Date       | Author              | Notes                                                                |
|---------|------------|---------------------|----------------------------------------------------------------------|
| 1.0     | 2026-05-18 | Cullis security team | First publication. Aligned to Wave 1-A PKI hardening + ADR-033 Phase 2 WebAuthn (PR #785-789). |

Next review: 2026-08-18. Triggers for an out-of-cycle revision: new
ADR ratified, new threat discovered, third-party penetration test
report, customer feedback that lands a substantive correction.
