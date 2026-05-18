# Frontdesk Shared-Mode Security Hardening

**Audience:** IT/security administrators deploying the Cullis Frontdesk container bundle in shared mode (multiple users on a single container instance).

**Applies to:** Frontdesk bundle v0.4.x and later (`cullis-frontdesk-bundle`).

---

## Threat Overview

Frontdesk shared mode runs a single Connector container that handles authentication on behalf of multiple users. When a user logs in via SSO, the Connector issues a short-lived session token and forwards requests to the Mastio with an `X-Cullis-On-Behalf-Of-User` header identifying the user.

This design gives the Connector container a high level of inherent trust: it is the authoritative source of user identity claims toward the Mastio. If the container is compromised (for example, via a supply-chain attack on a dependency, a container escape, or a misconfigured volume mount), an attacker who controls the container can issue requests attributed to any user in the organisation.

Container hardening reduces the probability of compromise, but does not eliminate it by design. This runbook documents the operational controls that bring the residual risk to an acceptable level for production deployments.

A cryptographic fix (WebAuthn-bound session tokens) is in the roadmap as Phase 2 and is the target state for regulated-industry customers. See "Roadmap" below.

---

## Operational Mitigations

### 1. Container Security Hardening

Run the Frontdesk container with the following Docker configuration:

```yaml
# docker-compose.yml (relevant security settings)
services:
  cullis-connector:
    read_only: true
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined    # replace with a custom profile in production
    cap_drop:
      - ALL
    tmpfs:
      - /tmp
      - /run
    volumes:
      # Bind-mount only the data directory; no docker.sock mount.
      - ./connector_data:/app/data:rw
```

Key requirements:

- **Read-only root filesystem.** Prevents an attacker from modifying the container image on disk.
- **No `docker.sock` mount.** Mounting the Docker socket grants effective root on the host. Never mount it inside the Frontdesk container.
- **Drop all capabilities.** The Connector process does not need any Linux capabilities.
- **No `--privileged` flag.** Never run the Frontdesk container in privileged mode.
- **Custom seccomp profile.** The default Docker seccomp profile is a good baseline. For production, apply a custom profile that blocks `ptrace`, `process_vm_readv`, and other memory-introspection syscalls.

### 2. Network Isolation

The Frontdesk container should only be able to reach the Mastio on your LAN. It should have no direct internet egress.

```yaml
services:
  cullis-connector:
    networks:
      - internal
    # Do NOT attach to a network with internet access.

networks:
  internal:
    internal: true
```

Firewall rules (apply at the host or on a dedicated security group):

| Direction | Source | Destination | Port | Rule |
|---|---|---|---|---|
| Inbound | User browsers | Frontdesk container | 4321/TCP | Allow |
| Outbound | Frontdesk container | Mastio | 9443/TCP | Allow |
| Outbound | Frontdesk container | IdP (OIDC only) | 443/TCP | Allow |
| Outbound | Frontdesk container | `*` (internet) | any | Deny |

### 3. Monitoring and Alerting

The Mastio emits a structured audit event every time the Frontdesk uses a session token that lacks a user cryptographic signature:

```
action: frontdesk_shared_unauthenticated_user_session_warning
```

This event fires on every authenticated request today (pre-Phase-2). Use it as a baseline metric, then alert on anomalous patterns:

- **Volume spike.** More than 10 events per minute from a single `connector_agent_id` when the expected concurrency is lower suggests automated exploitation.
- **Off-hours access.** Requests attributed to users outside business hours may indicate stolen sessions.
- **User enumeration.** A rapid sequence of requests attributed to many distinct users in a short window is a strong signal of automated impersonation.

Example Grafana alert (pseudo-query):

```
count_over_time(
  {action="frontdesk_shared_unauthenticated_user_session_warning"}[1m]
) > 10
```

You can disable the audit warning in non-production environments by setting `MCP_PROXY_FRONTDESK_AUDIT_WARNING_ENABLED=false` in `proxy.env`. Do not disable this in production.

### 4. Update Cadence

Keep the Frontdesk container up to date. Container images are published on each Mastio release at `ghcr.io/cullis-security/cullis-chat-frontdesk`. Enable automated image pulls on a schedule that matches your organisation's vulnerability remediation SLA.

To upgrade the bundle:

```bash
./deploy.sh --pull
```

Do not run `docker compose up -d` directly; it derives the wrong project name and creates an orphaned parallel stack. Always use `deploy.sh`.

### 5. Compromise Response

If you suspect the Frontdesk container has been compromised, follow these steps immediately:

**Step 1: Revoke the Connector certificate.**

```bash
# Find the Connector agent ID in the Mastio dashboard under Agents.
curl -X POST https://<mastio-host>:9443/v1/admin/agents/<connector-agent-id>/revoke \
  -H "Authorization: Bearer <admin-token>"
```

After revocation, the Mastio rejects all DPoP-authenticated requests from the Connector. Existing user sessions are invalidated because they depend on the Connector's cert thumbprint for pinning.

**Step 2: Revoke all user sessions.**

```bash
# Force all user sessions issued by this Connector to expire.
curl -X POST https://<mastio-host>:9443/v1/admin/agents/<connector-agent-id>/revoke-all-sessions \
  -H "Authorization: Bearer <admin-token>"
```

**Step 3: Take the container offline.**

```bash
docker compose -p cullis-frontdesk down
```

**Step 4: Audit the access log.**

Review the audit chain for the period from the suspected compromise to the revocation. Focus on entries with `on_behalf_of_user_id` populated — these show which users were potentially impersonated.

**Step 5: Re-enroll after investigation.**

After verifying the container image and configuration are clean, bring the bundle back up with `./deploy.sh` and re-approve the Connector enrollment in the Mastio dashboard. All users will need to log in again.

---

## WebAuthn user enrollment procedure (ADR-033 Phase 2)

WebAuthn-bound session tokens cut the residual trust the Mastio places in the Connector container: the user proves they consented to each session through an authenticator the Connector never sees the private key of. This section documents the enrollment + migration steps an administrator runs to flip a deployment from the Phase 1 warn-only posture to Phase 2 hard enforcement.

### Prerequisites

- Frontdesk bundle v0.4.x or later with the `[webauthn]` extra installed on the Mastio image. The bundle image published from the `release-mastio-enterprise.yml` workflow includes the extra; an air-gapped operator who rebuilds the image manually adds `pip install 'cullis-agent-sdk[webauthn]'` to the Dockerfile.
- Mastio nginx sidecar reachable from each user's browser via a stable DNS name (the `MCP_PROXY_WEBAUTHN_RP_ID` value below must match the host the browser sees).
- Each user has at least one WebAuthn authenticator available (passkey synchronised through Apple/Google, YubiKey 5-series, Windows Hello on Win10+, Touch ID on macOS).

### Configuration

Add to `proxy.env`:

```
MCP_PROXY_WEBAUTHN_RP_ID=mastio.example.corp
MCP_PROXY_WEBAUTHN_RP_NAME=Acme Frontdesk
MCP_PROXY_WEBAUTHN_ENFORCEMENT=warn
MCP_PROXY_WEBAUTHN_CHALLENGE_TTL_SECONDS=300
MCP_PROXY_WEBAUTHN_EXPECTED_ORIGIN=https://mastio.example.corp,https://frontdesk.example.corp:9443
```

Then `./deploy.sh --pull` from the bundle to apply.

Notes:

- Start with `MCP_PROXY_WEBAUTHN_ENFORCEMENT=warn`. The warn mode emits the legacy Phase 1 audit row (`frontdesk_shared_unauthenticated_user_session_warning`) when a user has not yet enrolled, but still issues the session. This is the migration window.
- `MCP_PROXY_WEBAUTHN_EXPECTED_ORIGIN` is a comma-separated allow-list. Include every host name a user's browser may use to reach the dashboard. An empty value defaults to `https://<rp_id>`.
- The Mastio refuses to start when `MCP_PROXY_WEBAUTHN_ENFORCEMENT=required` but the `webauthn` library is not importable, or when `MCP_PROXY_WEBAUTHN_RP_ID` is empty. This is intentional: production deployments fail loud rather than 500-ing every user login.

### User enrollment flow

1. The user opens the Connector dashboard (`https://frontdesk.example.corp:9443/webauthn` by default).
2. The page lists registered authenticators (empty on first visit) and exposes an "Add a new authenticator" button.
3. Clicking the button triggers `navigator.credentials.create` in the browser, which prompts for the user's gesture (Touch ID, YubiKey tap, Windows Hello PIN).
4. The browser returns an `AttestationResponse`; the Connector dashboard forwards it to `POST /v1/principals/{principal_id}/webauthn/register/finish`.
5. On success the Mastio writes a `frontdesk_shared_webauthn_credential_registered` audit chain entry. The user can name the authenticator (e.g. "YubiKey 5C", "MacBook Touch ID") for later identification.

The user can repeat the flow to register additional authenticators (recommended: at least one platform authenticator + one roaming key, so a lost device does not lock them out).

### Migration: from `warn` to `required`

After every active user has registered at least one authenticator (verify via the audit chain query in the next subsection):

1. Flip `MCP_PROXY_WEBAUTHN_ENFORCEMENT=required` in `proxy.env`.
2. Re-run `./deploy.sh --pull`.
3. From this point onwards, the Mastio rejects (HTTP 401) any session emission lacking a WebAuthn assertion. The Connector dashboard handles the 401 by sending the user through the WebAuthn ceremony before retrying the login.

### Auditing enrollment status

The Mastio audit chain records four event types relevant to WebAuthn:

| Event | Meaning |
|---|---|
| `frontdesk_shared_webauthn_credential_registered` | User completed a registration ceremony. |
| `frontdesk_shared_webauthn_credential_revoked` | User (or admin) revoked a credential. |
| `frontdesk_shared_authenticated_user_session` | Session emitted with a verified assertion. |
| `frontdesk_shared_webauthn_enforcement_rejected` | `required` enforcement refused a session for missing assertion. |

Use these to drive the readiness dashboard before flipping enforcement. A simple readiness check: for each `principal_id` in `local_user_principals`, confirm at least one `frontdesk_shared_webauthn_credential_registered` row exists.

### Rollback

If the migration to `required` exposes a regression (for example, a user whose authenticator stopped working), set `MCP_PROXY_WEBAUTHN_ENFORCEMENT=warn` and redeploy. Existing assertion-bound sessions keep working; sessions emitted during the rollback fall back to the Phase 1 warning path until the user re-enrolls.

---

## Roadmap

Phase 1 (PR #786, merged 2026-05-18): audit chain visibility for sessions emitted without a user-signed assertion. Operators run regex-on-rate alerts against `frontdesk_shared_unauthenticated_user_session_warning` to surface anomalous on-behalf-of volume before the cryptographic fix lands.

Phase 2 (this runbook section): WebAuthn-bound session tokens. The user's browser signs a challenge with a FIDO2 authenticator at login; the signature is verified by the Mastio and persisted on the `user_sessions` row. After enrollment the `frontdesk_shared_unauthenticated_user_session_warning` events stop appearing for the migrated user.

Phase 2b (next): wire the Connector dashboard proxy to the shared Ambassador HTTP client so the WebAuthn endpoints work end-to-end on a stock Frontdesk bundle. Today the dashboard surfaces a 501 banner when the proxy cannot reach a configured Mastio client. Operators running the standalone Mastio reach the endpoints directly with their existing API client.

Phase 3 (long term): TPM-bound device attestation for regulated-industry deployments where the threat model extends to compromised user devices.

---

## References

- ADR-019: Cullis Frontdesk architecture and distribution channels (`imp/adrs/adr-019-cullis-frontdesk.md`)
- ADR-020: User principal and request quadrants (`imp/adrs/adr-020-user-principal-and-quadrants.md`)
- ADR-033: Frontdesk shared-mode threat model and remediation roadmap (`imp/adrs/adr-033-frontdesk-threat-model-shared-mode.md`, internal)
- Mastio bundle deploy guide: `packaging/frontdesk-bundle/README.md`
