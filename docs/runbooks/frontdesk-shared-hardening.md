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

## Roadmap: Cryptographic Fix (Phase 2)

Phase 2, planned for the first Frontdesk shared customer engagement, adds WebAuthn-bound session tokens:

1. At login, the user's browser signs a challenge using a FIDO2 authenticator (platform authenticator or YubiKey).
2. The signature is included in the session token as a `user_signed_assertion` field.
3. The Mastio verifies the assertion against the user's registered public key before accepting the session.

After Phase 2, compromising the Connector container alone is not sufficient to impersonate users. The attacker also needs access to each user's authenticator device. The `frontdesk_shared_unauthenticated_user_session_warning` audit events will stop appearing once users have enrolled a WebAuthn credential.

Phase 3 (long term) adds TPM-bound device attestation for regulated-industry deployments where the threat model extends to compromised user devices.

---

## References

- ADR-019: Cullis Frontdesk architecture and distribution channels (`imp/adrs/adr-019-cullis-frontdesk.md`)
- ADR-020: User principal and request quadrants (`imp/adrs/adr-020-user-principal-and-quadrants.md`)
- ADR-033: Frontdesk shared-mode threat model and remediation roadmap (`imp/adrs/adr-033-frontdesk-threat-model-shared-mode.md`, internal)
- Mastio bundle deploy guide: `packaging/frontdesk-bundle/README.md`
