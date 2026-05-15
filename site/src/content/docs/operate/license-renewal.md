---
title: "License renewal"
description: "Rotate the Cullis enterprise license JWT every 90 days without bouncing the Mastio. Hot-swap recipe, validation rules, 4-eyes signoff, and audit trail."
category: "Operate"
order: 22
updated: "2026-05-15"
---

# License renewal

**Who this is for**: a Mastio operator on a paid tier who needs to rotate the enterprise license JWT on the standard 90-day cadence (or out-of-cycle after a tier change or suspected key exposure). The operation does not require a container restart.

## Prerequisites

- Mastio admin login to `/proxy/login`
- The new license JWT, issued by Cullis Security and delivered out-of-band (1Password share, signed email)
- `curl` on the host if you prefer the CLI to the dashboard form
- A second admin account when the `rbac_multi_admin` enterprise plugin is loaded (the swap is 4-eyes gated, see below)

## Why 90 days

The license JWT carries an `exp` claim. Cullis Security mints rotations with a 90-day window so the operator has a predictable cadence to plan, the same rhythm as standard TLS leaf certs. After the `exp` instant the Mastio drops to community tier on the next plugin gate check, paid plugins refuse to load, and the dashboard shows a "license expired" banner. The chain of custody is the same key that signed the previous JWT, so an expired license never silently disables the bundle's authentication primitives.

## The flow

### 1. Verify the candidate JWT before submitting

Before pasting a JWT into the dashboard, confirm it parses and that the `org` claim matches your deployment. Replace `<JWT>` with the new token:

```bash
echo "<JWT>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

You expect a JSON object shaped like:

```json
{
  "tier": "enterprise",
  "org": "your-org-id",
  "features": ["saml_sso", "rbac_multi_admin", "..."],
  "exp": 1748563200
}
```

Read the `org` and the `exp` (epoch seconds) before submitting. If `org` doesn't match your deployment's `MCP_PROXY_ORG_ID`, you have the wrong JWT, **stop here** and ask the issuer for the right one. The Mastio will reject a mismatched JWT at swap time, but catching it locally avoids a noisy audit row.

### 2. Submit the rotation

#### Via the dashboard (recommended)

1. Log in at `/proxy/login` with an admin account.
2. Open `/proxy/settings`.
3. Paste the JWT into the **License** form.
4. Click **Submit**.

The browser is redirected back to `/proxy/settings` with either a success flash naming the new tier or a red error flash naming the verification failure (expired, wrong-signature, paste error). The cached license is replaced atomically; the plugin registry re-filters against the new feature set on the next request.

#### Via curl

For scripted rotations or air-gapped operators driving the dashboard over the loopback:

```bash
# Open a session, capture the CSRF cookie + token in JAR-shape.
curl -sk -c jar.txt -b jar.txt \
    -d "password=$MCP_PROXY_ADMIN_PASSWORD" \
    https://your-mastio.example.com:9443/proxy/login

# Read the CSRF token from the cookie jar; the dashboard injects it
# into every form, but the API path is just a header.
CSRF=$(grep proxy_csrf jar.txt | awk '{print $NF}')

# Submit the swap.
curl -sk -c jar.txt -b jar.txt \
    -H "X-CSRF-Token: $CSRF" \
    -d "license_jwt=$NEW_JWT" \
    https://your-mastio.example.com:9443/proxy/settings/license
```

The endpoint returns a 303 to `/proxy/settings?ok=...` on success or `/proxy/settings?error=...` on validation failure. The HTTP body is empty by design; the audit log is the authoritative record.

### 3. Confirm the new license is live

```bash
curl -sk https://your-mastio.example.com:9443/health | jq .
```

The `/health` response includes the active tier and feature count. Compare against what you expect from the JWT decoded in step 1.

## 4-eyes signoff

When the enterprise `rbac_multi_admin` plugin is loaded and its `DEFAULT_POLICIES` matrix is in effect, license import is gated by `ACTION_LICENSE_IMPORT`: the submitter sees a 303 redirect to `/proxy/admin/approvals/<id>` and the swap is held in the approval queue until a second admin (compliance-leaning or super-admin role) signs off. The signed-off action is replayed by the plugin against the same endpoint with an internal-replay marker, so the swap actually fires only after both approvals are in.

Operators running open-core / single-admin deploys observe none of this: the `maybe_intercept_for_approval` helper returns `None` and the swap proceeds inline.

## Audit trail

Every swap attempt produces one `audit_log` row, success or failure:

| Field | Success | Failure |
|---|---|---|
| `action` | `license_swap` | `license_swap` |
| `status` | `success` | `error` |
| `detail` | `tier=... org=... features=N exp=... actor=...` | `reason=<message> actor=...` |

The candidate JWT itself is **not** included in the row. A bad paste (wrong-tenant JWT, an expired one cycled by mistake) leaves a forensic trace without leaking the token. The hash chain links every row to the previous one, so an attacker who suppresses an audit failure has to rewrite every subsequent chain link to keep `verify_audit_chain` green.

## Recovery scenarios

### Submitted the wrong JWT

`swap_token` validates before replacing the cache. A wrong-signature or expired JWT is rejected and the cache is unchanged: paid plugins keep working with the previous license. Just submit the correct JWT to retry.

### Submitted a downgrade by mistake

Tier downgrades and entitlement narrowing are legitimate operator actions (a customer downsizing their plan). If you swapped down by mistake, paste the previous JWT again; the swap is fully reversible until that JWT itself expires.

### The license expired and the cache is now community

You can submit the renewal JWT directly via the dashboard or `curl`. The community-tier state is just a cached `LicenseClaims` instance; there is no on-disk record to undo. After a successful swap the tier comes back up on the next plugin gate.

### Lost dashboard access during rotation

Set `MCP_PROXY_FORCE_LOCAL_PASSWORD=true` to re-enable the local admin password sign-in path even if SSO is broken; see `operate/runbook.md` for the full break-glass procedure. The license swap itself is independent of the sign-in path and uses the same admin token as the rest of the dashboard.

## Procedural calendar (suggested)

| Day relative to `exp` | Action |
|---|---|
| -30 | Cullis Security ships the new JWT out-of-band |
| -14 | Schedule the rotation window with your second admin (4-eyes deploys) |
| -7 | Decode the JWT, confirm `org`, `tier`, and `features` shape against your contract |
| 0 (rotation day) | Submit via dashboard or curl, confirm new tier via `/health` |
| +1 | Read `audit_log` to confirm the `license_swap` row with `status=success` is present and chained |

A calendar reminder at day -30 keeps the rotation comfortable. Cullis Security tracks customer JWTs on a per-tenant calendar and will reach out at -30 if no acknowledgement arrives.

## Why this is safer than a restart

Restarting the container to reload `CULLIS_LICENSE_KEY` would also:

- drop the in-process Redis DPoP JTI cache (cold start = lower replay protection until the cache fills again, see the threat-model boot-window note in the agent-authentication section)
- bounce every WebSocket session (UI flicker for any active dashboard users)
- re-run the first-boot wizard if a configuration knob accidentally regressed since last boot

The hot-swap path avoids all three. The license module's `swap_token` is a pure in-memory replace plus a plugin-registry invalidation; nothing about the auth, audit, or federation state is touched.

## Limitations

- Pubkey rotation (i.e. swapping the public key the verifier compares against, not just the license JWT) still requires a container rebuild. The pubkey is baked into the image at build time so it participates in the cosign attestation; rotating it is part of the next image release. The 90-day cycle exercises the JWT path only.
- The hot-swap does not propagate to peer Mastios in a federation. Each Mastio holds its own license and rotates it independently. Federation peering does not exchange license JWTs.
