---
title: "Onboarding an org with SPIFFE/SPIRE"
description: "Short-lived SPIFFE SVIDs for Cullis agents, as an alternative to BYOCA long-lived certs."
category: "Identity"
order: 30
updated: "2026-04-15"
---

# Cullis — Onboarding an org with SPIFFE/SPIRE

This guide is for org operators who want their Cullis agents to authenticate via short-lived SVIDs issued by SPIRE, instead of long-lived BYOCA agent certificates. Both models coexist in the same broker and even in the same org.

If you're starting from scratch and your agents don't use SPIFFE, see the regular [Operations Runbook](operations-runbook.md) and quickstart — you don't need any of this.

---

## When to use SPIFFE mode

Use SPIFFE when one of the following holds:

- You already run SPIRE (or are planning to) as your workload identity fabric — you want Cullis to trust the same identities your other services do.
- Your agents live in short-lived containers (Kubernetes pods, autoscaling workers) where rotating long-lived certs is painful.
- You want automatic cert rotation (typical SVID TTL: ~1 hour) without manual API calls to the broker.

Stay on classic BYOCA (CN/O-based certs) when agents are long-lived, externally issued, and their operators prefer manual rotation with certificate thumbprint pinning as a stronger anti-Rogue-CA control.

---

## Threat model — read this before you deploy

Moving to SPIFFE changes what the broker enforces. You should be deliberate about it:

- **The Org CA stops being the signing oracle.** It becomes an offline trust anchor. Your SPIRE server holds a short-lived intermediate signed by the Org CA, and SVIDs are minted under that intermediate. If your SPIRE server is compromised, an attacker can mint SVIDs until the intermediate rotates or is revoked.
- **Thumbprint pinning is disabled** for SPIFFE-mode logins. Pinning assumes a cert is stable across logins — SVIDs change every hour, so pinning would break auth. Identity in SPIFFE mode is bound by the chain walk + SPIFFE URI match, and ultimately by SPIRE's workload attestation (which Cullis delegates to).
- **Org CA pathLenConstraint must be ≤ 1.** The broker rejects onboarding of an Org CA with `pathLen > 1` when a trust_domain is declared. One intermediate only.
- **One trust_domain per org_id.** If you need two SPIRE clusters under the same logical org, register two separate org_ids on the broker.

If this trade is not acceptable to your threat model, do not enable SPIFFE mode for that org — stay on classic BYOCA.

---

## Prerequisites

- An Org CA (root of trust for your SPIFFE trust domain). Keep the private key offline or in an HSM. Issue it with `BasicConstraints: CA=true, pathLen=1`.
- SPIRE server configured with your Org CA as `UpstreamAuthority`. Any SPIRE topology works — single server, HA pair, multiple SPIRE servers across regions — as long as they all chain back to the same Org CA.
- A Cullis broker (shared or self-hosted) and a Cullis proxy in your org.
- `trust_domain` chosen — conventionally a reverse DNS under your control, e.g. `acme.com` or `payments.acme.internal`. Must be unique across all orgs on that broker.

---

## Step 1 — register the org with a trust_domain

The broker admin generates an invite token for you (same flow as classic onboarding):

```bash
curl -X POST https://broker/v1/admin/invites \
  -H "x-admin-secret: $ADMIN_SECRET" \
  -H "content-type: application/json" \
  -d '{"label": "acme onboarding", "ttl_hours": 24}'
```

Response contains the `token`. You (the org) submit your join request including `trust_domain`:

```bash
curl -X POST https://broker/v1/onboarding/join \
  -H "content-type: application/json" \
  -d '{
    "org_id": "acme",
    "display_name": "Acme Corp",
    "secret": "<choose a long random secret>",
    "contact_email": "sec@acme.com",
    "ca_certificate": "-----BEGIN CERTIFICATE-----\n...Org CA PEM...\n-----END CERTIFICATE-----",
    "invite_token": "<token from admin>",
    "trust_domain": "acme.com"
  }'
```

The broker validates:
- `trust_domain` is syntactically valid and not already claimed by another org
- Org CA has `BasicConstraints: CA=true` and key size ≥ 2048 (RSA) or a recognised curve (EC)
- Org CA `pathLenConstraint ≤ 1` (SPIFFE-specific check)

A 400 on pathLen means your CA was issued too permissively. Fix the CA and re-register. Do not accept a broker-side waiver — you'd be widening the trust surface silently.

The org starts in `pending`. The broker admin approves it via `POST /v1/admin/orgs/{org_id}/approve`.

### Alternative: attach-ca for a pre-provisioned org

If the broker admin created your org ahead of time (no CA yet) and issued an `attach-ca` invite, the flow is symmetric:

```bash
curl -X POST https://broker/v1/onboarding/attach \
  -H "content-type: application/json" \
  -d '{
    "ca_certificate": "...PEM...",
    "invite_token": "<attach-ca token>",
    "secret": "<proxy-chosen secret>",
    "trust_domain": "acme.com"
  }'
```

Same pathLen rule applies.

---

## Step 2 — configure SPIRE

Set your Org CA as SPIRE's UpstreamAuthority (minimal example, adapt to your topology):

```hcl
UpstreamAuthority "disk" {
    plugin_data {
        cert_file_path = "/etc/spire/org-ca.pem"
        key_file_path  = "/etc/spire/org-ca-key.pem"
    }
}
```

Create a registration entry for each workload:

```bash
spire-server entry create \
  -spiffeID spiffe://acme.com/workload/sales-agent \
  -parentID spiffe://acme.com/spire/agent/x509pop/... \
  -selector unix:uid:1000
```

The SPIFFE ID's path last segment becomes the Cullis agent name. For the entry above, the broker will derive `agent_id = "acme::sales-agent"`.

---

## Step 3 — register the agent on the Mastio

Before an agent can log in, it must exist in Cullis's registry with an approved binding. ADR-010 made the Mastio (proxy) authoritative for its own agents: you register the agent via the proxy's admin API with ``federated=true``, and the federation publisher propagates it to the Court so cross-org bindings can be approved.

```bash
# Create the agent record on your Mastio (federated=true exposes it to the Court)
curl -X POST https://proxy/v1/admin/agents \
  -H "x-admin-secret: $PROXY_ADMIN_SECRET" \
  -H "content-type: application/json" \
  -d '{
    "agent_name":   "sales-agent",
    "display_name": "Sales agent",
    "capabilities": ["quote.read", "quote.write"],
    "federated":    true
  }'

# After a few seconds, create + approve the binding on the Court
curl -X POST https://broker/v1/registry/bindings \
  -H "x-org-id: acme" -H "x-org-secret: $ORG_SECRET" \
  -H "content-type: application/json" \
  -d '{"org_id": "acme", "agent_id": "acme::sales-agent", "scope": ["quote.read", "quote.write"]}'

# Approve (same org = self-approval)
curl -X POST https://broker/v1/registry/bindings/<id>/approve \
  -H "x-org-id: acme" -H "x-org-secret: $ORG_SECRET"
```

Agent registrations are per-workload. You run these calls once per SPIFFE ID you want Cullis to accept.

---

## Step 4 — authenticate from the workload

Install the SDK with the SPIFFE extra (`pip install 'cullis[spiffe]'`) and use:

```python
from cullis_sdk import CullisClient

client = CullisClient.from_spiffe_workload_api(
    "https://broker.example.com",
    org_id="acme",
    socket_path="/run/spire/sockets/agent.sock",  # or SPIFFE_ENDPOINT_SOCKET env var
)

# client.token is now a DPoP-bound JWT — use normally.
```

The SDK fetches the SVID + full cert_chain + trust bundle from the Workload API, builds a client assertion with `x5c = [leaf, intermediate]`, and posts to `/v1/auth/token`. The broker walks the chain back to your Org CA, resolves the org by trust_domain, maps the last SPIFFE path segment to `agent_id`, and issues the token.

Rotation is automatic — SPIRE hands the SDK a fresh SVID before the old one expires. No thumbprint drift is logged because pinning is off in SPIFFE mode.

---

## Step 5 — validate end-to-end

From the workload host, confirm the whole chain works:

```bash
# Optionally inspect the SVID
spire-agent api fetch x509 \
  -socketPath /run/spire/sockets/agent.sock

# Smoke test in Python
python -c "
from cullis_sdk import CullisClient
c = CullisClient.from_spiffe_workload_api(
    'https://broker.example.com', org_id='acme',
)
print('token_prefix:', c.token[:24])
"
```

On the broker, check audit:

```
GET /v1/admin/audit/export?org_id=acme&event_type=auth.token_issued
```

You should see `agent.id=acme::sales-agent`, with chain length 2 in the span attributes (`auth.x509_chain_verify.chain.length`).

---

## Operational notes

### Mixed mode inside the same org

An agent either authenticates with a classic CN/O cert (pinning on) or with an SVID (pinning off). Both can coexist under the same `org_id` — the broker discriminates per-cert, not per-org. The `trust_domain` on the org just enables the SVID path; it doesn't disable the classic path for agents that don't present SVIDs.

### Multiple proxies in the same trust_domain

N proxies can share the same `trust_domain` as long as every SPIRE instance chains to the same Org CA. The broker accepts any SVID whose chain terminates at the registered Org CA, regardless of which intermediate signed it. HA, multi-region, site isolation — all work naturally.

### Name Constraints (recommended, not enforced)

If you can, issue your Org CA with a `nameConstraints` extension limiting the acceptable SPIFFE URIs to your own trust_domain:

```
permittedSubtrees: URI:.acme.com
```

The broker doesn't currently verify `nameConstraints` programmatically, but openssl / browsers do — and any third-party auditor of your CA will expect it. It's defence-in-depth against SPIRE-side misconfiguration that would otherwise let the intermediate mint SVIDs under an unrelated trust_domain.

### Rotating the Org CA

Since the Org CA is the trust anchor, rotating it is coordinated:
1. Issue a new Org CA, pathLen=1.
2. Configure SPIRE to use both old and new as UpstreamAuthority during the overlap.
3. Register the new CA on the broker using `POST /v1/registry/orgs/{org_id}/certificate` (classic rotate — does not consume an invite).
4. Once all workloads have rotated SVIDs under the new intermediate, decommission the old CA.

Workloads don't need to reconnect — SPIRE rotation + SDK re-auth handles it within an SVID TTL.

### Revoking a single workload

SPIRE-native: delete the registration entry (`spire-server entry delete`). The workload loses its SVID within one rotation cycle.
Cullis-native: `POST /v1/admin/certs/revoke` with the SVID's serial_hex for immediate effect at the broker (useful if SPIRE rotation is slow or compromised).

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `No organization registered for trust domain 'X'` | `trust_domain` not declared on `/onboarding/join`, or you registered with a different value. Check the `organizations.trust_domain` DB column. |
| `CA pathLenConstraint is 2 — … pathLen must be ≤ 1` | Your Org CA is too permissive. Re-issue with `pathLen=1` and re-register via attach-ca. |
| `certificate chain broken at position 0 — signature not produced by the next cert in the chain` | x5c ordering wrong (leaf first, intermediates after, trust anchor never), or the SDK is sending only the leaf. Verify `len(x5c) >= 2` in SPIFFE mode. |
| `Agent not found or org mismatch` | The agent_id derived from the SVID last path segment isn't registered on the broker. Follow Step 3. |
| `certificate chain contains a duplicate entry` | Your SDK is appending the Org CA to x5c (broker strips a trailing match, but mid-chain duplicates are an error). Fix the SDK to never include the trust anchor. |

---

## References

- ADR-003 — SPIRE 3-level PKI for SPIFFE-mode agents (internal)
- RFC 7515 §4.1.6 — x5c header semantics
- SPIFFE standards — https://github.com/spiffe/spiffe/tree/main/standards
- SPIRE UpstreamAuthority — https://github.com/spiffe/spire/blob/main/doc/plugin_server_upstreamauthority_disk.md
