---
title: "Agent enrollment — the four methods"
description: "Under ADR-011, enrollment and runtime auth are separate layers. Four ways to enroll, one runtime path (API-key + DPoP via the Mastio)."
category: "Identity"
order: 25
updated: "2026-04-18"
---

# Cullis — Agent enrollment

Under [ADR-011](../architecture) Cullis separates two concerns:

- **Enrollment** — a one-time handshake that turns whatever identity the agent already has (cert, SVID, OIDC login, admin-minted token) into a stable runtime credential.
- **Runtime auth** — the credential the agent presents on every subsequent call: an **API key + DPoP proof**, always sent to the agent's Mastio (never directly to the Court).

The four enrollment methods below are equivalent at the output layer — they all write the same three files on disk (`api-key`, `dpop.jwk`, `agent.json`) and produce the same runtime client. The difference is only in how the Mastio verifies the caller during enrollment.

---

## Which method to pick

| Method | Pick it when | Trust anchor |
|---|---|---|
| `admin` | default, programmatic agents, CI/CD | operator-held admin secret |
| `connector` | dev laptops, interactive onboarding | OIDC login via Connector Desktop |
| `byoca` | enterprise PKI already in place, air-gapped, CI with baked-in creds | operator-supplied cert signed by the Org CA |
| `spiffe` | K8s workloads under SPIRE | SVID verified against the SPIRE trust bundle |

All four are first-class. BYOCA and SPIFFE are **enrollment** primitives; runtime auth via SPIFFE/BYOCA direct login to the Court is legacy and emits deprecation headers (see [Migration from direct login](migration-from-direct-login.md)).

---

## Method 1 — admin (default)

Operator creates the agent row via the Mastio dashboard, emits an enrollment token, hands it to the runtime.

```bash
# Step 1 — dashboard: Create Agent → displays a one-shot enrollment token.
# Step 2 — runtime reads the token at first boot:
python -c "
from cullis_sdk import CullisClient
CullisClient.enroll_via_admin_token(
    'https://mastio.acme.corp',
    enrollment_token='enroll_xxx',
    persist_to='/etc/cullis/agent/',
)
"
# Step 3 — on every subsequent start:
python -c "
from cullis_sdk import CullisClient
client = CullisClient.from_api_key_file(
    'https://mastio.acme.corp',
    api_key_path='/etc/cullis/agent/api-key',
    dpop_key_path='/etc/cullis/agent/dpop.jwk',
)
client.send_oneshot('acme::target-bot', {'hello': 'world'})
"
```

---

## Method 2 — connector (interactive)

The user runs the [Connector Desktop](https://cullis.io/downloads), authenticates via OIDC against their corporate IdP (Google, Okta, Azure AD), and the Mastio admin approves the pending enrollment from the dashboard. The Connector persists credentials under `~/.cullis/identity/<org>/`.

```bash
cullis-connector enroll --site https://mastio.acme.corp
# OIDC browser flow opens — user logs in.
# Admin sees a pending enrollment in the dashboard + clicks Approve.

# SDK reads the persisted identity:
from cullis_sdk import CullisClient
client = CullisClient.from_connector()  # reads ~/.cullis/identity/
```

---

## Method 3 — BYOCA (cert + key)

The operator holds an Org-CA-signed cert + private key (typically exported from Vault, Sectigo, or an enterprise CA). The Mastio verifies the signature chain against its loaded Org CA and emits the runtime credentials.

```bash
python -c "
from cullis_sdk import CullisClient
CullisClient.enroll_via_byoca(
    'https://mastio.acme.corp',
    admin_secret='\$MASTIO_ADMIN_SECRET',
    agent_name='inventory-bot',
    cert_pem=open('agent.pem').read(),
    private_key_pem=open('agent-key.pem').read(),
    capabilities=['inventory.read', 'inventory.write'],
    persist_to='/etc/cullis/agent/',
)
"
```

A SPIFFE URI in the cert's `SubjectAlternativeName` is picked up automatically and persisted as `spiffe_id` on the `internal_agents` row.

---

## Method 4 — SPIFFE (SVID + trust bundle)

The operator has a workload running under SPIRE with an X.509-SVID. The Mastio verifies the SVID against the SPIRE trust bundle.

```bash
python -c "
from cullis_sdk import CullisClient
CullisClient.enroll_via_spiffe(
    'https://mastio.acme.corp',
    admin_secret='\$MASTIO_ADMIN_SECRET',
    agent_name='k8s-inventory',
    svid_pem=open('svid.pem').read(),
    svid_key_pem=open('svid-key.pem').read(),
    trust_bundle_pem=open('spire-bundle.pem').read(),  # optional if set on the Mastio
    capabilities=['inventory.read'],
    persist_to='/etc/cullis/agent/',
)
"
```

The SPIFFE URI SAN on the SVID is **mandatory** for this method — without it the cert is not a valid SVID and the endpoint returns 400. The URI gets pinned as `spiffe_id`, the cert material lives under `cert_pem` (SPIRE rotates the SVID; the runtime credentials stay valid because auth is API-key + DPoP, not the SVID itself).

Trust bundle resolution:

1. `body.trust_bundle_pem` (per-request override)
2. `proxy_config.spire_trust_bundle` on the Mastio (operator-configured baseline)
3. Neither → 503

---

## Runtime — one path for every method

```python
from cullis_sdk import CullisClient

client = CullisClient.from_api_key_file(
    mastio_url='https://mastio.acme.corp',
    api_key_path='/etc/cullis/agent/api-key',
    dpop_key_path='/etc/cullis/agent/dpop.jwk',
)

# Cross-org A2A message (no session — ADR-008 one-shot envelope).
client.send_oneshot('globex::fulfillment-bot', {'order_id': 'A123'})
```

No direct calls to the Court. No cert on the wire at runtime. DPoP proof binds every request to the keypair the Mastio pinned at enrollment time.

---

## Internals — what gets written where

| File | Owner | Contents | Permissions |
|---|---|---|---|
| `persist_to/api-key` | SDK / Connector | plaintext API key (shown once by server) | `0600` |
| `persist_to/dpop.jwk` | SDK / Connector | private DPoP JWK, EC P-256 | `0600` |
| `persist_to/agent.json` | SDK / Connector | `{agent_id, org_id, mastio_url}` | `0644` |

On the Mastio side the row in `internal_agents` carries `enrollment_method`, `spiffe_id` (nullable), `enrolled_at`, and `dpop_jkt` (the thumbprint the server compares each proof against).

---

## See also

- [Endpoint reference](enrollment-api-reference.md) — request / response schemas for each endpoint
- [Migration from direct login](migration-from-direct-login.md) — moving existing SPIFFE/BYOCA deployments off `/v1/auth/token`
- [SPIFFE onboarding](spiffe-onboarding.md) — deploying SPIRE alongside Cullis
