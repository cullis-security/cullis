---
title: "Enrollment API reference"
description: "Request + response schemas for /v1/admin/agents/enroll/{byoca, spiffe} and the other ADR-011 enrollment endpoints."
category: "Reference"
order: 60
updated: "2026-04-18"
---

# Cullis — Enrollment API reference

Endpoints under `/v1/admin/agents/enroll/` on the **Mastio** (never on the Court). All require `X-Admin-Secret`. Returns `201 Created` on success; API key in the response body is shown **exactly once** — the server stores only its bcrypt hash.

---

## `POST /v1/admin/agents/enroll/byoca`

Enroll an agent via a caller-supplied Org-CA-signed cert + key.

### Request

```json
{
  "agent_name": "inventory-bot",
  "display_name": "Inventory service",
  "capabilities": ["inventory.read", "inventory.write"],
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\n...",
  "dpop_jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
  "federated": false
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `agent_name` | string | yes | `^[a-zA-Z0-9._-]{1,64}$` — the Mastio scopes it to its own `org_id` |
| `display_name` | string | no | Free-form label; defaults to `agent_name` |
| `capabilities` | string[] | no | Arbitrary capability strings; empty list allowed |
| `cert_pem` | PEM | **yes** | Must chain to the Mastio's loaded Org CA |
| `private_key_pem` | PEM | **yes** | Must match `cert_pem` public key |
| `dpop_jwk` | JWK object | no | Public EC/RSA JWK. `d` (private) rejected. When supplied, the server computes RFC 7638 thumbprint and pins it |
| `federated` | bool | no | Push the agent to the Court via the federation publisher |

### Response — 201

```json
{
  "agent_id": "acme::inventory-bot",
  "display_name": "Inventory service",
  "capabilities": ["inventory.read", "inventory.write"],
  "api_key": "sk_local_inventory-bot_a1b2...",
  "cert_thumbprint": "f3d2...",
  "spiffe_id": null,
  "dpop_jkt": "uP6uY..."
}
```

If the cert carries a `spiffe://` URI in its `SubjectAlternativeName`, `spiffe_id` is populated automatically.

### Errors

| Code | When |
|---|---|
| 400 | `cert_pem` not signed by Org CA; key does not match cert; `dpop_jwk` contains `d`; unsupported `kty` |
| 403 | Missing / wrong `X-Admin-Secret` |
| 409 | Agent `<org>::<name>` already enrolled |
| 503 | Mastio's Org CA not loaded |

---

## `POST /v1/admin/agents/enroll/spiffe`

Enroll an agent via an X.509-SVID verified against a SPIRE trust bundle.

### Request

```json
{
  "agent_name": "k8s-inventory",
  "display_name": "K8s inventory workload",
  "capabilities": ["inventory.read"],
  "svid_pem": "-----BEGIN CERTIFICATE-----\n...",
  "svid_key_pem": "-----BEGIN EC PRIVATE KEY-----\n...",
  "trust_bundle_pem": "-----BEGIN CERTIFICATE-----\n...",
  "dpop_jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
  "federated": false
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `svid_pem` | PEM | **yes** | SVID leaf with a `spiffe://` URI SAN (mandatory for this method) |
| `svid_key_pem` | PEM | **yes** | Must match `svid_pem` public key |
| `trust_bundle_pem` | PEM | no | Per-request bundle override. When omitted, the Mastio falls back to `proxy_config.spire_trust_bundle` |
| `agent_name`, `display_name`, `capabilities`, `dpop_jwk`, `federated` | — | same as BYOCA |

### Response — 201

```json
{
  "agent_id": "acme::k8s-inventory",
  "display_name": "K8s inventory workload",
  "capabilities": ["inventory.read"],
  "api_key": "sk_local_k8s-inventory_c4d5...",
  "cert_thumbprint": "e7a8...",
  "spiffe_id": "spiffe://acme.internal/k8s-inventory",
  "dpop_jkt": "vL3pW..."
}
```

### Errors

| Code | When |
|---|---|
| 400 | SVID has no SPIFFE URI SAN; not signed by trust bundle; key mismatch; invalid `dpop_jwk` |
| 403 | Missing / wrong admin secret |
| 409 | Duplicate |
| 503 | Neither `trust_bundle_pem` in body nor `spire_trust_bundle` in proxy config |

---

## `POST /v1/admin/agents` — admin manual create

The pre-ADR-011 path. Still the default for programmatic agents created from scripts or CI. See existing runbooks — behavior unchanged, except the row now carries `enrollment_method='admin'` automatically.

## `POST /v1/enrollment/start` + polling — connector flow

The device-code enrollment for Connector Desktop. Unchanged; see [SPIFFE onboarding](spiffe-onboarding.md) and the Connector README. Rows get `enrollment_method='connector'`.

---

## Persistence contract (client side)

Every `enroll_via_*` helper in the Python SDK, given `persist_to=<dir>`, writes:

| File | Mode | Contents |
|---|---|---|
| `<dir>/api-key` | 0600 | plaintext API key |
| `<dir>/dpop.jwk` | 0600 | JSON `{"private_jwk": {...}}` |
| `<dir>/agent.json` | 0644 | `{"agent_id": "...", "org_id": "...", "mastio_url": "..."}` |

Runtime pass `api_key_path=<dir>/api-key` and `dpop_key_path=<dir>/dpop.jwk` to `CullisClient.from_api_key_file()`.

---

## Row shape — `internal_agents`

Columns added by migration 0016 that every enroll endpoint populates:

| Column | Value |
|---|---|
| `enrollment_method` | `admin` \| `connector` \| `byoca` \| `spiffe` |
| `spiffe_id` | SPIFFE URI when enrollment carried one, else NULL |
| `enrolled_at` | ISO timestamp of the successful enroll call |
| `dpop_jkt` | RFC 7638 thumbprint of the pinned public JWK (NULL if `dpop_jwk` was not supplied) |

The operator dashboard surfaces all of these so audit + migration progress is observable without touching SQL.
