---
title: "Configuration reference"
description: "Every environment variable the Mastio and Court read at boot — defaults, formats, and which ones you must set in production."
category: "Reference"
order: 30
updated: "2026-04-23"
---

# Configuration reference

**Who this is for**: an operator writing `proxy.env`, `.env`, or Helm `values.yaml` and needing the authoritative answer on what each variable does. Variables are grouped by the component that reads them.

Conventions:

- `MCP_PROXY_*` — read by the Mastio (MCP proxy)
- `CULLIS_*` — read by the SDK and, for a few shared fields, the Mastio
- Bare names (`ADMIN_SECRET`, `VAULT_TOKEN`, …) — read by the Court (legacy; migration to `CULLIS_*` or `BROKER_*` tracked)

Required variables in bold. Safe defaults mean "OK for sandbox / eval"; production-grade defaults are called out where they differ.

## Mastio

### Core identity

| Variable | Default | Purpose |
|---|---|---|
| **`MCP_PROXY_ORG_ID`** | *(none)* | The org slug this Mastio represents. Must match the `org_id` on the Court. Lowercase, no whitespace. |
| **`MCP_PROXY_PROXY_PUBLIC_URL`** | *(none)* | The URL clients and federation peers use to reach the Mastio. DPoP `htu` is derived from this — a mismatch with the caller's URL returns 401. Include scheme and port. |
| `MCP_PROXY_STANDALONE` | `false` | `true` disables federation publishing. Use for air-gapped single-org deploys. Flip to `false` later without re-enrolling agents. |

### Admin + dashboard

| Variable | Default | Purpose |
|---|---|---|
| **`MCP_PROXY_ADMIN_SECRET`** | *(none)* | The Mastio's admin secret. First-boot wizard bcrypts it into Vault; the value in the env is only consulted when the bcrypt hash is empty. |
| **`MCP_PROXY_DASHBOARD_SIGNING_KEY`** | *(none)* | HMAC key used to sign dashboard session cookies. Any 32+ bytes of entropy. Rotate to invalidate all sessions. |
| `MCP_PROXY_ALLOWED_ORIGINS` | `*` (dev) | Comma-separated origins allowed by the dashboard's CORS. **Set explicit origins in production.** |
| `MCP_PROXY_FORCE_LOCAL_PASSWORD` | `false` | Hardening: `true` disables OIDC dashboard login and forces local-password only. See local-password toggle notes. |
| `MCP_PROXY_LOCAL_AUTH_ENABLED` | `true` | Inverse of the toggle above, retained for clarity. |

### Persistence

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROXY_DATABASE_URL` | `sqlite+aiosqlite:////data/mcp_proxy.db` | Async SQLAlchemy URL. Use `postgresql+asyncpg://...` in production. |
| `MCP_PROXY_REDIS_URL` | `redis://redis:6379/0` | DPoP JTI store + cross-worker WS pub/sub. Ephemeral — no backup needed. |

### Secrets backend

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROXY_SECRET_BACKEND` | `file` | `file` (local PEMs in `/certs`) or `vault` (HashiCorp Vault KV v2). |
| `MCP_PROXY_VAULT_ADDR` | *(none)* | Vault address. HTTPS in production. |
| `MCP_PROXY_VAULT_TOKEN` | *(none)* | Vault token with access to the Mastio's KV path. Scope with a tight policy; rotate annually. |
| `MCP_PROXY_VAULT_CA_CERT_PATH` | *(none)* | Path to the CA cert trusted for Vault's TLS. Leave empty to use the system trust store. |
| `MCP_PROXY_VAULT_VERIFY_TLS` | `true` | Set to `false` **only** for dev Vault on HTTP. |

### Federation

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROXY_BROKER_JWKS_URL` | *(derived)* | Override the Court's JWKS URL. Default: `{broker_url}/.well-known/jwks.json`. |
| `MCP_PROXY_BROKER_VERIFY_TLS` | `true` | Disable **only** for a self-signed Court in dev. |
| `MCP_PROXY_FEDERATION_POLL_INTERVAL_S` | `30` | Publisher poll interval. Raise under high agent churn to reduce Court load. |
| `MCP_PROXY_FEDERATION_STATS_INTERVAL_S` | `300` | Background stats publisher. Purely observability; `-1` to disable. |
| `MCP_PROXY_INTRA_ORG_ROUTING` | `sign_only` | `sign_only` keeps intra-org A2A off the Court (ADR-001 fast path). `envelope` sends every message via the Court (legacy). |

### PKI + auth

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROXY_STRICT_PKI` | `false` | `true` refuses to boot on a legacy Org CA with `pathLen=0`. See [Apply updates § Remediate a legacy Org CA](../operate/apply-updates#worked-example--org-ca-pathlen0). |
| `MCP_PROXY_EGRESS_DPOP_MODE` | `bound` | `bound` or `none`. `none` disables DPoP on egress from the Mastio — only for legacy targets that can't verify DPoP. |
| `MCP_PROXY_PDP_URL` | *(none)* | Policy Decision Point webhook. See ADR / PDP template. |
| `CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS` | `300` | Minimum seconds between consecutive signing-key rotations. Rate-limits accidental back-to-back rotates. |

### Connector distribution

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROXY_CONNECTOR_DOWNLOAD_BASE` | `/downloads` | Path prefix for serving bundled Connector releases from the Mastio. Set to an external URL (e.g. an artifact bucket) to offload. |

## Court

The Court reads bare env var names for historical reasons — migration to `BROKER_*` / `CULLIS_*` prefixes is tracked.

| Variable | Default | Purpose |
|---|---|---|
| **`ADMIN_SECRET`** | *(none)* | Court admin secret. Same bcrypt-in-Vault pattern as the Mastio. |
| **`BROKER_PUBLIC_URL`** | *(none)* | Public URL of the Court. DPoP `htu` on Court-issued tokens derives from this. |
| **`DASHBOARD_SIGNING_KEY`** | *(none)* | 32+ bytes for Court dashboard cookie HMAC. |
| **`TRUST_DOMAIN`** | *(none)* | The Court's trust domain (e.g. `cullis.acme.com`). Orgs onboard with their own `trust_domain`, validated as a subdomain of the Court's. |
| `BROKER_CA_KEY_PATH` | `/app/certs/broker-ca-key.pem` | Where the Court's root CA key is mounted. |
| `BROKER_JWKS_URL` | *(derived)* | Override if the Court serves JWKS from a non-default path. |
| `BROKER_URL` | *(derived)* | Internal base URL for service-to-service calls inside the Court's k8s namespace. |
| `ALLOWED_ORIGINS` | `*` (dev) | Dashboard CORS. Set explicit origins in production. |
| `KMS_BACKEND` | `file` | `file` or `vault`. Same semantics as the Mastio's `MCP_PROXY_SECRET_BACKEND`. |
| `REQUIRE_SPIFFE_SAN` | `false` | `true` enforces a SPIFFE URI in every agent cert's SAN at enrollment. Recommended when running under SPIRE across all orgs. |
| `CULLIS_ALLOW_LEGACY_AUTH_LOGIN` | `true` | Temporary switch during the ADR-011 migration. Set to `false` once all orgs are on unified enrollment. See [Migration from direct login](migration-from-direct-login). |

### Vault (Court)

| Variable | Default | Purpose |
|---|---|---|
| `VAULT_ADDR` | *(none)* | Vault address. HTTPS in production. |
| `VAULT_TOKEN` | *(none)* | Scoped token; rotate annually. |
| `VAULT_CA_CERT` / `VAULT_CA_CERT_PATH` | *(none)* | PEM or path for Vault's TLS CA. |
| `VAULT_VERIFY_TLS` | `true` | Set to `false` only in dev. |
| `VAULT_ALLOW_HTTP` | `false` | `true` permits Vault over HTTP — **dev only**. |
| `VAULT_SECRET_PATH` | `secret/broker` | KV v2 path for Court material. |
| `VAULT_BOOTSTRAP_TOKEN_FIELD` | `root_token` | Field on the Vault bootstrap JSON holding the root token for first-boot PKI. |
| `VAULT_TIMEOUT` | `5` | Per-request timeout in seconds. |
| `VAULT_READ_TIMEOUT` | `10` | Read timeout for the bootstrap handshake. |

### Redis (Court)

| Variable | Default | Purpose |
|---|---|---|
| `REDIS_URL` | `redis://redis:6379/0` | Same shape as the Mastio's. Can be shared between Court and Mastios in a k8s cluster or separated. |
| `REDIS_CHANNEL_PREFIX` | `cullis` | Pub/sub channel prefix. Change to isolate two Cullis deployments on the same Redis. |
| `REDIS_TRANSIENT_ERRORS` | `ConnectionError,TimeoutError` | Comma-separated exception class names treated as transient (retry). |

## SDK

| Variable | Default | Purpose |
|---|---|---|
| `CULLIS_PROXY_URL` | *(none)* | Default Mastio URL when `CullisClient.from_api_key_file` is called without `mastio_url`. |
| `CULLIS_BROKER_URL` | *(none)* | Default Court URL when the SDK needs to talk directly. Rarely used — most flows go through the Mastio. |
| `CULLIS_ORG_ID` | *(none)* | Default org slug for SDK constructors. |
| `CULLIS_AGENT_ID` | *(none)* | Default agent id. |
| `CULLIS_API_KEY` | *(none)* | Override for `api_key_path` — useful in containers that don't persist files. |
| `CULLIS_EGRESS_DPOP_MODE` | `bound` | Same semantics as `MCP_PROXY_EGRESS_DPOP_MODE`, read SDK-side. |
| `CULLIS_DISABLE_QUEUE_OPS` | `false` | Disable inbox-poller queue operations. Used by the Connector when running in dashboard-only mode. |
| `CULLIS_EXTENSION_URI` | `cullis-trust/v1` | A2A extension URI the SDK advertises. Override only when interop-testing against a non-default registry. |

## MCP-catalog seed (sandbox)

The sandbox's MCP catalog server reads a handful of `SEED_MCP_*` variables to pre-populate demo resources. Not used in production.

| Variable | Default | Purpose |
|---|---|---|
| `SEED_MCP_CATALOG_URL` | `http://mcp-catalog:9300` | Base URL of the demo catalog MCP server. |
| `SEED_MCP_INVENTORY_URL` | `http://mcp-inventory:9301` | Base URL of the demo inventory MCP server. |

## Environment templates

Start from `.env.example` at the repo root and `deploy/proxy/proxy.env.example`. Both carry the complete variable list with commentary; this page is the authoritative definition when the two drift.

For the minimal production Mastio `.env`:

```bash
# Identity
MCP_PROXY_ORG_ID=acme
MCP_PROXY_PROXY_PUBLIC_URL=https://mastio.acme.com

# Admin
MCP_PROXY_ADMIN_SECRET=<32+ bytes of entropy>
MCP_PROXY_DASHBOARD_SIGNING_KEY=<32+ bytes of entropy>
MCP_PROXY_ALLOWED_ORIGINS=https://mastio.acme.com

# Persistence
MCP_PROXY_DATABASE_URL=postgresql+asyncpg://cullis:@postgres:5432/cullis
MCP_PROXY_REDIS_URL=redis://redis:6379/0

# Secrets
MCP_PROXY_SECRET_BACKEND=vault
MCP_PROXY_VAULT_ADDR=https://vault.acme.internal:8200
MCP_PROXY_VAULT_TOKEN=<scoped token>

# Federation (omit for standalone)
MCP_PROXY_STANDALONE=false
```

## Next

- [Self-host the Mastio](../install/mastio-self-host) — step-by-step for a production `.env`
- [Mastio on Kubernetes](../install/mastio-kubernetes) — Helm `values.yaml` equivalents
- [Rotate keys](../operate/rotate-keys) — which variables participate in key rotation
- [Migration from direct login](migration-from-direct-login) — context for `CULLIS_ALLOW_LEGACY_AUTH_LOGIN`
