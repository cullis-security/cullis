---
title: "Vault as Org CA private key store"
description: "Move the Mastio Org CA root key out of the local database and into HashiCorp Vault KV v2. Step-by-step migration for an existing deploy and zero-day setup for a new one."
category: "Operate"
order: 16
updated: "2026-05-14"
---

# Vault as Org CA private key store

The Mastio Org CA is the trust root of your org: it signs every agent
certificate and every Connector user certificate. By default it lives
as plaintext PEM in the local proxy database (the
`proxy_config.org_ca_key` row). That is fine for a single-operator
sandbox, but in a regulated production deploy you usually want the
private key inside an audited secret store with fine-grained ACL,
auto-unseal, and out-of-band backup. This page is how to get there.

## When to use this

| Setup | Use case |
|-------|----------|
| Local DB (default) | Sandbox, dev workstation, single-operator pilots |
| HashiCorp Vault KV v2 | Production with on-call rotations, regulated deploys (DORA, AI Act high-risk, ISO 42001) |
| Cloud KMS (AWS / Azure / GCP) | Enterprise plugin, separate operator guide |

If you also want Vault to auto-unseal at boot without manual key
shares, pair this page with [Vault auto-unseal](/docs/operate/vault-auto-unseal/).
The two changes are independent: you can adopt either one first.

## How the Vault backend works

```
+--------------------+        HTTPS + token       +-----------------+
|  Mastio container  | --------------------------> |  Vault KV v2    |
|                    |                             |                 |
|  agent_manager     |  GET  /v1/<path>            |  key_pem        |
|    .load_org_ca()  | <---------- 200 ---------- |  cert_pem       |
|                    |                             |                 |
|  agent_manager     |  POST /v1/<path>            |                 |
|    .store_org_ca() | ----------- CAS ----------> |                 |
+--------------------+                             +-----------------+
```

The provider lives at `mcp_proxy.kms.vault.VaultKMSProvider` (in-tree,
open-core). Activation is one env var: `MCP_PROXY_KMS_BACKEND=vault`.
The factory at `mcp_proxy.kms.factory.get_kms_provider` resolves
`vault` directly, ahead of the enterprise-plugin registry that
handles cloud KMS backends.

The Org CA key never leaves Vault except into the Mastio process
memory at first read, where it stays cached for the lifetime of the
process. Every signing operation (CSR signing for a new agent, user
cert reissue) uses that in-memory copy. A Mastio restart re-fetches.

## Vault path layout

Default path: `secret/data/cullis-mastio/org-ca`

Fields inside the secret:

```json
{
  "key_pem": "-----BEGIN PRIVATE KEY-----\n...",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

Override the path with `MCP_PROXY_VAULT_ORG_CA_PATH`. Operators with
policy constraints on path layout typically use something like
`secret/data/orgs/<org-id>/mastio/ca` so a single Vault policy can
cover both tool secrets (`secret/data/mcp-proxy/tools/*`) and Org CA
under one wildcard.

## Prerequisites

1. **A reachable Vault**: HTTPS, with a token that has at least
   `read` and `update` on the configured path.
2. **Vault settings already wired** into your Mastio proxy.env or
   dashboard `/proxy/vault` page: `MCP_PROXY_VAULT_ADDR`,
   `MCP_PROXY_VAULT_TOKEN`. If you also want to pin a custom CA bundle,
   set `MCP_PROXY_VAULT_CA_CERT_PATH`.
3. **A Mastio at v0.4.2 or newer**: the `VaultKMSProvider` shipped in
   PR #684 (mastio-v0.5.0 at the earliest tag carrying it; verify with
   `cullis-proxy --version`).
4. **The migration CLI**: shipped in PR #685, same release as the
   provider.

## Minimal Vault policy

Create a policy scoped to the Org CA path:

```hcl
path "secret/data/cullis-mastio/org-ca" {
  capabilities = ["read", "update"]
}

path "secret/metadata/cullis-mastio/org-ca" {
  capabilities = ["read"]
}
```

The `metadata` capability is needed for the CAS read that
`store_org_ca` does before every write. If you skip it, writes still
work but you lose the merge-with-prior-fields property and any
operator-set metadata under the same path gets clobbered.

Attach the policy to an AppRole, a Kubernetes auth role, or (for a
quick pilot) a periodic token.

## Scenario 1: new deploy, day zero

If you are bringing up a Mastio for the first time and want Vault as
the Org CA store from the start, set the env vars before first boot:

```bash
# proxy.env
MCP_PROXY_KMS_BACKEND=vault
MCP_PROXY_VAULT_ADDR=https://vault.your-org.internal:8200
MCP_PROXY_VAULT_TOKEN=hvs.CAESIG...
# Optional: pin the CA bundle if Vault uses an internal CA.
MCP_PROXY_VAULT_CA_CERT_PATH=/run/secrets/vault-ca.pem
```

Boot the Mastio. On first start `load_org_ca` returns `None` (the
Vault path is empty), `agent_manager.generate_org_ca` mints a fresh
EC P-256 keypair, and `store_org_ca` writes it to Vault. From that
moment on the trust root lives in Vault only; the local DB never
sees the key.

Verify:

```bash
vault kv get secret/cullis-mastio/org-ca | head
```

You should see `key_pem` + `cert_pem`. The Mastio logs include a line
of the form `KMS provider: vault (path=secret/data/cullis-mastio/org-ca)`.

## Scenario 2: existing deploy, migrate from local DB

This is the path for most v0.x customers. You already have an Org
CA in `proxy_config`; you want to move it to Vault without losing
the trust root.

### 1. Pre-flight

Make sure the Mastio is healthy and the Org CA actually lives in the
DB (it should, unless you wiped `proxy_config`):

```bash
docker compose exec mcp-proxy sqlite3 /var/lib/mcp_proxy/mcp_proxy.db \
  "SELECT length(value) FROM proxy_config WHERE key='org_ca_key';"
```

You should see a positive integer (length in bytes of the PEM).

Make sure your Vault settings reach the Mastio container:

```bash
docker compose exec mcp-proxy printenv MCP_PROXY_VAULT_ADDR MCP_PROXY_VAULT_TOKEN
```

If either is empty, set them in `proxy.env` and restart the container
before continuing.

### 2. Dry-run the migration

```bash
docker compose exec mcp-proxy cullis-proxy migrate-org-ca-to-vault --dry-run --yes
```

This validates: the DB has the keys, Vault is reachable, the target
path is empty (or `--force` would be needed). No writes happen. Read
the output carefully. If it complains about missing settings, fix
them first.

### 3. Run the migration with verification, without clearing the DB

```bash
docker compose exec mcp-proxy cullis-proxy migrate-org-ca-to-vault --yes
```

This step writes the Org CA to Vault and verifies by read-back. It
does **not** clear the DB row. You now have the key in both places.
That is intentional: it gives you a window to verify Vault is
correctly serving the key before you make Vault the only source of
truth.

Spot-check Vault directly:

```bash
vault kv get -format=json secret/cullis-mastio/org-ca \
  | jq -r '.data.data.cert_pem' \
  | openssl x509 -noout -subject -issuer -dates
```

The subject should be `CN=Cullis Org CA, O=<your org id>` and the
dates should match the cert you have been using. If the cert reads
correctly, Vault has the right data.

### 4. Cut over

Edit `proxy.env`:

```bash
MCP_PROXY_KMS_BACKEND=vault
```

Restart the Mastio:

```bash
./deploy.sh --pull
```

Watch the logs for `KMS provider: vault`. Issue a Connector enrollment
or trigger a cert reissue to confirm signing still works.

### 5. Clear the DB (optional but recommended)

Once you are satisfied Vault is serving the key correctly in
production, run the migration once more with `--clear-db`:

```bash
docker compose exec mcp-proxy cullis-proxy migrate-org-ca-to-vault \
  --yes --force --clear-db
```

`--force` is needed here because Vault already holds the key (the
CLI refuses to overwrite without it). The `--clear-db` flag empties
`proxy_config.org_ca_key` and `org_ca_cert` only after a successful
write + read-back verification. If anything goes wrong, the DB rows
are preserved so you can roll back.

After this step the trust root lives in Vault only. A `pg_dump` or
DB snapshot of the Mastio no longer carries the private key.

## Rollback path

If something goes wrong after Step 4 (Vault is unreachable, the
wrong token was wired, etc.), flip back:

```bash
# proxy.env
MCP_PROXY_KMS_BACKEND=local
```

Restart. As long as you did **not** run Step 5 (`--clear-db`), the
DB still holds the original Org CA and the Mastio resumes signing
from there. Investigate the Vault issue offline before retrying.

If you already ran Step 5 and need to roll back, you can re-seed the
DB by running the migration in reverse (a `migrate-org-ca-from-vault`
CLI will land as a follow-up; for now the recipe is `vault kv get` +
`UPDATE proxy_config`, handled manually by an operator with DB
access).

## Threat-model delta

| Surface | Local DB mode | Vault mode |
|---------|---------------|------------|
| Org CA in proxy DB | Plaintext PEM | Empty (after `--clear-db`) |
| Org CA in DB backup | Plaintext leak | Backup carries no key material |
| Org CA in Vault | N/A | TLS in transit, sealed at rest, audited reads |
| Operator with Postgres read | Full trust root | No path to the Org CA without the Vault token |
| Operator with Vault token | N/A | Full trust root (audited in Vault) |

Net: the operator population that can access the Org CA shrinks from
"anyone with DB read or backup access" to "anyone with the Vault
token", which in well-run deploys is the ops team only and is
audited per request.

## What is out of scope here

- **Cloud KMS providers** (AWS KMS, Azure Key Vault, GCP Cloud KMS):
  enterprise plugins, separate ADR + operator pages.
- **Sign-only HSM mode** (the key never leaves the device): Phase 2
  of the `KMSProvider` protocol, requires an API extension.
- **Token rotation** via AppRole / Kubernetes auth: separate ADR.
  For now you set `MCP_PROXY_VAULT_TOKEN` once via the dashboard
  `/proxy/vault` page or your secret-injection layer.
- **Auto-rotation of the Org CA itself**: out of scope of ADR-031.
  Rotation today is operator-driven via the existing cert rotation
  endpoints.

## Related

- [ADR-031: Vault as Org CA private key store](https://github.com/cullis-security/cullis/blob/main/docs/adrs/adr-031-vault-org-ca-kms-provider.md)
- [Vault auto-unseal](/docs/operate/vault-auto-unseal/)
- [Rotating keys](/docs/operate/rotate-keys/)
