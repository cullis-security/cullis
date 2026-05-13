# ADR-031 — HashiCorp Vault as Org CA private key store

Status: Proposed - 2026-05-13
Date: 2026-05-13
Supersedes: none
Related: ADR-014 (mastio-nginx sidecar), ADR-021 (multi-user KMS), ADR-030 (bind-mount data layout)

## Context

The Mastio Org CA private key signs every agent certificate (`AgentManager._generate_agent_cert`) and every Connector user cert (ADR-021 path `sign_external_pubkey`). Today the key lives as plaintext PEM in the local SQLite/Postgres row `proxy_config.org_ca_key`. Three pressures converge:

1. **Asymmetric protection.** Migration `0032_ai_creds_at_rest_encrypt` wrapped AI provider credentials in Fernet envelopes (`enc:v1:...`). The Org CA private key, a higher-value secret because it is the trust root of the entire org, remains in cleartext alongside it. A `pg_dump`, a misplaced backup, or an accidental `cat mcp_proxy.db | grep -i pem` exposes it.

2. **Pilot CISO bloccante.** The 2026-05-11 simulated CISO panel listed "Vault auto-unseal + Org CA root protection" as one of three Phase A blockers for a pilot in a regulated EU bank or insurer. PR #673 shipped the auto-unseal operator guide; the Org CA itself still has nowhere to go.

3. **KMSProvider Protocol is dormant.** `mcp_proxy/kms/provider.py` defines a clean `KMSProvider` protocol with `load_org_ca` and `store_org_ca`. `mcp_proxy/kms/factory.py` already dispatches on `MCP_PROXY_KMS_BACKEND`. Only `LocalKMSProvider` ships; cloud KMS backends are deferred to `cullis-enterprise` plugins. HashiCorp Vault, despite being in the same open-core stack as the rest of Cullis (compose, Helm chart, dashboard `/proxy/vault` page, `mcp_proxy/tools/secrets.VaultSecretProvider`), has no Org CA implementation.

## Decisions

**A. Implement `VaultKMSProvider` in-tree, open-core.**

Vault is already shipped end-to-end (`deploy/helm/cullis/templates/vault-statefulset.yaml`, sandbox), already wired for tool secrets, and is HashiCorp-MPL-2.0 / OpenBao Apache-2.0 — no licensing conflict with FSL-1.1-Apache-2.0 Mastio. The provider lives at `mcp_proxy/kms/vault.py`. Cloud-specific KMS providers (AWS, Azure, GCP) stay enterprise.

**B. KV v2 path `secret/data/cullis-mastio/org-ca`, fields `key_pem` + `cert_pem`.**

Single secret per Mastio instance (one Mastio = one Org). The path is configurable via `MCP_PROXY_VAULT_ORG_CA_PATH` for operators with policy constraints on path layout. The default mirrors the `secret/data/mcp-proxy/tools/...` prefix used by tool secrets so a single Vault policy can cover both with a wildcard.

**C. TLS-only Vault transport.**

Refuse plaintext HTTP unless `VAULT_ALLOW_HTTP=true` is set (dev escape hatch, matches `app/kms/vault.py`). The token is the highest-value credential in the deploy; no degraded mode.

**D. Fail-fast on Vault errors at startup.**

If `MCP_PROXY_KMS_BACKEND=vault` and Vault is unreachable, `load_org_ca` raises and the Mastio aborts startup. This is symmetric with the existing `LocalKMSProvider` failure mode (DB unreachable → startup crash) and avoids silently falling back to a local cleartext path the operator did not configure.

**E. No automatic migration of existing deployments in this PR.**

`store_org_ca` writes to Vault when `MCP_PROXY_KMS_BACKEND=vault` is set. Existing customers on `local` stay on `local` until they opt in. A follow-up PR ships a CLI tool (`cullis-mastio migrate-org-ca-to-vault`) that copies `proxy_config.org_ca_key`/`org_ca_cert` to Vault and clears the DB row under operator confirmation. Out of scope here to keep the threat surface (read path) reviewable in isolation.

**F. Same `vault_addr` / `vault_token` settings reused for both tool secrets and Org CA.**

A single Vault instance with two paths (`secret/data/mcp-proxy/tools/*` for tool secrets, `secret/data/cullis-mastio/org-ca` for the CA). Operators wanting separation can run two Vault clusters and override the path; the code does not assume colocation.

## Consequences

**Positive**
- Org CA key gains the same controls as the rest of the Vault-managed surface: audit log, fine-grained ACL, key rotation, auto-unseal (PR #673 guide), backup/restore.
- The KMS provider protocol gains its second in-tree implementation, proving the abstraction works.
- Operators with existing Vault deployments adopt with one env var flip.
- One of the three CISO Phase A blockers is materially closer to closed.

**Negative**
- Adds an external dependency on Vault availability at startup. Mitigated by Vault HA pattern (3+ replicas, auto-unseal) which is already the recommendation in the deploy docs.
- Token rotation becomes an operator concern (today the `vault_token` is set once via dashboard `/proxy/vault`; future ADR will move it to AppRole or Kubernetes auth).
- Adds ~200 lines of new code and the test surface for Vault network mocking.

**Neutral**
- Telemetry: `KMS provider: vault (in-tree)` is logged at startup. No change to per-signature hot path (Org CA key is cached in memory after first `load_org_ca`).

## Out of scope

- Cloud KMS providers (AWS KMS, Azure Key Vault, GCP Cloud KMS): enterprise plugins, separate ADRs.
- Sign-only HSM mode (key never leaves device): Phase 2 of the KMSProvider protocol, requires API extension.
- Existing-customer migration tooling: follow-up PR with `cullis-mastio migrate-org-ca-to-vault`.
- Auto-rotation: ADR-031 only stores; rotation is operator-driven via the existing `/registry/agents/{id}/rotate-cert` path and a future Org CA rotation endpoint.

## Threat model delta

| Surface | Before | After |
|---|---|---|
| Org CA key on disk in DB row | Plaintext | Removed from DB (vault-mode) |
| Org CA key in DB backup | Plaintext leak | Backup carries no key material |
| Org CA key in Vault | N/A | TLS in transit, sealed at rest, audited reads |
| Operator with Postgres read access | Full Org CA compromise | No path to Org CA without Vault token |
| Operator with Vault token | N/A | Full Org CA compromise (no change vs local DB read) |
| First-boot generation | Local DB row | Vault PUT with CAS (cas=0 on first write) |

Net: shifts the blast radius from "anyone with DB read" (commonly: any backup admin, any developer with pg_dump access) to "anyone with Vault token" (commonly: ops team only, audited).

## Implementation pointers

- `mcp_proxy/kms/vault.py` — new file, `VaultKMSProvider` implementing `KMSProvider` protocol.
- `mcp_proxy/kms/factory.py` — `backend == "vault"` branch returns `VaultKMSProvider` directly (before falling through to plugin registry).
- `mcp_proxy/config.py` — new `vault_org_ca_path: str = "secret/data/cullis-mastio/org-ca"` setting.
- `tests/test_kms_vault_provider.py` — full coverage of load/store paths with `httpx.MockTransport`, including 404 first-boot, 200 hit, malformed-payload, HTTP-without-override refusal, CAS write.
- Doc update: `site/src/content/docs/operate/vault-org-ca.md` (follow-up PR, mirrors `vault-auto-unseal.md` pattern).
