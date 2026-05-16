# Azure Key Vault — Org CA setup

How to store the Mastio Org CA private key in Azure Key Vault instead of the
local SQLite/Postgres row. Targets customers who already operate Key Vault in
production (Azure-native shops, M365 Premier tenants, regulated workloads with
an Azure-resident key custody team).

Open-core ships two backends: `local` (default, plaintext in `proxy_config`)
and `vault` (HashiCorp Vault KV v2, ADR-031). `cullis-enterprise` adds three
cloud KMS plugins: `aws` (Secrets Manager), `azure` (Key Vault), `gcp` (Secret
Manager). This document covers `azure`.

Related: ADR-031 (Vault Org CA), `enterprise-kit/BYOCA.md` (CA onboarding).

---

## When to pick Azure Key Vault

| Backend | Pick when |
|---|---|
| `local` | Single-node dev/pilot, no shared key custody requirement |
| `vault` | You already run HashiCorp Vault or want a self-hosted KMS in your DC |
| `azure` | Azure tenant exists, key custody team uses Key Vault, you want managed-identity auth |
| `aws` / `gcp` | Equivalent for AWS Secrets Manager / GCP Secret Manager |

Switching backend is a one-time export/import (see Migration below); the cert
on disk stays the same, only the storage location changes.

## What gets stored

A single Key Vault secret containing a JSON document:

```json
{
  "key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

Default secret name: `cullis-org-ca`. One Mastio = one Org = one secret.
Key Vault appends a new version every `set_secret` call, so rotation is the
same single operation as the initial write.

## Prerequisites

- An Azure subscription with an existing or new Key Vault (Standard tier is
  enough; Premium / HSM-backed is supported but optional).
- A Cullis Mastio deploy with `cullis-enterprise` installed and the
  `cloud_kms_azure` extra (`pip install 'cullis-enterprise[cloud_kms_azure]'`
  or the equivalent enterprise container image, which ships with all KMS
  extras included).
- An Azure identity that can read and write a single secret in that vault
  (managed identity, service principal, or a developer Azure CLI session).
  See "Authentication options" below.

## 1. Provision the Key Vault

If you don't already have one:

```bash
RG=cullis-mastio-rg
LOC=westeurope
VAULT=cullis-mastio-kv-prod   # must be globally unique

az group create --name "$RG" --location "$LOC"

az keyvault create \
  --name "$VAULT" \
  --resource-group "$RG" \
  --location "$LOC" \
  --enable-rbac-authorization true \
  --enable-soft-delete true \
  --enable-purge-protection true \
  --retention-days 90
```

Soft-delete + purge protection are recommended: they prevent a compromised
or runaway control plane from permanently deleting the Org CA secret. With
purge protection on, a deleted secret can be recovered within
`--retention-days` and the vault itself cannot be purged before that window.

## 2. Authentication options

The plugin uses Azure SDK `DefaultAzureCredential`, which walks the standard
credential chain. Pick whichever fits your topology:

### Option A — Managed Identity (recommended when Mastio runs on Azure)

If Mastio runs on an Azure VM, VMSS, AKS pod, or Container App, assign a
user-assigned (or system-assigned) managed identity to the workload and
grant it Key Vault access. No secrets to manage.

```bash
# Example: system-assigned identity on an Azure VM
az vm identity assign --resource-group "$RG" --name mastio-vm

PRINCIPAL_ID=$(az vm show --resource-group "$RG" --name mastio-vm \
  --query identity.principalId -o tsv)

az role assignment create \
  --assignee "$PRINCIPAL_ID" \
  --role "Key Vault Secrets Officer" \
  --scope "$(az keyvault show --name "$VAULT" --query id -o tsv)"
```

If you want least-privilege at the secret level instead of the vault level,
use Key Vault's per-secret access policies (legacy auth model) or define a
custom role limited to a single secret name.

### Option B — Service Principal (Mastio outside Azure or air-gapped to Azure)

Create an App Registration and grant it secret get + set on the vault.

```bash
APP_NAME="Cullis Mastio Production"

# 1. Register the application
APP_ID=$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)

# 2. Create a service principal for the app
az ad sp create --id "$APP_ID"

# 3. Mint a client secret (rotate periodically)
SECRET=$(az ad app credential reset --id "$APP_ID" --query password -o tsv)

# 4. Grant secret get + set on the vault
az role assignment create \
  --assignee "$APP_ID" \
  --role "Key Vault Secrets Officer" \
  --scope "$(az keyvault show --name "$VAULT" --query id -o tsv)"

TENANT_ID=$(az account show --query tenantId -o tsv)

echo "AZURE_TENANT_ID=$TENANT_ID"
echo "AZURE_CLIENT_ID=$APP_ID"
echo "AZURE_CLIENT_SECRET=$SECRET"
```

Feed those three values into Mastio as environment variables — Azure SDK
picks them up via `EnvironmentCredential` (third link in
`DefaultAzureCredential`). Certificate credentials are also supported; see
[`azure-identity` docs](https://learn.microsoft.com/python/api/azure-identity)
for `AZURE_CLIENT_CERTIFICATE_PATH`.

If you want stricter scoping than "Key Vault Secrets Officer", a custom role
with `Microsoft.KeyVault/vaults/secrets/getSecret/action` +
`setSecret/action` on a single secret resource is sufficient. `list` is not
required by the plugin.

### Option C — Azure CLI session (development only)

`DefaultAzureCredential` falls back to the Azure CLI session of the user
running Mastio. Useful for local debugging, not for production.

## 3. Configure Mastio

Set these environment variables on the Mastio process (Helm values,
docker-compose `environment:` block, or systemd unit):

```bash
MCP_PROXY_KMS_BACKEND=azure
CULLIS_CLOUD_KMS_AZURE_VAULT_URL=https://cullis-mastio-kv-prod.vault.azure.net/
CULLIS_CLOUD_KMS_AZURE_SECRET_NAME=cullis-org-ca           # optional, this is the default
CULLIS_CLOUD_KMS_AZURE_CREATE_IF_MISSING=true              # optional, default true
```

If using a service principal (Option B), add the Azure SDK envs:

```bash
AZURE_TENANT_ID=<tenant>
AZURE_CLIENT_ID=<app id>
AZURE_CLIENT_SECRET=<client secret>
```

`CULLIS_CLOUD_KMS_AZURE_CREATE_IF_MISSING=false` is the safer setting once
the Org CA is provisioned: it makes Mastio refuse to write a fresh CA if the
expected secret has been deleted, instead of silently re-issuing a brand new
root that does not match any existing agent cert. Leave it `true` only
during initial bootstrap.

## 4. Bootstrap and verify

First Mastio boot with `MCP_PROXY_KMS_BACKEND=azure` will:

1. Call `load_org_ca` against Key Vault.
2. If the secret does not exist and `CREATE_IF_MISSING=true`, generate a
   fresh Org CA keypair and push it via `store_org_ca`.
3. Subsequent boots load the existing keypair on every restart — no DB row
   for the key, no plaintext on disk.

Confirm the secret landed:

```bash
az keyvault secret show \
  --vault-name "$VAULT" \
  --name cullis-org-ca \
  --query 'attributes.{created:created,updated:updated,version:version}'
```

You should see a non-null `created` timestamp. Do **not** dump the value to
a terminal in production — the field contains the private key in PEM form.

Mastio boot logs confirm the backend on startup:

```text
cullis_enterprise.cloud_kms_azure  INFO  cloud_kms_azure provider ready (vault=https://cullis-mastio-kv-prod.vault.azure.net/ secret=cullis-org-ca)
```

If you see this line, `MCP_PROXY_KMS_BACKEND=azure` was honoured and the
provider built without error. The first agent enroll after boot will
exercise the load path end-to-end.

## 5. Migration from another backend

There is no `migrate-org-ca-to-azure` CLI yet (the open-core
`cullis-proxy migrate-org-ca-to-vault` covers `local → vault` only). For
`local → azure` or `vault → azure`, do it manually:

1. Stop Mastio.
2. Read the current key + cert PEMs from the source:
   - `local`: `SELECT org_ca_key, org_ca_cert FROM proxy_config;`
   - `vault`: `vault kv get secret/cullis-mastio/org-ca`
3. Build the JSON payload and upload it:
   ```bash
   jq -n --arg k "$(cat org-ca-key.pem)" --arg c "$(cat org-ca-cert.pem)" \
     '{key_pem:$k, cert_pem:$c}' > payload.json

   az keyvault secret set \
     --vault-name "$VAULT" \
     --name cullis-org-ca \
     --file payload.json
   ```
4. Flip `MCP_PROXY_KMS_BACKEND=azure` (plus the URL env vars) and restart.
5. Verify with `/health/kms` and a smoke agent enroll.
6. Once stable for a release cycle, clear the source row:
   - `local`: `UPDATE proxy_config SET org_ca_key='', org_ca_cert='';`
   - `vault`: `vault kv delete secret/cullis-mastio/org-ca`

Agent certificates already issued continue to validate — the Org CA is
unchanged, only the storage moved.

## 6. Disaster recovery

The Org CA private key is the trust root for every agent and user
certificate in the org. Losing it forces re-enrollment of every agent and
re-issue of every user identity. Treat the Key Vault secret as a tier-0
asset.

**Recovery scenarios:**

- **Secret accidentally deleted.** Soft-delete (Step 1) keeps the secret
  recoverable for `--retention-days`. Restore with:
  ```bash
  az keyvault secret recover --vault-name "$VAULT" --name cullis-org-ca
  ```
- **Vault accidentally deleted.** Purge protection (Step 1) blocks
  destruction for `--retention-days`. Recover the vault, then the secret:
  ```bash
  az keyvault recover --name "$VAULT" --location "$LOC"
  ```
- **Tenant-wide loss.** Key Vault backup files (`.backup` blobs from
  `az keyvault secret backup`) restore into a vault in a different region
  or subscription. Run a quarterly `az keyvault secret backup` against the
  Org CA secret and store the backup blob in your standard tier-0 backup
  location (separate subscription, separate region, separate identity).

Cullis does not currently ship an automated backup job for this — operator
responsibility.

## 7. Operational notes

- **Latency.** `load_org_ca` runs once per Mastio boot. `store_org_ca` runs
  only on initial provisioning and explicit rotation. The Azure SDK is
  synchronous; the plugin bridges to asyncio via `asyncio.to_thread`, so
  the event loop is never blocked.
- **Cost.** Key Vault Standard tier bills per 10k operations
  (≈ €0.025 / 10k ops as of 2026-05). Mastio steady-state is one read at
  boot. Even with hourly restarts the run rate is below €0.01/month per
  Mastio. Premium / HSM-backed pricing differs.
- **Rotation.** To rotate the Org CA private key:
  1. Generate a fresh keypair off-box.
  2. Upload via `az keyvault secret set` — Key Vault stores it as a new
     version, the old version stays retrievable.
  3. Restart Mastio.
  4. Re-enroll agents (their cert chain points at the previous CA).

  In-place rotation without re-enrollment requires a cross-signed bridge
  CA and is out of scope here.
- **Audit log.** Every `get_secret` / `set_secret` is logged in Key Vault's
  diagnostic settings if you've wired them to Log Analytics or Event Hubs.
  Cullis recommends turning this on for the vault hosting the Org CA — it
  is the lowest-noise channel for "who touched the trust root and when".

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `RuntimeError: CULLIS_CLOUD_KMS_AZURE_VAULT_URL is unset` | Env var not propagated to the Mastio process. Check the deploy target's env block, not just the host shell. |
| `azure.core.exceptions.HttpResponseError: (Forbidden)` on boot | The identity Mastio runs as lacks `secrets/get` (or `secrets/set` on first boot). Check `az role assignment list --assignee <principal>` and re-grant "Key Vault Secrets Officer" or a custom role with both verbs. |
| `azure.core.exceptions.ClientAuthenticationError` | `DefaultAzureCredential` walked the entire chain and found nothing usable. For service-principal auth, confirm `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` are all set. |
| Boot logs say "Azure Key Vault secret … is not valid JSON" | Someone edited the secret in the portal and broke the payload shape. Restore from the previous version: `az keyvault secret list-versions --vault-name "$VAULT" --name cullis-org-ca`. |
| Mastio boots fine but agents fail enrollment with cert chain errors | The Key Vault secret holds an Org CA that does not match the agent cert chain on file. You probably restored an old secret version or migrated between two Mastios with different CAs. Re-issue from the correct CA or re-enroll. |

## Need help

`hello@cullis.io` for setup support during the pilot. For production-grade
support contracts see the enterprise license terms.
