---
title: "Vault auto-unseal"
description: "Configure HashiCorp Vault to auto-unseal at boot using AWS KMS, Azure Key Vault, or GCP Cloud KMS — production setup for teams with on-call rotations and disaster recovery requirements."
category: "Operate"
order: 15
updated: "2026-05-13"
---

# Vault auto-unseal with cloud KMS

The default `vault/init-vault.sh` configures Vault with Shamir 5-of-3
manual unseal. That works for a single operator on a workstation. In
production with on-call rotations, a Vault restart at 3 a.m. should
not require five people to type their key shares.

Vault auto-unseal solves this. The cloud KMS holds the master key
inside its hardware security module, Vault retrieves it on boot, and
the only thing your team holds offline are the recovery keys, used
for emergency operations and never for daily unseal.

## When to use this

| Setup | Use case |
|-------|----------|
| Shamir manual (default) | Single operator, dev workstation, sandbox demos |
| Auto-unseal AWS KMS | Production on AWS, on-call rotation, multi-AZ |
| Auto-unseal Azure Key Vault | Production on Azure |
| Auto-unseal GCP CKMS | Production on GCP |
| Auto-unseal Transit | Production on-prem with a separate hardened Vault cluster |

For a regulated deployment (DORA, NIS2, AI Act high-risk), auto-unseal
is effectively required. Manual unseal procedures do not meet the
operational continuity expectations of a Tier-1 ICT service.

## How auto-unseal works

The cloud KMS becomes the custodian of Vault's master key. On every
boot:

1. Vault contacts the KMS endpoint with its configured credentials.
2. KMS decrypts the wrapped master key.
3. Vault uses the master key to derive the encryption key for the
   storage backend.
4. Vault transitions to unsealed state. No human input.

Two key sets coexist:

- **Master key**: wrapped by KMS. Never leaves the KMS HSM in
  plaintext. Used at every boot.
- **Recovery keys**: 5 shares, threshold 3. Held offline by your
  operators. Used **only** for emergency operations: regenerating the
  root token, rotating the recovery key set itself, and (rarely)
  recovering from a corrupt KMS configuration.

You still split recovery keys across operators. You just stop using
them on every restart.

## AWS KMS

### 1. Create the KMS key

```bash
aws kms create-key \
  --description "Cullis Mastio Vault auto-unseal" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --tags TagKey=Component,TagValue=cullis-mastio \
         TagKey=Purpose,TagValue=vault-auto-unseal
```

Note the `KeyId` from the output (`arn:aws:kms:region:account:key/...`).

Enable rotation if your policy requires it:

```bash
aws kms enable-key-rotation --key-id <key-id>
```

### 2. IAM role for the Vault container

Vault needs three KMS actions on this key only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:region:account:key/<key-id>"
    }
  ]
}
```

Attach to an IAM role assumed by the Vault container (preferred), or
to an IAM user whose access key you inject via environment.

### 3. Configure Vault

In `vault.hcl`:

```hcl
seal "awskms" {
  region     = "eu-west-1"
  kms_key_id = "arn:aws:kms:eu-west-1:123456789012:key/abcd-..."
}

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = false
  tls_cert_file = "/etc/vault/tls/cert.pem"
  tls_key_file  = "/etc/vault/tls/key.pem"
}

api_addr = "https://vault.your-org.internal:8200"
ui = true
```

If you use IAM role credentials (recommended), no `access_key` or
`secret_key` in the seal block. Vault picks them up from the instance
metadata service, ECS task role, or EKS service account.

For static credentials (not recommended in production):

```hcl
seal "awskms" {
  region     = "eu-west-1"
  kms_key_id = "..."
  access_key = "AKIA..."
  secret_key = "..."
}
```

Prefer environment variables to inline secrets: `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_REGION`.

### 4. Initialize Vault

This is a one-time bootstrap. Note the syntax changes from manual
mode: `-recovery-shares` and `-recovery-threshold` replace
`-key-shares` and `-key-threshold`.

```bash
vault operator init \
  -recovery-shares=5 \
  -recovery-threshold=3 \
  -format=json > vault-recovery-keys.json
```

Store `vault-recovery-keys.json` offline. Distribute the 5 shares to
5 different operators with 3-of-5 quorum needed to authorize
recovery operations.

`chmod 600 vault-recovery-keys.json` and consider GPG-encrypting each
share separately before distribution.

### 5. Verify

```bash
vault status
```

You should see:

```
Recovery Seal Type    awskms
Initialized           true
Sealed                false
```

Note `Recovery Seal Type` (not `Seal Type`) and `Sealed: false`
without any manual unseal command. That confirms KMS unsealed Vault
at boot.

## Azure Key Vault

### 1. Create the Key Vault and key

```bash
az keyvault create \
  --name cullis-mastio-vault \
  --resource-group cullis-prod \
  --location westeurope \
  --enable-rbac-authorization false

az keyvault key create \
  --vault-name cullis-mastio-vault \
  --name vault-unseal-key \
  --kty RSA \
  --size 2048 \
  --ops wrapKey unwrapKey
```

### 2. Service principal

```bash
az ad sp create-for-rbac --name cullis-vault-sp --skip-assignment

az keyvault set-policy \
  --name cullis-mastio-vault \
  --spn <appId> \
  --key-permissions get wrapKey unwrapKey
```

Save `appId`, `password` (client secret), and `tenant` from the
create-for-rbac output.

### 3. Configure Vault

```hcl
seal "azurekeyvault" {
  tenant_id     = "<tenant-uuid>"
  client_id     = "<app-id>"
  client_secret = "<password>"
  vault_name    = "cullis-mastio-vault"
  key_name      = "vault-unseal-key"
}
```

Prefer environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
`AZURE_CLIENT_SECRET`.

If running in AKS or Azure VM with managed identity, omit credentials
and Vault uses the assigned identity.

### 4. Initialize and verify

```bash
vault operator init -recovery-shares=5 -recovery-threshold=3 \
  -format=json > vault-recovery-keys.json

vault status
# Recovery Seal Type    azurekeyvault
# Initialized           true
# Sealed                false
```

## GCP Cloud KMS

### 1. Create the key

```bash
gcloud kms keyrings create cullis-mastio \
  --location europe-west1

gcloud kms keys create vault-unseal-key \
  --location europe-west1 \
  --keyring cullis-mastio \
  --purpose encryption
```

### 2. Service account

```bash
gcloud iam service-accounts create cullis-vault-unseal \
  --display-name "Cullis Mastio Vault auto-unseal"

gcloud kms keys add-iam-policy-binding vault-unseal-key \
  --location europe-west1 \
  --keyring cullis-mastio \
  --member serviceAccount:cullis-vault-unseal@PROJECT.iam.gserviceaccount.com \
  --role roles/cloudkms.cryptoKeyEncrypterDecrypter

gcloud iam service-accounts keys create vault-sa-key.json \
  --iam-account cullis-vault-unseal@PROJECT.iam.gserviceaccount.com
```

### 3. Configure Vault

```hcl
seal "gcpckms" {
  project     = "your-project"
  region      = "europe-west1"
  key_ring    = "cullis-mastio"
  crypto_key  = "vault-unseal-key"
  credentials = "/etc/vault/gcp-sa-key.json"
}
```

If running in GKE Workload Identity, omit `credentials` and Vault
uses the bound service account.

### 4. Initialize and verify

```bash
vault operator init -recovery-shares=5 -recovery-threshold=3 \
  -format=json > vault-recovery-keys.json

vault status
# Recovery Seal Type    gcpckms
```

## Migrate an existing Shamir-sealed Vault to auto-unseal

If you started with `./vault/init-vault.sh` (Shamir manual) and want
to migrate, Vault supports an in-place seal migration without losing
data.

### 1. Add the seal block

Edit `vault.hcl` and **add** a `seal` block for your KMS provider
without removing the existing storage. Restart Vault. It will detect
both seal types and refuse to start without `-config` migration mode.

### 2. Run migration

Set the migration flag and restart:

```bash
VAULT_SEAL_MIGRATION=true vault server -config=vault.hcl
```

In another terminal, unseal Vault with your **Shamir keys** (this is
the last time). Vault will then automatically re-wrap the master key
with the new KMS and switch to auto-unseal mode:

```bash
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>
```

You will see logs indicating the migration completed.

### 3. Rotate to recovery keys

After migration, your Shamir keys still work but are deprecated.
Regenerate as recovery keys:

```bash
vault operator generate-root -init -recovery-token
# ... follow prompts using recovery keys
```

The new recovery keys replace the Shamir set entirely. Securely
destroy the old `vault-keys.json` and distribute the new recovery
shares.

### 4. Verify

```bash
vault status
# Recovery Seal Type    awskms   (or azurekeyvault, gcpckms)
# Migration             false
```

## Operational implications

### KMS access is required at every boot

If KMS becomes unreachable (network outage, IAM revoke, KMS key
deleted), Vault cannot unseal. Plan for this:

- Multi-region KMS replication where the provider supports it
  (AWS KMS multi-region keys, Azure replicated vaults)
- KMS read access alerting
- Document the manual recovery path using recovery keys

### Recovery keys are still important

Auto-unseal removes the daily burden, not the security model. Keep
recovery keys offline, distributed, audited. Use them only for:

- Generating a new root token (`vault operator generate-root`)
- Rotating the recovery key set (`vault operator rekey -target=recovery`)
- Emergency recovery from KMS misconfiguration

Annual recovery key rotation is a reasonable cadence.

### Disaster recovery scenarios

| Failure | Auto-unseal still works? | Recovery |
|---------|--------------------------|----------|
| Vault node crash | Yes, KMS unseals on restart | None needed |
| Vault storage corruption | Yes, but data is gone | Restore from snapshot, KMS unseals |
| KMS key deleted | No | Recovery keys cannot re-create the master key; data is unrecoverable |
| IAM role revoked | No | Restore IAM, restart Vault |
| Cloud region outage | Depends on KMS replication | Failover to replica region |

Pin your DR plan: never delete the KMS key without verified backup of
the storage layer **and** intent to start fresh.

### Audit log

Vault logs every seal/unseal operation. Forward to your SIEM or
Loki. Critical events:

- `seal init successful` (during migration)
- `core: seal configuration missing, but cluster is initialized` (KMS
  unreachable or misconfigured)
- `core: vault is unsealed`

## Troubleshooting

### Vault refuses to start with "stored unseal keys supported"

Likely cause: you added a `seal` block but Vault was initialized in
Shamir mode. Either run the migration (above) or re-initialize
(destroys data).

### Vault sealed: true after restart with KMS configured

Likely cause: KMS credentials missing or expired. Check:

```bash
# AWS
aws sts get-caller-identity

# Azure
az account show

# GCP
gcloud auth list
```

Then verify the KMS key is accessible:

```bash
# AWS
aws kms describe-key --key-id <key-id>

# Azure
az keyvault key show --vault-name <vault> --name <key>

# GCP
gcloud kms keys describe vault-unseal-key \
  --location europe-west1 --keyring cullis-mastio
```

### Recovery shares lost or compromised

Use the remaining 3-of-5 to rotate:

```bash
vault operator rekey -init -recovery-key -recovery-shares=5 -recovery-threshold=3
# ... follow prompts
```

If you have fewer than 3 shares, recovery is not possible. The KMS
seal still works for daily unsealing, but you cannot generate a new
root token or rotate. Treat this as a P1 incident: plan a controlled
re-initialization with a new Vault cluster and migrate data via
`vault operator raft snapshot`.

### Performance impact

Auto-unseal adds one KMS round-trip at every boot. AWS KMS p99 is
~30ms in-region. Negligible for normal restarts.

## See also

- [Operations Runbook](/docs/operate/runbook) — incident response for
  a sealed-Vault production event
- [Rotate keys](/docs/operate/rotate-keys) — rotating the Mastio
  signing key (orthogonal to Vault seal)
- Upstream Vault docs:
  [Auto-unseal seal stanza](https://developer.hashicorp.com/vault/docs/configuration/seal)
