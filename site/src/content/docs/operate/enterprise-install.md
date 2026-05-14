---
title: "Enterprise install"
description: "Deploy the licensed Cullis Mastio enterprise image: prerequisites, license JWT setup, feature flags, plugin envs, first-boot validation, upgrades, and troubleshooting."
category: "Operate"
order: 5
updated: "2026-05-14"
---

# Cullis Mastio Enterprise install

This page covers the operator-facing install path for the licensed
Mastio enterprise image (`ghcr.io/cullis-security/cullis-mastio-enterprise`).
It is the artefact a customer with a Cullis enterprise contract
deploys; the open-core `cullis-mastio` image follows a different
quickstart (see the
[runbook](./runbook)).

The enterprise image is feature-identical to the open-core one plus
nine paid plugins gated by an offline-signed RS256 license JWT:

| Plugin | What it adds |
|---|---|
| `audit_export_s3` | Audit log → S3 NDJSON, batched every 60s |
| `audit_export_datadog` | Audit log → Datadog Logs API |
| `saml_sso` | SAML 2.0 SP for admin login on `/proxy/login` |
| `cloud_kms_aws` | Org CA private key in AWS Secrets Manager |
| `cloud_kms_azure` | Org CA private key in Azure Key Vault |
| `cloud_kms_gcp` | Org CA private key in GCP Secret Manager |
| `rbac_multi_admin` | DB-backed multi-admin user model + 4-eyes approvals |
| `llm_guardian` | LLM firewall fast-path + slow-path judge dispatch (ADR-016) |
| `scim_2_0` | SCIM 2.0 SP for IdP-driven user + group lifecycle |

The license JWT lists which of these features the running container
is allowed to activate. Plugins without their feature in the license
are dropped from the registry at boot.

## Prerequisites

You need three things from Cullis Security at deal close:

1. **A GitHub PAT** with `read:packages` scope, scoped to
   `cullis-security/cullis-mastio-enterprise`. Without it `docker pull`
   against the private image fails.
2. **An RS256-signed license JWT** with `tier=enterprise`, your
   `org` identifier, an expiry, and the `features` array your contract
   grants. The JWT is verified offline against the pubkey baked into
   the image; no phone-home, no network call.
3. **The enterprise bundle release URL** for the `mastio-enterprise-bundle-v*`
   tag matching the image tag you want to run. Bundle and image tag
   should agree (the bundle pins the image version by default).

Plus the same prerequisites the open-core bundle needs:

- Docker 24+ with Compose v2
- A public hostname the agents will reach the Mastio at (for DPoP `htu`
  validation) and a public TLS port (default `9443`)
- For `cloud_kms_*` features: the matching cloud account + IAM identity

## Quickstart

```bash
# 1. Authenticate to the private registry (one-time per host)
echo <PAT> | docker login ghcr.io -u <github-user> --password-stdin

# 2. Pull the bundle
curl -L https://github.com/cullis-security/cullis/releases/download/mastio-enterprise-bundle-v0.3.0/cullis-mastio-enterprise-bundle.tar.gz | tar xz
cd cullis-mastio-enterprise-bundle/

# 3. Configure
cp proxy.env.example proxy.env
# Edit proxy.env (see "Required keys" below)

# 4. Deploy
./deploy.sh
```

The deploy script pre-flights two things before bringing the stack
up:

- **License JWT shape**: the value of `CULLIS_LICENSE_KEY` must match
  the JWT base64url layout `header.payload.signature`. Signature
  verification happens inside the container against the baked pubkey.
- **Registry pull**: `docker pull` of the enterprise image. Fails fast
  with a clear message if `docker login ghcr.io` has not been done.

Post-up, the script reports how many plugins loaded and the active
license tier. Expect `plugins loaded: N` matching the features in
your license (one plugin per granted feature).

## Required keys in proxy.env

Always set:

| Env var | Value | Where it comes from |
|---|---|---|
| `CULLIS_LICENSE_KEY` | Raw JWT, single line | From Cullis Security at deal close |
| `MCP_PROXY_PROXY_PUBLIC_URL` | Public URL agents reach the Mastio at | Your DNS + TLS port |
| `MCP_PROXY_ADMIN_SECRET` | 32+ hex chars | `openssl rand -hex 32` |
| `MCP_PROXY_DASHBOARD_SIGNING_KEY` | 32+ hex chars | `openssl rand -hex 32` |
| `CULLIS_MASTIO_VERSION` | Released image tag (e.g. `0.3.0`) | The release notes for the bundle tag |

Then enable each licensed feature's envs as needed. The full
catalogue lives in `proxy.env.example` with one section per plugin.
For instance, to enable `audit_export_s3`:

```bash
CULLIS_AUDIT_EXPORT_S3_BUCKET=cullis-audit-yourorg
CULLIS_AUDIT_EXPORT_S3_REGION=eu-west-1
CULLIS_AUDIT_EXPORT_S3_PREFIX=mastio/2026/
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

`MCP_PROXY_KMS_BACKEND` selects exactly one Org CA backend:
`local` (default; in proxy DB), `vault` (in-tree open-core, see
[Vault as Org CA private key store](./vault-org-ca)), or one of
`aws` / `azure` / `gcp` (enterprise plugins). Mixing is undefined.

## First boot validation

After `./deploy.sh` reports success:

```bash
# 1. License recognised
docker compose -p cullis-mastio-enterprise logs mcp-proxy 2>&1 | grep "license:"
# Expect: license: tier=enterprise org=<your-org> features=<N> exp=<YYYY-MM-DD>

# 2. Plugin loading
docker compose -p cullis-mastio-enterprise logs mcp-proxy 2>&1 | grep "plugin loaded:"
# One line per granted feature

# 3. Health
curl -k https://localhost:9443/health
# {"status":"ok","version":"<your tag>"}

# 4. Dashboard reachable
open https://<MCP_PROXY_PROXY_PUBLIC_URL>/proxy/login
```

If `license: tier=community` shows up instead, the JWT is missing,
malformed, expired, signed by a different keypair, or the bundle is
using an image without the matching pubkey. Cross-check the JWT exp
claim and re-issue if needed.

## CISO verification

The bundled image is cosign-signed (Sigstore keyless) and ships with
a CycloneDX SBOM. Customer CISO can verify either independently.

### Verify the cosign signature

```bash
cosign verify \
  --certificate-identity-regexp \
  '^https://github.com/cullis-security/cullis-enterprise/.github/workflows/release-mastio-enterprise.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/cullis-security/cullis-mastio-enterprise:<VERSION>
```

A green verify confirms: this image was built by the canonical Cullis
Security release workflow on the named tag and the signature is
discoverable in the public Sigstore Rekor transparency log. No
private-key trust required.

### Pull the SBOM

The CycloneDX SBOM is attached to the corresponding `mastio-enterprise-v*`
release in the private `cullis-security/cullis-enterprise` repo. Look
for `sbom.cdx.json` in the release assets. Access requires the same
PAT used for the image pull.

## Upgrading

```bash
# Bump the pinned tag
sed -i 's/^CULLIS_MASTIO_VERSION=.*/CULLIS_MASTIO_VERSION=<new>/' proxy.env

# Re-pull and restart
./deploy.sh --pull
```

Operator-side data (`./data/mcp_proxy.db`, `./nginx-certs/`,
`./saml-keys/`) survives the image bump. The Org CA in
`./nginx-certs/org-ca.crt` is the trust root of your agent population;
do not lose it. See [Apply updates](./apply-updates) for the wider
upgrade strategy that applies to both open-core and enterprise.

## Troubleshooting

### `pull of ghcr.io/cullis-security/cullis-mastio-enterprise:... failed`

The PAT has not been registered, expired, or is missing the
`read:packages` scope.

```bash
# Re-authenticate
echo <PAT> | docker login ghcr.io -u <github-user> --password-stdin

# Confirm pull succeeds
docker pull ghcr.io/cullis-security/cullis-mastio-enterprise:<VERSION>
```

If the PAT itself is bad, ask hello@cullis.io for a fresh one
referencing your contract ID.

### `license: tier=community` despite a JWT being set

Three possible causes:

1. **JWT not picked up.** Make sure `CULLIS_LICENSE_KEY` in `proxy.env`
   has the JWT on a single line, no surrounding quotes. Check with
   `docker compose exec mcp-proxy env | grep CULLIS_LICENSE`.
2. **JWT expired.** Decode the `exp` claim and compare against now.
   Re-issue from Cullis Security.
3. **JWT signed by a non-prod key.** A common foot-gun in staging:
   `cullis-license-gen` is run locally with a dev keypair, the
   resulting JWT does not verify against the prod pubkey baked into
   the image. For staging tokens, set
   `CULLIS_LICENSE_PUBKEY_PATH=/etc/cullis/keys/dev-pubkey.pem` and
   mount your dev pubkey in.

### Plugin `X` not loading despite `X` in license features

The license grants the feature but the plugin's dependency is missing
or its required envs are not set. Check the boot log for the plugin
discovery section: it will tell you which plugin failed to load and
why (e.g. `cloud_kms_aws: missing CULLIS_CLOUD_KMS_AWS_SECRET_ID`).

If the boot log shows the plugin as loaded but its functionality
does not work, walk the plugin-specific guide:

- [Audit export](./audit-export) for `audit_export_*`
- [Vault as Org CA private key store](./vault-org-ca) for the parallel
  in-tree path (the cloud KMS plugins follow the same shape, just
  swap the backend)

### nginx-sidecar unhealthy, mcp-proxy healthy

The nginx sidecar gates on three cert files existing on the bind
mount: `mastio-server.crt`, `mastio-server.key`, `org-ca.crt`. The
mcp-proxy generates them on first boot inside
`/var/lib/mastio/nginx-certs` (host path `./nginx-certs`). If they
are absent, the proxy did not finish first-boot wizard; complete it
via the dashboard, then `docker compose restart mastio-nginx`.

### Cannot reach `https://<host>:9443` from a sibling Docker network

The Mastio binds 9443 on the host via the nginx sidecar. A sibling
container reaching the host needs `host.docker.internal` resolved to
`host-gateway`; the bundle's compose adds this `extra_hosts` entry
already. If your sibling stack is in a separate compose file, copy
the same `extra_hosts` block over.

## Compliance mapping

The supply chain controls this bundle ships with match a handful of
common compliance line items:

| Control | Where it lands |
|---|---|
| SOC 2 CC6.1 (logical + physical access) | License + PAT gating |
| SOC 2 CC7.1 (system monitoring) | `audit_export_*` plugins |
| ISO 27001 A.8.30 (provider monitoring) | SBOM attached to release |
| ISO 27001 A.12.7 (audit logging) | Audit export plugins |
| EU AI Act Art. 12 (record-keeping) | Audit export plugins |
| DORA Art. 28 (ICT third-party) | Cosign keyless verify, SBOM |

The SBOM is CycloneDX JSON; map it through your SCA tool of choice
for ongoing CVE monitoring.

## Where to get help

- Operations questions: hello@cullis.io
- License renewal / PAT rotation: hello@cullis.io with contract ID
- Bug reports: include `./deploy.sh --down` exit logs, redacted
  `proxy.env` (license JWT REDACTED), and the cosign verify output
  of the failing image tag
