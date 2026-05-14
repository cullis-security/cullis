# Cullis Mastio Enterprise — image-based bundle

Self-contained Docker Compose deploy of the Mastio enterprise image
plus its mTLS nginx sidecar. Same shape as the open-core
`packaging/mastio-bundle`; the difference is the image (private,
licensed) and the plugin env surface.

## Prerequisites

- Docker 24+ with Compose v2
- A GitHub PAT issued by Cullis Security at deal close (read access to
  `ghcr.io/cullis-security/cullis-mastio-enterprise`)
- A license JWT issued by Cullis Security (RS256-signed, lists the
  paid features your contract grants)

## Quick start

```bash
# 1. Authenticate to the private registry (one-time per host)
echo <PAT> | docker login ghcr.io -u <github-user> --password-stdin

# 2. Configure the proxy
cp proxy.env.example proxy.env
# Edit proxy.env:
#   - CULLIS_LICENSE_KEY=<paste the JWT here>
#   - MCP_PROXY_PROXY_PUBLIC_URL=https://mastio.yourorg.example.com:9443
#   - MCP_PROXY_ADMIN_SECRET=<openssl rand -hex 32>
#   - MCP_PROXY_DASHBOARD_SIGNING_KEY=<openssl rand -hex 32>
#   - Plugin-specific envs for the features your license grants
#     (see comments in proxy.env.example for the catalogue)

# 3. Deploy
./deploy.sh
```

`deploy.sh` runs two pre-flights before bringing the stack up:

1. License JWT shape check (header.payload.signature base64url). The
   container verifies the signature on boot against the pubkey baked
   into the image.
2. `docker pull` of the enterprise image. Fails fast with a clear
   message if `docker login ghcr.io` has not been done.

On `up` success the script reports how many plugins loaded and prints
the active license tier. Expect `plugins loaded: N` matching the
features in your license (1 plugin per granted feature).

## Verifying the image (CISO checklist)

The image is cosign-signed (Sigstore keyless) and ships with a
CycloneDX SBOM. Customer CISO can verify either before deploying.

### Verify the cosign signature

```bash
cosign verify \
  --certificate-identity-regexp \
  '^https://github.com/cullis-security/cullis-enterprise/.github/workflows/release-mastio-enterprise.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/cullis-security/cullis-mastio-enterprise:<VERSION>
```

A green verify means: this image was built by the canonical Cullis
Security release workflow on a tagged release, and the signature is
discoverable in the public Sigstore Rekor transparency log.

### Pull the SBOM

The CycloneDX SBOM is attached to the corresponding GitHub Release in
`cullis-security/cullis-enterprise` (private; needs PAT access). Look
for `sbom.cdx.json` in the release assets.

## Operations

| Action | Command |
|---|---|
| Bring up | `./deploy.sh` |
| Bring down | `./deploy.sh --down` |
| Re-pull image then up | `./deploy.sh --pull` |
| Logs | `docker compose -p cullis-mastio-enterprise logs -f mcp-proxy` |
| Open dashboard | `https://<MCP_PROXY_PROXY_PUBLIC_URL>/proxy/login` |

The first boot generates the Org CA and (if `MCP_PROXY_KMS_BACKEND` is
not `local`) writes the Org CA private key to the configured KMS
(Vault, AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager).

## Upgrading

```bash
# Edit proxy.env, bump CULLIS_MASTIO_VERSION to the new tag.
sed -i 's/^CULLIS_MASTIO_VERSION=.*/CULLIS_MASTIO_VERSION=<new>/' proxy.env
./deploy.sh --pull
```

Operator-side data (`./data/mcp_proxy.db`, `./nginx-certs/`,
`./saml-keys/`) survives the image bump.

## Where things live

| Path | What |
|---|---|
| `./data/` | SQLite DB, runtime state. Owned by container UID 10001. |
| `./nginx-certs/` | Org CA + nginx server cert. Read-write by mcp-proxy, read-only by mastio-nginx. |
| `./certs/` | (Optional) corporate CA bundle to trust. Mount-only. |
| `./saml-keys/` | (Optional) SAML SP signing keypair, generated on first saml_sso boot. |
| `proxy.env` | All config + license JWT. NEVER commit. |

## Support

- Documentation: https://cullis.io/docs/operate/enterprise-install
- License renewal / PAT rotation: hello@cullis.io
- Bug reports: include `./deploy.sh --down` logs + `proxy.env` (license
  REDACTED) + the cosign verify output of the failing image
