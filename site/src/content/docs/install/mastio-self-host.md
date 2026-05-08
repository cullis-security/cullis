---
title: "Self-host the Mastio"
description: "Deploy a Cullis Mastio on a single host with Docker Compose — TLS options, first-boot wizard, env vars."
category: "Install"
order: 20
updated: "2026-04-23"
---

# Self-host the Mastio

**Who this is for**: an enterprise operator deploying the Cullis Mastio on-prem or on a single VM. You control the DNS, the TLS certificates, and the host. For Kubernetes-based deploys, see [Mastio on Kubernetes](mastio-kubernetes) instead.

## Prerequisites

- Docker Engine ≥ 24 with Compose v2
- 4 GB RAM, 20 GB disk
- A DNS name for the Mastio (e.g. `mastio.acme.local` or `mastio.acme.com`) pointing at the host
- A TLS certificate, or public DNS + port 80 open for Let's Encrypt ACME challenge

## 1. Clone and configure

```bash
git clone https://github.com/cullis-security/cullis
cd cullis
cp .env.example .env
```

Generate secrets:

```bash
python3 -c "import secrets; print('ADMIN_SECRET=' + secrets.token_urlsafe(32))" >> .env
python3 -c "import secrets; print('DASHBOARD_SIGNING_KEY=' + secrets.token_urlsafe(32))" >> .env
```

Edit `.env` and set at minimum:

```bash
ADMIN_SECRET=<generated>
DASHBOARD_SIGNING_KEY=<generated>
MCP_PROXY_PROXY_PUBLIC_URL=https://mastio.acme.local
MCP_PROXY_ORG_ID=acme
ALLOWED_ORIGINS=https://mastio.acme.local
```

See [Configuration reference](../reference/configuration) for every supported env var.

## 2. Generate the Mastio PKI

```bash
python3 generate_certs.py
```

This writes an Org CA + Mastio intermediate into `certs/` and stages them for Vault or the local KMS. The script is idempotent — re-running preserves existing material.

## 3. Deploy with a TLS profile

`deploy_broker.sh` orchestrates the compose stack with three TLS profiles. All run unattended via CLI flags (suitable for CI or Terraform `local-exec`); without flags the script falls back to interactive prompts.

### A. Development (self-signed, localhost)

```bash
./deploy_broker.sh --dev
```

Generates a self-signed cert for `localhost` and `127.0.0.1`. The Mastio is reachable at `https://localhost:9443`. **Suitable only for laptop demos** — no client outside the host will trust this cert.

### B. Production with Let's Encrypt

```bash
./deploy_broker.sh --prod-acme \
    --domain mastio.acme.com \
    --email  ops@acme.com
```

Requirements:

- Public DNS for `mastio.acme.com` pointing at this host
- TCP/80 reachable from the internet (for the ACME `http-01` challenge)
- TCP/443 reachable for the renewed cert

What the script does:

1. Boots nginx with a 1-day temporary self-signed cert so the container starts
2. Runs `certbot certonly --webroot` to obtain the real certificate
3. Reloads nginx pointing at `/etc/letsencrypt/live/<domain>/fullchain.pem`
4. Prints a renewal cron line — **add it manually**:
   ```cron
   0 3 * * * cd /opt/cullis && docker compose \
       -f deploy/compose/docker-compose.yml \
       -f deploy/compose/docker-compose.prod.yml \
       -f deploy/compose/docker-compose.letsencrypt.yml \
       run --rm certbot renew --quiet && \
       docker compose exec nginx nginx -s reload
   ```

### C. Production with Bring Your Own CA (BYOCA)

```bash
./deploy_broker.sh --prod-byoca \
    --domain mastio.acme.com \
    --cert /etc/ssl/cullis/fullchain.pem \
    --key  /etc/ssl/cullis/privkey.pem
```

The script copies both files into `nginx/certs/` (chmod 600 on the key) and writes a matching `nginx/nginx.conf` for the supplied domain. Renewal is your responsibility — re-run with the new files when the cert expires.

## 4. First-boot wizard

The Mastio's first load redirects to a one-time setup page at `https://mastio.acme.com/proxy/first-boot`. Fill three fields:

- **Admin password**: matches `ADMIN_SECRET` from `.env` — the wizard stores a bcrypt hash in Vault.
- **Org display name**: "Acme Corp". Shown on the dashboard and federation peers.
- **Org ID**: lowercase slug (`acme`). Must match `MCP_PROXY_ORG_ID` in `.env`.

Press **Set up**. The Mastio finishes PKI initialization, provisions the local admin account, and redirects to `/proxy/overview`.

## 5. Verify

```bash
curl -sk https://mastio.acme.com/healthz
# {"status": "ok"}

curl -sk https://mastio.acme.com/readyz
# {"status": "ready", "checks": {"db": "ok", "redis": "ok", "vault": "ok"}}

curl -sk -H "X-Admin-Secret: $ADMIN_SECRET" \
    https://mastio.acme.com/v1/admin/mcp-resources
# []  — empty until you register MCP servers
```

Your Mastio is up. Agents can now enroll via [BYOCA](../enroll/byoca), [Connector](../enroll/connector-device-code), or [SPIRE](../enroll/spire).

## Troubleshoot

**`Invalid DPoP proof: htu mismatch` 401s after deploy**
: `MCP_PROXY_PROXY_PUBLIC_URL` in `.env` does not match the URL clients actually use. The DPoP proof carries the client's URL; the Mastio derives `htu` from its configured public URL. They must match exactly, scheme and port included. Check with:
  ```bash
  docker compose exec proxy env | grep PROXY_PUBLIC_URL
  curl -kvI https://mastio.acme.com/healthz 2>&1 | grep -E "Host|location"
  ```

**First-boot wizard rejects the admin password**
: The password you type must be the exact value of `ADMIN_SECRET` in `.env`. No trimming, no URL-encoding. Verify with `docker compose exec proxy env | grep ADMIN_SECRET`.

**`nginx: [emerg] BIO_new_file() ... PEM_read_bio_PrivateKey() failed`**
: The TLS key file is not readable by the nginx container or is malformed. Check `ls -l nginx/certs/server-key.pem` — should be mode 600, owned by root. Verify with `openssl rsa -in nginx/certs/server-key.pem -check -noout`.

**Vault fails to unseal**
: `./vault/init-vault.sh` seeded unseal keys into `vault/vault-keys.json` on first run. If you deleted that file, you've lost the keys and Vault is bricked; restore from backup or run `./deploy_broker.sh --prod-byoca` against a fresh Vault volume.

## Next

- [Mastio on Kubernetes](mastio-kubernetes) — Helm chart for multi-node deployments
- [Runbook](../operate/runbook) — incident response for the failures most likely to wake you up
- [Configuration reference](../reference/configuration) — every env var, defaults, and format
- [Apply updates](../operate/apply-updates) — framework migrations and the sign-halt flow
