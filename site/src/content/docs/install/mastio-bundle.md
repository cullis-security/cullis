---
title: "Mastio on Docker"
description: "Self-host the Cullis Mastio on a single Linux host with the Docker Compose bundle — two commands from tarball to a running gateway with first-boot Org CA, admin account, and dashboard."
category: "Install"
order: 20
updated: "2026-05-22"
---

# Mastio on Docker

**Who this is for**: an operator self-hosting a single Mastio on a Linux host (VM, bare metal, dev laptop). The bundle is a self-contained `docker compose` stack: it pulls the published image from GHCR, mints a fresh Org CA on first boot, generates an admin account, and exposes the dashboard on `https://localhost:9443`. No source tree required.

For a Kubernetes deployment, see [Mastio on Kubernetes](mastio-kubernetes) instead.

## Prerequisites

- **Docker Engine** 20.10+ with **Docker Compose v2** (`docker compose version`)
- **bash** 4+, **curl**, **tar**, **gzip** — almost always already on the host
- **openssl** is optional; when absent the bundle falls back to `/dev/urandom + base64` so minimal NixOS / Alpine / distroless hosts work out of the box
- One free TCP port on the host (default `9443`)

## Scope

**In scope**

- Single-host Mastio standalone (private docker network)
- First-boot Org CA mint + admin account + nginx TLS sidecar
- Dashboard on `https://localhost:9443/proxy/login`
- `/healthz` → 200 and `/readyz` → ready

**Out of scope** (covered elsewhere)

- Multi-node production deployment — see [Mastio on Kubernetes](mastio-kubernetes)
- Postgres backend for pilots above ~50 concurrent agents — see [Postgres for production pilots](../operate/postgres-pilot)
- External Redis / Vault — supported via `proxy.env`, see [Configuration reference](../reference/configuration)

## 1. Download the bundle

Grab the latest release tarball from <https://cullis.io/download/>. That page tracks the current recommended URL atomically with each release; the full Mastio version list is at <https://github.com/cullis-security/cullis/releases?q=mastio-v>.

```bash
curl -L -o cullis-mastio-bundle.tar.gz \
    https://github.com/cullis-security/cullis/releases/latest/download/cullis-mastio-bundle.tar.gz
tar xzf cullis-mastio-bundle.tar.gz
cd cullis-mastio-bundle/
```

## 2. Deploy

```bash
./deploy.sh
```

The script prompts once for the **public URL** agents will use to reach this Mastio. The default is auto-detected:

- **Single laptop / VM** (Mastio + browser + SDK on the same host): just press Enter — the script picks `https://host.docker.internal:9443` on macOS / Windows / Docker Desktop, or an interface IP on Linux pure.
- **VM hosting Mastio, browser/SDK on a separate machine** (e.g. a libvirt VM reached from your laptop over a bridge network): the auto-detected default is the VM's primary interface IP, reachable from the laptop. Press Enter unless you have a stable DNS name.
- **Internal server with stable DNS**: enter `https://mastio.acme.local` (or whatever your DNS resolves).
- **Internet-facing**: enter the LB / ingress hostname (e.g. `https://mastio.myorg.example.com`).

Whatever you pick, the deploy script bakes it into both `MCP_PROXY_PROXY_PUBLIC_URL` (so DPoP `htu` validation accepts it) and the nginx TLS server certificate SAN list (so agents using `verify_tls=True` complete the handshake). The next deploy reuses these values; rerun `./deploy.sh` with a different answer to rotate.

The script also:

- Generates `proxy.env` from `proxy.env.example` if missing
- Mints the Org CA and the nginx server certificate into `./nginx-certs/`
- Pulls the GHCR image and starts the stack
- Waits for `/healthz` to return `200`

## 3. Create the administrator and connect an agent

Open the dashboard URL printed by the deploy script (e.g. `https://<your-host>:9443/proxy/login`) in a browser. The browser will warn about the certificate — that is expected: the TLS cert is signed by your auto-generated Org CA, not a public CA. Accept the warning once, or import `./certs/org-ca.pem` (also exported to `./nginx-certs/org-ca.crt`) into your OS trust store.

Create the **admin account**. For standalone Mastio, the separate broker
setup wizard is not needed.

Follow **`FIRST_AGENT.md` in the bundle** for the standard first-agent path:
configure a model provider, run `first-agent.py connect` on the agent computer,
approve the request in **Enrollments**, then run `check` and a first task.
The agent generates its own identity and request-signing keys. The guide
also covers selecting MCP tools and verifying resource access.

This path uses the existing Python SDK and keeps TLS verification enabled.
It does not require an administrator token or provider key on the agent host.

## 4. Verify

```bash
curl -k https://localhost:9443/healthz
# {"status":"ok"}

curl -k https://localhost:9443/readyz
# {"status":"ready","checks":{"database":"ok","jwks_cache":"ok"}}
```

If `/readyz` returns `503`, jump to [Troubleshoot](#troubleshoot).

## Enable model access

Open **Settings → AI Providers** in the dashboard. Configure Anthropic, OpenAI
or Ollama, save the settings and test the connection. Keep the provider credentials on
Mastio and use a model ID supported by the configured provider in the agent.
Without a configured provider, model requests cannot complete; registry,
MCP and audit can still operate independently.

Assign **`llm.chat`** to agents that should call a model. The first-agent guide
includes this permission in its approval step.

## Production deployment

For anything beyond a local trial, mint a production `proxy.env` and switch to the `--prod` profile (fails fast on insecure defaults):

```bash
BROKER_URL=https://broker.example.com \
PROXY_PUBLIC_URL=https://mastio.acme.example.com \
./generate-proxy-env.sh --prod
./deploy.sh --prod
```

`generate-proxy-env.sh --prod` mints fresh `MCP_PROXY_ADMIN_SECRET` + `MCP_PROXY_DASHBOARD_SIGNING_KEY` and refuses to run without `BROKER_URL` / `PROXY_PUBLIC_URL` env vars.

### Pin a release

```bash
CULLIS_MASTIO_VERSION=0.5.2 ./deploy.sh
```

`latest` is fine for a quick try; pin to a specific tag in production.

### Tune workers

Mastio ships with multi-worker uvicorn enabled by default (4 workers). On hosts with more or fewer logical cores, override via `proxy.env`:

```bash
echo 'MASTIO_WORKERS=8' >> proxy.env
./deploy.sh --pull
```

For cross-worker DPoP replay protection, point the Mastio at Redis:

```bash
echo 'MCP_PROXY_REDIS_URL=redis://your-redis-host:6379/0' >> proxy.env
./deploy.sh --pull
```

## Deploy modes

| Command | Effect |
|---|---|
| `./deploy.sh` | Standalone Mastio, private docker network. Default. |
| `./deploy.sh --prod` | Production safety: fails fast on insecure defaults. Requires `proxy.env` pre-provisioned. |
| `./deploy.sh --pull` | Force re-pull the image before starting. |
| `./deploy.sh --down` | Stop and remove containers. Bind dirs (`./data`, `./nginx-certs`, `./certs`) are preserved. |
| `./deploy.sh --down -v` | Stop, remove containers, AND wipe bind dirs. Resets state to a brand-new install. |

## Updating

Default — full bundle refresh:

```bash
./deploy.sh --upgrade 0.5.2
```

Downloads the released tarball from GitHub, backs up `proxy.env` + `./data/` + `./nginx-certs/` to `./backups/pre-upgrade-<ts>/`, extracts the new bundle scripts in place (without touching your state), bumps `CULLIS_MASTIO_VERSION`, pulls the matching image, and restarts the stack with `compose up -d --wait`.

`./data/` (SQLite DB), `./nginx-certs/` (Org CA + server cert), and `proxy.env` are preserved across every upgrade path. Org CA and admin password persist across image bumps.

## Troubleshoot

| Symptom | Fix |
|---|---|
| `permission denied` on `./deploy.sh` | `chmod +x deploy.sh generate-proxy-env.sh` |
| `docker compose is not installed` | Install Docker Engine 20.10+ with Compose v2 |
| Browser warns "self-signed certificate" | Expected. The Org CA is local; accept once or import `./nginx-certs/org-ca.crt` into your OS trust store. |
| Agent gets `401 Invalid DPoP proof: htu mismatch` | The Mastio validates DPoP proofs against `MCP_PROXY_PROXY_PUBLIC_URL` (default `https://localhost:9443`). Production deploys MUST override this in `proxy.env` to match the public hostname agents reach the Mastio at. |
| Agent fails with `SSL: CERTIFICATE_VERIFY_FAILED` or `hostname doesn't match` | The nginx sidecar's TLS cert SAN includes only `MCP_PROXY_NGINX_SAN` entries (default `mastio.local,localhost`). Append your hostname and `./deploy.sh --pull` to re-mint the cert. |
| Agent fails with `getaddrinfo failed` / `Name or service not known` | The hostname you set as the public URL must resolve to the Mastio host's IP from the agent's machine. Use corporate DNS, a public DNS A record, or `/etc/hosts` per-agent for small trials. |
| `Bind for 0.0.0.0:9443 failed: port is already allocated` | Override the host port in `proxy.env`: `MCP_PROXY_PORT=9444`. **Critical:** also update `MCP_PROXY_PROXY_PUBLIC_URL` to use the same port — agents sign DPoP `htu` against that exact URL+port and a mismatch silently 401s. |

For the full troubleshooting catalogue (volume migrations from v0.3.x, Postgres swap guardrails, `--shared-broker` networking), see the README that ships inside the bundle tarball.

## Reset everything

```bash
./deploy.sh --down -v
```

Stops the stack and wipes `./data`, `./nginx-certs`, and `./certs`. The wipe runs as root inside a transient `busybox` so the `0600` files owned by uid `10001` are actually removed, no `sudo rm -rf` on the host required. `proxy.env`, the bundle scripts, and `./backups/` are NOT touched.

**Destructive.** Every agent enrolled against the current Org CA will fail TLS verify on `/v1/principals/csr` after the next bring-up — the new Mastio derives a fresh CA and `org_id`. Use `./deploy.sh --upgrade <version>` for any flow where you want to preserve enrolled agents.

## Next

- [Enroll agents via BYOCA](../enroll/byoca) — wire a customer-provided PKI
- [Enroll agents via SPIRE](../enroll/spire) — if SPIRE is part of your workload identity fabric
- [SDK quickstart](../quickstart/sdk) — install the Python SDK and call the Mastio from agent code
- [Runbook](../operate/runbook) — production incident response
- [Mastio on Kubernetes](mastio-kubernetes) — multi-node deployment with Helm
