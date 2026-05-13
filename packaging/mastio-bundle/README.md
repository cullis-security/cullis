# Cullis Mastio — deploy bundle

Self-contained Mastio deploy. Pulls the published image from GHCR, no
source tree required.

## Prerequisites

- **Docker** Engine 20.10+ with **docker compose v2** (`docker compose version`).
- **bash** 4+, **curl**, **tar**, **gzip** — almost always already on the host.
- **openssl** is optional. When present `deploy.sh` uses `openssl rand` for the admin secrets; when absent it falls back to `/dev/urandom + base64`, so minimal NixOS / Alpine / distroless hosts work out of the box.

## Quickstart (2 commands, you already have this tarball)

```bash
cd cullis-mastio-bundle/
./deploy.sh
```

This README ships **inside** the bundle tarball, so by the time you
are reading it you have already extracted the code. To grab a fresh
download from scratch, see <https://cullis.io/download/> for the
current recommended URL — that page tracks the latest rc / stable
release. The full Mastio version list is at
<https://github.com/cullis-security/cullis/releases?q=mastio-v>.

> Why no pinned ``curl ...`` URL here? The download URL must point at a
> specific release tag, but the README ships *inside* the tarball; a
> hard-coded version drifts the moment a newer rc/stable cuts and
> readers paste a stale URL even though they are already running a
> newer bundle. The cullis.io/download page above is updated atomically
> with each release.

Open `https://localhost:9443/proxy/login` (the browser will warn — the
TLS cert is signed by your auto-generated Org CA, not a public CA).
Complete the first-boot wizard and enroll your first agent.

## Enable chat (Anthropic API key)

The Mastio includes an embedded AI gateway (ADR-017) that powers the
chat completion endpoint used by Cullis Chat and Frontdesk. Without a
provider key, chat returns HTTP 503 `provider_key_missing` and the UI
shows an error — registry / MCP / audit keep working regardless.

To enable chat, copy `proxy.env.example` to `proxy.env` (the deploy
script does this on first run if missing), open it, and set:

```bash
MCP_PROXY_ANTHROPIC_API_KEY=sk-ant-...
```

Then restart the bundle:

```bash
./deploy.sh --pull
```

Today only Anthropic is wired as upstream provider. OpenAI / Gemini
are on the roadmap; setting `MCP_PROXY_AI_GATEWAY_PROVIDER` to anything
other than `anthropic` returns HTTP 501 until the corresponding wiring
lands. See the AI gateway block in `proxy.env.example` for the full
list of tunables (backend, provider, sidecar URL, timeout).

## Pin a release

```bash
CULLIS_MASTIO_VERSION=0.3.0 ./deploy.sh
```

`latest` is fine for a quick try; pin to a specific tag in production.

## Modes

| Command | Effect |
|---|---|
| `./deploy.sh` | Standalone Mastio, private docker network. Default. |
| `./deploy.sh --shared-broker` | Federated. Joins an existing Court's docker network. |
| `./deploy.sh --prod` | Production safety: fails fast on insecure defaults. Requires `proxy.env` pre-provisioned. |
| `./deploy.sh --pull` | Force re-pull the image before starting. |
| `./deploy.sh --down` | Stop and remove containers. |

## Production proxy.env

```bash
BROKER_URL=https://broker.example.com \
PROXY_PUBLIC_URL=https://mastio.myorg.example.com \
./generate-proxy-env.sh --prod
./deploy.sh --prod
```

`generate-proxy-env.sh --prod` mints fresh `MCP_PROXY_ADMIN_SECRET` +
`MCP_PROXY_DASHBOARD_SIGNING_KEY` and refuses to run without
`BROKER_URL` / `PROXY_PUBLIC_URL` env vars.

## What's in the bundle

```
docker-compose.yml                  # base: image-based (GHCR), standalone
docker-compose.shared-broker.yml    # overlay: federated mode
docker-compose.prod.yml             # overlay: production safety
nginx/mastio/                       # nginx sidecar config (TLS + mTLS)
proxy.env.example                   # config template
generate-proxy-env.sh               # config generator
deploy.sh                           # entrypoint
```

The Mastio writes its Org CA + nginx server cert into `./nginx-certs/`
(host bind mount, ADR-030) on first boot; the `mastio-nginx` sidecar
mounts the same path read-only and serves TLS on host port 9443. The
SQLite DB lives at `./data/mcp_proxy.db`. No manual cert provisioning,
no `docker volume rm` indirection for backups — host filesystem is the
source of truth.

Customers upgrading from v0.3.x with legacy named volumes
(`mcp_proxy_data`, `mastio_nginx_certs`) are auto-migrated to the bind
layout the first time they run `./deploy.sh --upgrade-bundle <version>`;
see the **Updating** section below.

## Kubernetes

The image is also packaged as a Helm chart published to the same
registry:

```bash
helm install cullis-mastio \
  oci://ghcr.io/cullis-security/charts/cullis-mastio \
  --version 0.3.0 \
  --set nginx.san="mastio.myorg.example.com,mastio.local" \
  --set proxy.proxyPublicUrl=https://mastio.myorg.example.com
```

See `deploy/helm/cullis-mastio/README.md` in the source repo for the
full values reference.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `permission denied` on `./deploy.sh` | `chmod +x deploy.sh generate-proxy-env.sh` |
| `docker compose is not installed` | Install Docker Engine 20.10+ with Compose v2 |
| `network cullis-broker_default not found` (with `--shared-broker`) | Bring the Court compose project up first, or drop `--shared-broker` |
| Browser warns "self-signed certificate" | Expected. The Org CA is local; accept once or import `./nginx-certs/org-ca.crt` (also exported to `./certs/org-ca.pem` by `./deploy.sh` post-up). |
| Agent gets `401 Invalid DPoP proof: htu mismatch` | The Mastio validates DPoP proofs against `MCP_PROXY_PROXY_PUBLIC_URL` (default `https://localhost:9443` for quickstart). Production deploys MUST override this in `proxy.env` to match the public hostname agents reach the Mastio at — e.g. `MCP_PROXY_PROXY_PUBLIC_URL=https://mastio.myorg.example.com`. |
| Agent fails with `SSL: CERTIFICATE_VERIFY_FAILED` or `hostname doesn't match` | The nginx sidecar's TLS cert is signed by the auto-generated Org CA and includes only the SAN entries listed in `MCP_PROXY_NGINX_SAN` (default `mastio.local,localhost`). `./deploy.sh` auto-extracts the hostname from your prompt answer and adds it to the SAN; if you set `MCP_PROXY_PROXY_PUBLIC_URL` manually after-the-fact, also append the hostname to `MCP_PROXY_NGINX_SAN` (e.g. `MCP_PROXY_NGINX_SAN=mastio.acme.local,mastio.local,localhost`) and `./deploy.sh --pull` to re-mint the cert. |
| Agent fails with `getaddrinfo failed` / `Name or service not known` | The hostname you set as the public URL must resolve to the Mastio host's IP from the agent's machine. Three paths: (1) corporate DNS (e.g. Active Directory) — recommended; (2) public DNS A record if the Mastio is internet-reachable; (3) `/etc/hosts` line on each agent machine (`192.168.10.42  mastio.acme.local`) — okay for 2-3 employees, brittle past that. |
| `Bind for 0.0.0.0:9443 failed: port is already allocated` | Another service on the host is using 9443 (Caddy / Traefik / nginx-proxy / a previous Mastio that didn't shut down cleanly). Override the host port in `proxy.env`: `MCP_PROXY_PORT=9444`. **Critical:** also update `MCP_PROXY_PROXY_PUBLIC_URL` to use the same port (e.g. `https://mastio.acme.local:9444`) — agents firma DPoP htu against that exact URL+port and a mismatch silently 401s. |

## Updating

**Recommended — full bundle refresh (ADR-030):**

```bash
./deploy.sh --upgrade-bundle 0.4.0
```

Downloads the released tarball from GitHub, backs up `proxy.env` + `./data/` + `./nginx-certs/` to `./backups/pre-upgrade-<ts>/`, extracts the new bundle scripts in place (without touching your state), bumps `CULLIS_MASTIO_VERSION`, pulls the matching image, and restarts the stack with `compose up -d --wait`. The dashboard's "update available" banner shows the same command as a one-liner you can paste into the host shell.

**Image-only bump (scripts stay at the bundle's original version):**

```bash
./deploy.sh --upgrade 0.4.0
# or:
./deploy.sh --pull
```

Use this if you trust the new image but want to keep your current `deploy.sh` / compose / scripts. Note: future env vars introduced by a release will NOT reach `proxy.env` until you do a full bundle refresh.

**Migrate from legacy named volumes (one-shot, v0.3.x → v0.4.x):**

```bash
./deploy.sh --migrate-volumes
```

Stops the stack, copies `mcp_proxy_data` → `./data/` and `mastio_nginx_certs` → `./nginx-certs/` via a transient busybox container (so file ownership stays correct), and leaves the named volumes in place so you can confirm the new layout boots cleanly before deleting them with `docker volume rm`. Idempotent: safe to re-run.

`--upgrade-bundle` triggers this automatically when it detects legacy volumes, prompting interactively unless you pass `--from-banner` (the banner one-liner does this for you).

**Advanced — step-by-step fallback:**

If your `deploy.sh` predates v0.4.0 and you cannot use `--upgrade-bundle` yet, you can do the upgrade by hand:

```bash
cd ~/cullis-mastio-bundle
wget https://github.com/cullis-security/cullis/releases/download/mastio-v0.4.0/cullis-mastio-bundle-0.4.0.tar.gz
tar xzf cullis-mastio-bundle-0.4.0.tar.gz --strip-components=1 --overwrite
./deploy.sh --pull
```

The new `deploy.sh` will offer to run `--migrate-volumes` on the next invocation if it still finds named volumes.

**Data preservation:** `./data/` (SQLite DB), `./nginx-certs/` (Org CA + server cert), and `proxy.env` are preserved across every upgrade path above. Org CA and admin password persist across image bumps.
