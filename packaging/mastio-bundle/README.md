# Cullis Mastio — deploy bundle

Self-contained Mastio deploy. Pulls the published image from GHCR, no
source tree required.

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

The Mastio writes its Org CA + nginx server cert into a docker volume
on first boot; the `mastio-nginx` sidecar mounts the same volume
read-only and serves TLS on host port 9443. No manual cert
provisioning.

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
| Browser warns "self-signed certificate" | Expected. The Org CA is local; accept once or extract `org-ca.crt` from the `mcp_proxy_data` volume and import it. |
| Agent gets `401 Invalid DPoP proof: htu mismatch` | The Mastio validates DPoP proofs against `MCP_PROXY_PROXY_PUBLIC_URL` (default `https://localhost:9443` for quickstart). Production deploys MUST override this in `proxy.env` to match the public hostname agents reach the Mastio at — e.g. `MCP_PROXY_PROXY_PUBLIC_URL=https://mastio.myorg.example.com`. |
| Agent fails with `SSL: CERTIFICATE_VERIFY_FAILED` or `hostname doesn't match` | The nginx sidecar's TLS cert is signed by the auto-generated Org CA and includes only the SAN entries listed in `MCP_PROXY_NGINX_SAN` (default `mastio.local,localhost`). `./deploy.sh` auto-extracts the hostname from your prompt answer and adds it to the SAN; if you set `MCP_PROXY_PROXY_PUBLIC_URL` manually after-the-fact, also append the hostname to `MCP_PROXY_NGINX_SAN` (e.g. `MCP_PROXY_NGINX_SAN=mastio.acme.local,mastio.local,localhost`) and `./deploy.sh --pull` to re-mint the cert. |
| Agent fails with `getaddrinfo failed` / `Name or service not known` | The hostname you set as the public URL must resolve to the Mastio host's IP from the agent's machine. Three paths: (1) corporate DNS (e.g. Active Directory) — recommended; (2) public DNS A record if the Mastio is internet-reachable; (3) `/etc/hosts` line on each agent machine (`192.168.10.42  mastio.acme.local`) — okay for 2-3 employees, brittle past that. |
| `Bind for 0.0.0.0:9443 failed: port is already allocated` | Another service on the host is using 9443 (Caddy / Traefik / nginx-proxy / a previous Mastio that didn't shut down cleanly). Override the host port in `proxy.env`: `MCP_PROXY_PORT=9444`. **Critical:** also update `MCP_PROXY_PROXY_PUBLIC_URL` to use the same port (e.g. `https://mastio.acme.local:9444`) — agents firma DPoP htu against that exact URL+port and a mismatch silently 401s. |

## Updating

```bash
./deploy.sh --pull           # pull latest, restart
# or pin:
CULLIS_MASTIO_VERSION=0.3.1 ./deploy.sh --pull
```

Volumes (`mcp_proxy_data`, `mastio_nginx_certs`) survive restarts; Org
CA and DB persist across image upgrades.
