# Cullis Mastio — deploy bundle

Self-contained Mastio deploy. Pulls the published image from GHCR, no
source tree required.

## Quickstart (3 commands)

```bash
curl -L https://github.com/cullis-security/cullis/releases/latest/download/cullis-mastio-bundle.tar.gz | tar xz
cd cullis-mastio-bundle/
./deploy.sh
```

Open `https://localhost:9443/proxy/login` (the browser will warn — the
TLS cert is signed by your auto-generated Org CA, not a public CA).
Complete the first-boot wizard and enroll your first agent.

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
| `Bind for 0.0.0.0:9443 failed: port is already allocated` | Another service on the host is using 9443 (Caddy / Traefik / nginx-proxy / a previous Mastio that didn't shut down cleanly). Override the host port in `proxy.env`: `MCP_PROXY_PORT=9444`. **Critical:** also update `MCP_PROXY_PROXY_PUBLIC_URL` to use the same port (e.g. `https://mastio.acme.local:9444`) — agents firma DPoP htu against that exact URL+port and a mismatch silently 401s. |

## Updating

```bash
./deploy.sh --pull           # pull latest, restart
# or pin:
CULLIS_MASTIO_VERSION=0.3.1 ./deploy.sh --pull
```

Volumes (`mcp_proxy_data`, `mastio_nginx_certs`) survive restarts; Org
CA and DB persist across image upgrades.
