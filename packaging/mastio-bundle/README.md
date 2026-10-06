# Cullis Mastio, deploy bundle

Self-contained Mastio deploy. Pulls the published image from GHCR, no
source tree required. This README covers the fast path; the full guide,
with every tunable and operations runbook, lives at
**<https://cullis.io/docs/install/mastio-bundle>**.

## Prerequisites

- **Docker** Engine 20.10+ with **docker compose v2** (`docker compose version`).
- **bash** 4+, **curl**, **tar**, **gzip**: almost always already present.
- **jq**: only for the SDK quickstart's `curl`-based agent provisioning.
- **openssl**: optional. Used for admin secrets when present; falls back
  to `/dev/urandom` so minimal hosts work out of the box.

## Quickstart

**Want to evaluate with a local model? Follow [Local model demo](LOCAL_DEMO.md).**
It prepares Mastio, Ollama and an agent in a separate local environment, with
automatic model configuration and one explicit agent approval. Use synthetic data.

**First installation? Follow [Mastio and your first autonomous agent](FIRST_AGENT.md).**
It covers the model provider, administrator approval, an agent connection
check, and a bounded task using explicitly selected MCP tools. The bundle
includes `first-agent.py`; Python and the Cullis SDK are needed only on the
agent computer.

```bash
cd cullis-mastio-bundle/
./deploy.sh
```

`deploy.sh` prints the dashboard URL it picked for your host. Open it
(the browser warns: TLS is signed by your auto-generated Org CA, not a
public CA), create the administrator account and follow `FIRST_AGENT.md`.
The broker setup wizard is not required for standalone Mastio.

To grab a fresh download from scratch, see <https://cullis.io/download/>,
that page tracks the current rc / stable release.

## Enable chat

Configure your LLM provider from the dashboard: **Settings → AI Providers**
(`/proxy/ai-providers`). Add the provider settings, **Save**, then **Test**. Registry, MCP, and
audit work without it; only chat completion needs a provider. Until one is
configured, chat returns `503 provider_not_configured`.

Anthropic is wired today; OpenAI and Ollama are selectable in the same
page. Agents still need the `llm.chat` capability to reach chat endpoints,
see [SDK quickstart](https://cullis.io/docs/quickstart/sdk).

## Modes

| Command | Effect |
|---|---|
| `./deploy.sh` | Standalone Mastio, private docker network. Default. |
| `./deploy.sh --prod` | Production safety: fails fast on insecure defaults. Requires `proxy.env` pre-provisioned. |
| `./deploy.sh --pull` | Force re-pull the image before starting. |
| `./deploy.sh --down` | Stop and remove containers. Bind dirs preserved. |
| `./deploy.sh --down -v` | Stop, remove containers, AND wipe bind dirs (brand-new install). |
| `./deploy.sh --upgrade-bundle <version>` | Full bundle refresh, auto-backs-up state. See [Updating](#updating). |

## Reset (`--down -v`)

Wipes `./data/`, `./nginx-certs/`, and `./certs/` (the SQLite DB, Org CA,
and server cert) as root inside a transient busybox, so the 0600 files
owned by uid 10001 are actually removed without `sudo`. `proxy.env`,
the scripts, and `./backups/` are kept.

**Destructive.** The next bring-up mints a fresh Org CA and `org_id`;
every agent enrolled against the old CA must re-enroll. To preserve
enrolled agents across versions use `--upgrade-bundle` instead.

## What's in the bundle

```
docker-compose.yml                  # base: image-based (GHCR), standalone
docker-compose.shared-broker.yml    # overlay: federated mode
docker-compose.prod.yml             # overlay: production safety
docker-compose.postgres.yml         # overlay: external Postgres
nginx/mastio/                       # nginx sidecar config (TLS + mTLS)
proxy.env.example                   # config template
generate-proxy-env.sh               # config generator
deploy.sh                           # entrypoint
```

The Mastio writes its Org CA + nginx server cert into `./nginx-certs/`
and the SQLite DB to `./data/mcp_proxy.db` on first boot (host bind
mounts, ADR-030). The host filesystem is the source of truth: no manual
cert provisioning, no `docker volume` indirection for backups.

The default backend is SQLite, ship-safe with 4 uvicorn workers (A.1b
stress test, May 2026: 0 audit-chain integrity errors in 472k concurrent
rows). For the Tier 2 throughput envelope and the Postgres path, see
[Capacity planning](https://cullis.io/docs/operate/capacity-planning)
and [Postgres pilot](https://cullis.io/docs/operate/postgres-pilot).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `permission denied` on `./deploy.sh` | `chmod +x deploy.sh generate-proxy-env.sh` |
| `docker compose is not installed` | Install Docker Engine 20.10+ with Compose v2 |
| Browser warns "self-signed certificate" | Expected. Accept once, or import `./certs/org-ca.pem`. |
| Agent `401 Invalid DPoP proof: htu mismatch` | `MCP_PROXY_PROXY_PUBLIC_URL` in `proxy.env` must match the exact URL (scheme + host + port) agents reach the Mastio at. Fix it and `./deploy.sh --pull`. |
| Agent `SSL: CERTIFICATE_VERIFY_FAILED` / `hostname doesn't match` | Add the hostname to `MCP_PROXY_NGINX_SAN` (e.g. `mastio.acme.local,mastio.local,localhost`) and `./deploy.sh --pull` to re-mint the cert. |
| `getaddrinfo failed` / `Name or service not known` | The public-URL hostname must resolve to this host's IP from the agent's machine (corporate DNS, public A record, or `/etc/hosts`). |
| `Bind for 0.0.0.0:9443 failed: port is already allocated` | Set `MCP_PROXY_PORT=9444` in `proxy.env`, and update `MCP_PROXY_PROXY_PUBLIC_URL` to the same port. |
| `Refusing to boot` / `CA bootstrap is disabled (production default)` | First standalone `--prod` boot only: set `MCP_PROXY_ALLOW_CA_BOOTSTRAP=1` in `proxy.env`, then `./deploy.sh --prod` to mint the initial Org CA. Remove it after the first successful boot so a partial restore can't silently re-mint the CA and orphan enrolled agents. |

Full incident playbooks: [Runbook](https://cullis.io/docs/operate/runbook).

## Updating

```bash
./deploy.sh --upgrade-bundle 0.5.0   # or the alias: --upgrade 0.5.0
```

Downloads the released tarball, backs up `proxy.env` + `./data/` +
`./nginx-certs/` to `./backups/pre-upgrade-<ts>/`, extracts the new
scripts in place, bumps the image, and restarts. `./data/`,
`./nginx-certs/`, and `proxy.env` are preserved across every upgrade
path; Org CA and admin password persist. Image-only bump:
`./deploy.sh --pull`. Legacy named-volume migration and the step-by-step
fallback are documented at
[Apply updates](https://cullis.io/docs/operate/apply-updates).

## More

- [Install guide (full)](https://cullis.io/docs/install/mastio-bundle)
- [Configuration reference](https://cullis.io/docs/reference/configuration), every `MCP_PROXY_*` var
- [Kubernetes / Helm](https://cullis.io/docs/install/mastio-kubernetes)
- [Production hardening](https://cullis.io/docs/operate/runbook)
