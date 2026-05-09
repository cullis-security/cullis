# Cullis Frontdesk — multi-user container bundle

Deploys Cullis Chat as a corporate web app, identity-aware. One container per N concurrent users, audit attributed per user. Implements ADR-019 rev 3 Phase 7 + ADR-025 dual-mode auth.

## Auth mode (default: ADR-025 local)

By default the bundle ships **ADR-025 `AUTH_MODE=local`**: the SPA serves a real `/login` form backed by a `users.db` (bcrypt hashed); the admin pre-creates accounts via `POST /admin/users` with `X-Admin-Secret`; each post-login session mints a per-user UserPrincipal cert at the sibling Mastio. Audit chain shows the actual employee, not a shared placeholder.

```
[browser Mario] ──┐
[browser Anna]  ──┼─→ [nginx :8080] ──→ [Cullis Chat SPA] ──→ [Connector :7777, AUTH_MODE=local]
[browser Luca]  ──┘     ↑                                        ↓ DPoP+mTLS, per-user UserPrincipal cert
                        /login form (real bcrypt auth)            ↓
                        admin provisions via /admin/users    [Cullis Mastio]
```

**Legacy shared-mode SSO** (pre-v0.2.0): set `AMBASSADOR_MODE=shared` in `frontdesk.env` to fall back to the `X-Forwarded-User` injection pattern. Kept for back-compat with existing deploys; new deploys should prefer `AUTH_MODE=local` or wire OIDC delegation upstream of the bundle (oauth2-proxy + corporate IdP).

## Prerequisites

1. **A reachable Mastio.** The Connector enrolls against it and forwards requests to its proxy + audit chain. Stand one up with `packaging/mastio-bundle/` if you do not already have one. The sibling bundle exports its CA to `../cullis-mastio-bundle/certs/org-ca.pem` when extracted from the release tarball, or `../mastio-bundle/certs/org-ca.pem` when running out of a repo checkout — `./deploy.sh` here picks up either automatically.
2. **A Mastio admin who can approve enrollments**. The Connector posts a pending row to `/v1/enrollment/start`; the admin approves it from `Mastio dashboard → Enrollments`. There is no pre-minted invite token — this is a device-code flow.
3. **A Mastio CA bundle PEM** on the host machine. Auto-detected at `../cullis-mastio-bundle/certs/` (release tarball) or `../mastio-bundle/certs/` (repo); otherwise set `CULLIS_FRONTDESK_CA_BUNDLE_HOST` in `frontdesk.env`.
4. **Docker Compose v2.20+**. The bundle pulls all three images from `ghcr.io`; no repo checkout or `docker build` required.

## Quickstart (deploy.sh)

```bash
./deploy.sh
```

That single command:

1. Generates `frontdesk.env` with sensible same-host defaults if it doesn't exist (auto-detecting the Mastio CA path).
2. Generates a sensible requester identity (`frontdesk@<trust-domain>`) and the Mastio site URL (defaults to `https://host.docker.internal:9443` for the same-host topology).
3. Runs the device-code enrollment via a throwaway `cullis-connector` container. The container blocks until the Mastio admin approves the pending row at `/proxy/enrollments`; the script prints the URL where to click. Identity material lands in `./connector_data/`.
4. `docker compose up -d` and waits until `http://localhost:8080` answers.
5. Prints the SPA URL and a fake-SSO smoke test command.

Re-runs are idempotent: if `connector_data/profiles/<profile>/identity/metadata.json` exists, the enrollment step is skipped.

### Non-interactive

```bash
# Override requester identity + site URL:
./deploy.sh --requester-email ops@acme.local --site https://mastio.acme.local:9443

# Already enrolled out-of-band, just bring the stack up:
./deploy.sh --skip-enroll

# Production: requires a pre-provisioned frontdesk.env with real values
./deploy.sh --prod
```

### Manual generate (no deploy)

```bash
./generate-frontdesk-env.sh --interactive   # prompts for ORG_ID, trust domain, CA path
./generate-frontdesk-env.sh --defaults      # same-host defaults, no prompts
./generate-frontdesk-env.sh --prod          # validates env vars, fails fast
```

The bundle exposes nginx on the host port from `FRONTDESK_HTTP_PORT` (default `8080`).

### Image versions

The compose file pins sensible defaults via env vars:

| Variable | Default | Image |
|---|---|---|
| `CONNECTOR_VERSION` | `0.4.0-rc1` | `ghcr.io/cullis-security/cullis-connector` |
| `CHAT_VERSION`      | `0.1.0-rc1` | `ghcr.io/cullis-security/cullis-chat-frontdesk` |

Pin both in production via `frontdesk.env` rather than relying on the defaults shipped with the bundle.

## Smoke test (dev fake-SSO)

The dev nginx (`nginx/default.conf`) reads a `?user=` query string the first time you load the page, maps it to a fake email, and injects `X-Forwarded-User`. Three demo users are pre-mapped: `mario`, `anna`, `luca`.

```bash
# Terminal 1: tail Connector logs while you click around.
docker compose logs -f connector

# Browser tab A:
open http://localhost:8080?user=mario   # establishes the cullis_session cookie
                                         # and the badge shows "user · mario"

# Browser tab B (incognito so the cookie is fresh):
open http://localhost:8080?user=anna   # different cookie, different audit attribution
```

Each chat message is signed by a per-user agent key (provisioned via `UserPrincipalKMS`, ADR-021 PR4a) and lands in Mastio's audit chain attributed to `acme.test/acme/user/mario` (or `…/anna`). The two tabs never see each other's history.

## Verify per-user audit attribution

After running a chat in tab A and another in tab B, open the Mastio dashboard's audit log. Filter by `principal_type=user`. You should see one row per chat message, with the `principal_id` matching the user that sent it.

If both rows show the same principal, the `X-Forwarded-User` header is not reaching the Ambassador. Common causes:

| Symptom | Likely cause |
|---|---|
| Connector logs `untrusted proxy IP` | The docker bridge CIDR your host hands out is not in `CULLIS_TRUSTED_PROXIES`. Adjust the env var. |
| Both users land as `unknown@frontdesk.dev` | nginx is not seeing the `?user=` query (it only triggers on the cookie-mint path). Open in incognito so each tab starts cookie-less. |
| 502 from nginx | Connector cannot reach the Mastio. Check enrollment is good (`docker compose exec connector cullis-connector doctor`). |

## Production: replace nginx with oauth2-proxy + IDP

`nginx/default.conf` is dev-grade. The contracts the rest of the bundle relies on are exactly two:

1. **Every** request reaching the SPA / Ambassador carries `X-Forwarded-User` set to the authenticated user (email or sub).
2. The reverse proxy's source IP is in `CULLIS_TRUSTED_PROXIES` on the Connector.

Any reverse proxy that performs SSO and injects that header works: oauth2-proxy + Dex, Keycloak gatekeeper, Istio with JWT, EnvoyAuthZ, AWS ALB with OIDC, Azure App Gateway with EntraID. The nginx config in this bundle exists only so a developer can dogfood the multi-user flow without standing up a full IDP.

For oauth2-proxy specifically, the upstream config `--pass-user-headers=true` is what injects the header. Point oauth2-proxy at the Cullis Chat container (`cullis-chat:4321`) and route `/api/session/(init|logout)` directly to the Connector (`connector:7777`), exactly like the dev nginx does.

## Tear down

```bash
./deploy.sh --down             # stop containers, keep connector_data
docker compose --env-file frontdesk.env down -v   # also wipe connector_data (forces re-enrollment)
```

## Threat model & exposure

The Frontdesk bundle serves **plain HTTP** on `:80` inside the
container. By default the host port (`8080`) is bound to **`127.0.0.1`
only**, not `0.0.0.0`. Three exposure modes:

| Mode | Bind | Where Frontdesk is reachable | Coherent with Cullis threat model? |
|------|------|------------------------------|------------------------------------|
| Default (dogfood, single-user) | `127.0.0.1:8080` | The host's own browser only | Yes. Localhost is a W3C "secure context" — SPA crypto, Secure cookies, Service Workers all behave as on HTTPS. |
| LAN multi-user, no TLS | `0.0.0.0:8080` | Any host on the LAN, plain HTTP | **No.** Session cookie + DPoP proofs travel cleartext. A coworker on the same office network can intercept and replay. Not "zero-trust fabric for AI agents" if the SPA-to-Connector hop isn't authenticated. |
| LAN / internet, with TLS terminator | `0.0.0.0:8080` (or `127.0.0.1` if terminator is on the same host) | The terminator's HTTPS port | Yes. Pattern: `Browser → HTTPS → terminator → :8080 (loopback or LAN) → cullis-chat`. Recommended for any deploy with more than one user. |

To expose Frontdesk over the LAN or the internet, override the bind:

```bash
# In frontdesk.env
FRONTDESK_HTTP_BIND=0.0.0.0
FRONTDESK_HTTP_PORT=8080
```

…AND put a TLS terminator in front. Below are three minimal recipes.

### oauth2-proxy + corporate IdP

```bash
# Terminator on the same host as the bundle. oauth2-proxy authenticates
# the user against your IdP, terminates TLS, and forwards to the bundle.
docker run -d --name oauth2-proxy \
  -p 443:4180 \
  -v $PWD/oauth2-proxy.cfg:/etc/oauth2-proxy.cfg:ro \
  -v $PWD/tls.crt:/etc/tls.crt:ro -v $PWD/tls.key:/etc/tls.key:ro \
  quay.io/oauth2-proxy/oauth2-proxy:latest \
    --config=/etc/oauth2-proxy.cfg \
    --upstream=http://127.0.0.1:8080 \
    --tls-cert-file=/etc/tls.crt --tls-key-file=/etc/tls.key
```

### Caddy with auto-Let's Encrypt

```caddyfile
frontdesk.acme.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Traefik label on the bundle's docker-compose

Add a labels block under the `nginx` service in
`docker-compose.override.yml`:

```yaml
services:
  nginx:
    labels:
      traefik.enable: "true"
      traefik.http.routers.frontdesk.rule: "Host(`frontdesk.acme.example.com`)"
      traefik.http.routers.frontdesk.tls.certresolver: "acme"
```

If you bind `0.0.0.0:8080` without one of the above, you have just put
plain-HTTP user-principal authentication on a multi-user network. The
``zero-trust fabric`` tagline does not survive that. Pick a path.

A ``--with-tls-sidecar`` option that bakes a self-signed cert + nginx
TLS terminator into the bundle (the same pattern Mastio's
``mastio-nginx`` uses) is on the roadmap as ADR-024 — track that ADR
draft for the design discussion.

## Known limitations

- **No autoscale.** Single Connector replica per bundle; the cookie secret lives on local disk so horizontal scale needs a shared secret store. Roadmap.
- **Cookie secret rotation** is manual for now: stop the bundle, delete `connector_data/cookie.secret`, restart. Forces every browser to re-init the session, no security incident.
- **The bundle does not bundle the Mastio.** Cleanly separates concerns; deploy Mastio with `packaging/mastio-bundle/` and point this bundle at it.
