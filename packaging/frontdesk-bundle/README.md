# Cullis Frontdesk — multi-user container bundle

Deploys Cullis Chat as a corporate web app, identity-aware via SSO. One container per N concurrent users, audit attributed per user. Implements ADR-019 rev 3 Phase 7.

```
[browser Mario] ──┐
[browser Anna]  ──┼─→ [nginx :8080] ──→ [Cullis Chat SPA] ──→ [Connector :7777, AMBASSADOR_MODE=shared]
[browser Luca]  ──┘     ↑                                        ↓ DPoP+mTLS, per-user keys via UserPrincipalKMS
                        SSO: oauth2-proxy + IDP                  ↓
                        injects X-Forwarded-User             [Cullis Mastio cloud]
```

## Prerequisites

1. **A reachable Mastio.** The Connector enrolls against it and forwards requests to its proxy + audit chain. Stand one up with `packaging/mastio-bundle/` if you do not already have one.
2. **An invite code** issued by your Mastio admin (`/v1/admin/invites` on the Mastio dashboard).
3. **Docker Compose v2.20+** for the bundle, plus the cullis-connector image (built once or pulled from `ghcr.io/cullis-security/cullis-connector`).

## One-shot enrollment

The bundle does not enroll the Connector for you. Run this once before `docker compose up`:

```bash
docker run --rm -it \
  -v $(pwd)/connector_data:/root/.cullis \
  ghcr.io/cullis-security/cullis-connector:latest \
  enroll \
    --site https://mastio.acme.local:9443 \
    --code <INVITE_CODE_FROM_MASTIO_ADMIN> \
    --profile frontdesk
```

This writes the cert + key + config to the local `connector_data/` directory. The bundle mounts that directory into the Connector container; subsequent `docker compose up` calls reuse the same identity.

If you wipe `connector_data/`, you must re-enroll.

## Bring the bundle up

```bash
cp frontdesk.env.example frontdesk.env
# Edit frontdesk.env: set CULLIS_FRONTDESK_ORG_ID and CULLIS_FRONTDESK_TRUST_DOMAIN
# to match what you registered on the Mastio.

docker compose --env-file frontdesk.env up -d
```

The bundle exposes nginx on the host port from `FRONTDESK_HTTP_PORT` (default `8080`).

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
docker compose down            # stop containers, keep connector_data volume
docker compose down -v         # also wipe connector_data (forces re-enrollment)
```

## Known limitations

- **No HTTPS in the bundle.** Production deployments terminate TLS at the corporate ingress (or at oauth2-proxy with a cert), upstream of nginx. The bundle binds `:80` on purpose.
- **No autoscale.** Single Connector replica per bundle; the cookie secret lives on local disk so horizontal scale needs a shared secret store. Roadmap.
- **Cookie secret rotation** is manual for now: stop the bundle, delete `connector_data/cookie.secret`, restart. Forces every browser to re-init the session, no security incident.
- **The bundle does not bundle the Mastio.** Cleanly separates concerns; deploy Mastio with `packaging/mastio-bundle/` and point this bundle at it.
