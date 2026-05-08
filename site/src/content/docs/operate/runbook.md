---
title: "Runbook"
description: "Incident response and day-to-day operations for a Mastio deployment — the failures most likely to wake you up, plus the commands you reach for without thinking."
category: "Operate"
order: 10
updated: "2026-04-23"
---

# Runbook

**Who this is for**: an operator running a Cullis Mastio in production (standalone or federated). Keep this page bookmarked.

## Quick reference

| Action | Command |
|---|---|
| Start all services | `docker compose up -d` |
| Stop all services | `docker compose down` |
| Tail Mastio logs | `docker compose logs -f proxy` |
| Tail Court logs (federated) | `docker compose logs -f broker` |
| Liveness | `curl -sk https://mastio.example.com/healthz` |
| Readiness | `curl -sk https://mastio.example.com/readyz` |
| Run DB migrations | `docker compose exec proxy alembic upgrade head` |
| Backup Postgres | `./scripts/pg-backup.sh` (see [Backups](#backups)) |
| Rotate signing key | See [Rotate keys](rotate-keys) |
| Apply framework update | See [Apply updates](apply-updates) |
| Export audit bundle | See [Audit export](audit-export) |

## Prerequisites

- Docker Engine ≥ 24 with Compose v2
- `curl`, `openssl`, `python3` on the host
- Admin secret available (in your password manager, not on disk)

## 1. Mastio is down

**Symptoms**

- `curl https://mastio.example.com/healthz` → connection refused or 5xx
- Dashboard unreachable, agents cannot mint DPoP-bound calls

**Confirm**

```bash
docker compose ps proxy
docker compose logs --tail=200 proxy
docker inspect --format '{{.State.ExitCode}} {{.State.Error}}' \
    $(docker compose ps -q proxy)
```

**Recover**

1. **Exit 3** (uvicorn told to shut down) — read the last `Waiting for application startup` log line; the failure on the next line is the real fault (Alembic, Vault, or Postgres).
2. **Exit 137** (OOM killed) — raise `deploy.resources.limits.memory` in `deploy/compose/docker-compose.prod.yml` and `docker compose up -d proxy`.
3. **Exit 1 / 2** (uncaught exception) — scan logs for the traceback. See sections 2–4 below for common root causes.
4. Restart: `docker compose restart proxy`.

**Verify**

- `/healthz` → 200
- `/readyz` → 200 (checks DB + Redis + Vault)
- `./sandbox/demo.sh mcp-catalog` completes if you have the sandbox handy

## 2. Postgres down or unreachable

**Symptoms**

- Mastio logs: `connection refused` on 5432 or `asyncpg.exceptions.ConnectionDoesNotExistError`
- Proxy container cycles between `unhealthy` and `starting`

**Confirm**

```bash
docker compose ps postgres
docker compose exec postgres pg_isready -U cullis -d cullis
docker compose logs --tail=100 postgres
```

**Recover**

1. **OOM / exited** — bump memory in `deploy/compose/docker-compose.prod.yml`, then `docker compose up -d postgres`.
2. **Disk full** — `df -h /var/lib/docker`. The `audit_log` table is append-only; archive rows older than N days to cold storage.
3. **Corruption** — restore from the most recent backup: `./scripts/pg-restore.sh <backup.sql.gz>`. Data loss window = last successful backup.

**Verify**

- `pg_isready` OK
- `docker compose restart proxy` if the connection pool went stale
- `./sandbox/demo.sh mcp-catalog` passes

**Prevent**

- Daily cron: `0 2 * * * ./scripts/pg-backup.sh`
- Monitor `pg_stat_activity.count` for connection leaks

## 3. Vault sealed or unreachable

**Symptoms**

- Mastio logs: `503 Service Unavailable` from Vault or `Vault is sealed`
- On boot: `RuntimeError: Vault secret at 'secret/data/mastio' missing field 'signing_key_pem'`
- Every DPoP token issuance returns 500

**Confirm**

```bash
docker compose exec vault vault status -address=https://127.0.0.1:8200
# Sealed: true → proceed
```

**Recover (sealed)**

```bash
./vault/init-vault.sh    # re-uses vault/vault-keys.json if present
# or manually, threshold 3 of 5:
docker compose exec vault \
    vault operator unseal -address=https://127.0.0.1:8200 <key1>
```

After unseal:

```bash
docker compose restart proxy
```

**Recover (scoped token expired, 30 day TTL)**

```bash
docker compose exec -e VAULT_TOKEN="$(jq -r .root_token vault/vault-keys.json)" vault \
    vault token create -policy=mastio-policy -ttl=720h -renewable -format=json \
    | jq -r .auth.client_token > vault/mastio-token

sed -i "s|^VAULT_TOKEN=.*|VAULT_TOKEN=$(cat vault/mastio-token)|" .env
docker compose up -d proxy
```

**Verify**

- `vault status` → `Sealed: false`
- Mastio `/healthz` → 200

**Prevent**

- Auto-unseal via cloud KMS (AWS KMS, GCP KMS) for teams; manual unseal is fine for a single-operator org.

## 4. Redis down

**Symptoms**

- Mastio logs: `redis.exceptions.ConnectionError` on DPoP replay checks
- DPoP tokens fall back to in-memory replay tracking (single-worker only); WebSocket cross-worker delivery breaks

**Confirm**

```bash
docker compose ps redis
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" ping
```

**Recover**

1. `docker compose restart redis`.
2. Password mismatch? Regenerate `.env` with `scripts/generate-env.sh --prod --force` (this rotates `POSTGRES_PASSWORD` too — back up first).

**Data loss expectations**

Redis is ephemeral. The DPoP JTI blacklist and rate-limit counters rebuild as traffic returns. Nothing permanent is lost.

## 5. TLS cert expired

**Symptoms**

- External clients: `SSL_ERROR_CERT_DATE_INVALID`
- `openssl s_client -connect mastio.example.com:443 </dev/null | openssl x509 -noout -dates` → `notAfter` in the past

**Recover**

- **ACME**: `./deploy_broker.sh --prod-acme --domain X --email Y` re-runs certbot; nginx reloads automatically.
- **BYOCA**: drop the new cert + key in `nginx/certs/`, then `docker compose exec nginx nginx -s reload`.

**Prevent**

- ACME: install the renewal cron the deploy script prints after first run.
- BYOCA: alert 30 days before `notAfter`, rotate with 14 days to spare.

## 6. Revoke everything for a compromised org

**Symptoms**

Internal report or threat intel says org `X` is compromised. Goal: kill all of X's agents without taking the Court down.

**Recover**

```bash
ADMIN="demo-admin-secret-change-me"
COURT="https://court.example.com"
ORG="compromised-org"

# 1. List X's agents
curl -s -H "x-admin-secret: $ADMIN" "$COURT/v1/federation/agents?org_id=$ORG" | jq

# 2. Revoke each agent cert
for serial in $(curl ... | jq -r '.[].cert_thumbprint'); do
    curl -X POST -H "x-admin-secret: $ADMIN" -H "Content-Type: application/json" \
         -d "{\"serial_hex\":\"$serial\",\"org_id\":\"$ORG\",\"reason\":\"compromise\"}" \
         "$COURT/v1/admin/certs/revoke"
done

# 3. Revoke every binding
for bid in $(curl ... | jq -r '.[].binding_id'); do
    curl -X POST -H "x-org-id: $ORG" -H "x-org-secret: $ORG_SECRET" \
         "$COURT/v1/registry/bindings/$bid/revoke"
done
```

Existing JWTs stay valid until their 15-minute TTL expires. Cert thumbprint revocation kicks in on the next session open.

**Verify**

- `curl ... /v1/auth/token` → 401 `Certificate has been revoked`
- Sandbox smoke phases 3 (revoked cert) and 4 (revoked binding) exercise this path end-to-end — run `./sandbox/smoke.sh full` on a staging copy to rehearse.

## 7. Admin lockout

**Symptoms**

- Dashboard rejects the known password
- `/v1/admin/*` endpoints return 403

**Recover**

`ADMIN_SECRET` is stored as a bcrypt hash in Vault after first boot. Reset the hash, then the Mastio re-bootstraps from the `ADMIN_SECRET` env on next boot.

```bash
docker compose exec -e VAULT_TOKEN="$(jq -r .root_token vault/vault-keys.json)" vault \
    vault kv patch secret/mastio admin_secret_hash=""

# Rotate .env
NEW="$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)"
sed -i "s|^ADMIN_SECRET=.*|ADMIN_SECRET=$NEW|" .env
docker compose up -d proxy
echo "New admin secret: $NEW"
```

**Verify**

- Dashboard login with the new secret → 200
- `/v1/admin/orgs` with the new `x-admin-secret` → 200

## 8. "It just doesn't work" — blanket triage

When the symptoms don't match anything above:

```bash
# 1. Full state snapshot
docker compose ps -a
docker compose logs --tail=50 proxy postgres redis vault

# 2. Quick smoke
curl -sk https://mastio.example.com/healthz
curl -sk https://mastio.example.com/readyz
curl -sk -H "x-admin-secret: $ADMIN_SECRET" \
    https://mastio.example.com/v1/admin/mcp-resources

# 3. Sandbox smoke to rule out code regression
./sandbox/smoke.sh full
# smoke PASS + prod FAIL → environment or config
# smoke FAIL → regression; bisect vs. last green commit
```

## Monitoring

**Health endpoints**

- `GET /healthz` — liveness (200 if the process is up)
- `GET /readyz` — readiness (DB + Redis + KMS)

**Metrics (OpenTelemetry counters)**

- `auth.success` / `auth.deny`
- `session.created` / `session.denied`
- `policy.allow` / `policy.deny`
- `rate_limit.reject`
- `updates.sign_halt` (framework update boot detector; see [Apply updates](apply-updates))

**Logs**

Set `LOG_FORMAT=json` in `.env` for SIEM-ready structured logging.

## Backups

| What | How often | Where |
|---|---|---|
| Postgres dump | Daily | `./scripts/pg-backup.sh` → offsite |
| Vault unseal keys | On init | Password manager + cold storage (not on the Mastio host) |
| `.env` | On regen | Secrets manager (holds ADMIN_SECRET, POSTGRES_PASSWORD, REDIS_PASSWORD, VAULT_TOKEN) |
| Org CA keys | On org onboard | Each org's operator owns this, not the Court |
| Mastio signing key | In Vault | Vault backup = key backup |

Run a quarterly DR drill: restore Postgres + Vault into a staging compose, run `./sandbox/smoke.sh full` against it. If smoke passes, your recovery works.

## Troubleshoot

**`Invalid DPoP proof: htu mismatch` 401s after deploy**
: `MCP_PROXY_PROXY_PUBLIC_URL` in `proxy.env` doesn't match the URL clients actually use. The DPoP proof carries the client's URL; the Mastio compares it to its configured public URL. Check with `docker compose exec proxy env | grep PROXY_PUBLIC_URL` and `curl -kvI https://mastio.example.com/healthz 2>&1 | grep Host`. The Mastio also logs both values on mismatch.

**Self-signed cert rejected**
: All SDKs refuse self-signed certs. The Python SDK exposes `verify_tls=False` **only** for `--dev` localhost demos. Never set it in production.

**WebSocket not connecting**
: Ensure the nginx config includes WebSocket proxy headers (`Upgrade`, `Connection`). Confirm `PROXY_PUBLIC_URL` matches the URL the Connector uses. Redis must be up (cross-worker WS pub/sub depends on it).

## Next

- [Rotate keys](rotate-keys) — signing-key rotation without downtime
- [Apply updates](apply-updates) — framework updates with boot-time detector + sign halt
- [Audit export](audit-export) — hash chain, TSA bundle, CLI verifier
- [Migration from direct login](../reference/migration-from-direct-login) — moving legacy SPIFFE/BYOCA deployments onto ADR-011
