---
title: "Operations runbook"
description: "Incident response for the six failures most likely to wake you up."
category: "Operations"
order: 20
updated: "2026-04-12"
---

# Cullis — Operations Runbook

Incident response for the six failures most likely to wake you up. Every
section follows the same shape: what you'll see, how to confirm, the
minimum steps to recover, and what to verify after.

> This runbook assumes a production deploy via `./deploy_broker.sh --prod-*`.
> For proxy incidents, the proxy operator runs through the proxy-specific
> section.

---

## 1. Broker is down

### Symptoms
- `curl https://broker.example.com/health` → connection refused / 5xx.
- Dashboard unreachable. Agents cannot get fresh JWTs → all agent→agent
  messaging stops within the token TTL (~15 min).

### Confirm
```
docker compose ps broker                     # status column
docker compose logs --tail=200 broker        # last 200 lines
docker inspect --format '{{.State.ExitCode}} {{.State.Error}}' $(docker compose ps -q broker)
```

### Recover
1. If **Exit 3**: uvicorn was told to shut down. Check logs for the last
   "Waiting for application startup" line — what came right after is the
   real fault (Alembic, Vault, Postgres).
2. If **Exit 137**: OOM killed. Bump memory in `docker-compose.prod.yml`
   under `deploy.resources.limits.memory` and `docker compose up -d`.
3. If **Exit 1 / 2** (uncaught exception): look for traceback in logs.
   Common causes below.
4. Restart: `docker compose -f docker-compose.yml -f docker-compose.prod.yml restart broker`.

### Verify
- `/health` returns 200.
- `/readyz` returns 200 (checks DB + Redis + Vault).
- Smoke test one agent login.

---

## 2. Postgres down or unreachable

### Symptoms
- Broker logs: `connection refused` on port 5432 or `asyncpg.exceptions.ConnectionDoesNotExistError`.
- Broker container cycles between `unhealthy` and `starting` (depends-on
  healthcheck fails).

### Confirm
```
docker compose ps postgres
docker compose exec postgres pg_isready -U atn -d agent_trust
docker compose logs --tail=100 postgres
```

### Recover
1. If Postgres container **OOM / exited**: increase memory in
   `docker-compose.prod.yml`, then `docker compose up -d postgres`.
2. If **disk full**: `df -h /var/lib/docker`. Rotate/compress old audit
   rows (`audit_log` is append-only; safe to archive rows older than N
   days to cold storage).
3. If Postgres **won't start** (corruption): restore from backup —
   `scripts/pg-restore.sh <backup.sql.gz>`. Data loss window = last
   successful backup timestamp.

### Verify
- `pg_isready` OK.
- Broker reconnects automatically (asyncpg has retry). If not,
  `docker compose restart broker` clears stale pool.
- Smoke PASS: `./demo_network/smoke.sh full`.

### Prevent
- Daily cron: `0 2 * * * ./scripts/pg-backup.sh`.
- Monitor `pg_stat_activity.count` — spikes indicate leaking connections.

---

## 3. Vault sealed or unreachable

### Symptoms
- Broker logs: `503 Service Unavailable` from Vault, or `Vault is sealed`.
- On broker startup: `RuntimeError: Vault secret at 'secret/data/broker' missing field 'private_key_pem'` — broker keys unreadable.
- JWT signing fails → every agent login returns 500.

### Confirm
```
docker compose exec vault vault status -address=https://127.0.0.1:8200
# Sealed? → status shows "Sealed: true"
```

### Recover (sealed)
```
./vault/init-vault.sh                        # re-uses vault/vault-keys.json
# or manually:
docker compose exec vault vault operator unseal -address=https://127.0.0.1:8200 <key1>
# repeat for key2, key3 (threshold 3 of 5)
```

After unseal, restart the broker so it re-authenticates with the scoped
token that should still be valid (30d TTL):
```
docker compose -f docker-compose.yml -f docker-compose.prod.yml restart broker
```

### Recover (scoped token expired)
```
# Using root token from vault/vault-keys.json (one-time, then revoke):
docker compose exec -e VAULT_TOKEN="$(jq -r .root_token vault/vault-keys.json)" vault \
    vault token create -policy=broker-policy -ttl=720h -renewable -format=json \
    | jq -r .auth.client_token > vault/broker-token

sed -i "s|^VAULT_TOKEN=.*|VAULT_TOKEN=$(cat vault/broker-token)|" .env
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d broker
```

### Verify
- `vault status` shows `Sealed: false`.
- Broker `/health` returns 200.

### Prevent
- Vault auto-unseal via cloud KMS (AWS KMS / GCP KMS) in production —
  manual unseal is fine for a single-operator org, hostile for a team.

---

## 4. Redis down

### Symptoms
- Broker logs: `redis.exceptions.ConnectionError` on DPoP replay checks
  or WebSocket pub/sub.
- DPoP tokens may be replay-able within the broker's in-memory fallback
  window (low risk; single-worker) but WebSocket cross-worker delivery
  breaks.

### Confirm
```
docker compose ps redis
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" ping
```

### Recover
1. Restart: `docker compose restart redis`.
2. If password mismatch in logs: `.env` REDIS_PASSWORD doesn't match the
   one Redis boots with. Regenerate with `scripts/generate-env.sh --prod --force`
   (note: will rotate POSTGRES_PASSWORD too — back up DB first).

### Verify
- `redis-cli ping` returns PONG.
- Broker logs stop emitting ConnectionError.

### Data loss expectations
Redis is ephemeral — DPoP JTI blacklist and rate-limit counters are
rebuilt as traffic comes in. Nothing permanent is lost.

---

## 5. TLS cert expired (broker public URL)

### Symptoms
- All external clients: `SSL_ERROR_CERT_DATE_INVALID`.
- Agents: `certificate has expired` in logs.
- `openssl s_client -connect broker.example.com:443 </dev/null | openssl x509 -noout -dates`
  → notAfter date in the past.

### Recover
- **ACME**: `./deploy_broker.sh --prod-acme --domain X --email Y` re-runs
  certbot. The nginx container reloads automatically.
- **BYOCA**: get a fresh cert from your CA, drop it in `nginx/certs/`,
  then `docker compose exec nginx nginx -s reload`.

### Prevent
- ACME: add renewal cron from `deploy_broker.sh` output (printed after
  first `--prod-acme` run).
- BYOCA: monitor `notAfter` 30 days ahead; rotate before 14 days.

---

## 6. Agent compromise — revoke everything for one org

### Symptoms
- Threat intel / internal report that org X is compromised.
- Goal: invalidate all of X's agents without taking the whole broker down.

### Recover
```
ADMIN="demo-admin-secret-change-me"   # from .env
BROKER="https://broker.example.com"
ORG="compromised-org"

# 1. List X's agents
curl -s -H "x-admin-secret: $ADMIN" "$BROKER/v1/federation/agents?org_id=$ORG" | jq

# 2. Revoke each agent's cert (serial_hex from the listing)
for serial in $(curl ... | jq -r '.[].cert_thumbprint'); do
    curl -X POST -H "x-admin-secret: $ADMIN" -H "Content-Type: application/json" \
         -d "{\"serial_hex\":\"$serial\",\"org_id\":\"$ORG\",\"reason\":\"compromise\"}" \
         "$BROKER/v1/admin/certs/revoke"
done

# 3. Revoke every binding in X
for bid in $(curl ... | jq -r '.[].binding_id'); do
    curl -X POST -H "x-org-id: $ORG" -H "x-org-secret: $ORG_SECRET" \
         "$BROKER/v1/registry/bindings/$bid/revoke"
done

# 4. Optional: flip org status to "suspended" via dashboard (Orgs → Suspend).
```

Any existing JWT for X is still valid until its 15-min TTL expires, but
cert thumbprint revocation kicks in on the next session open.

### Verify
- Smoke's phase 3 (revoked cert → 401) and phase 4 (revoked binding → 403)
  prove the protocol works. Run a manual check:
  ```
  curl -s ... /v1/auth/token  → expect 401 "Certificate has been revoked"
  ```

---

## 7. Admin lockout (forgot ADMIN_SECRET)

### Symptoms
- Dashboard login rejects known password.
- `/v1/admin/*` endpoints return 403.

### Recover
`ADMIN_SECRET` is stored **as a bcrypt hash in Vault** after first boot.
You can either:

**a) Reset the hash directly in Vault** (requires root token):
```
docker compose exec -e VAULT_TOKEN="$(jq -r .root_token vault/vault-keys.json)" vault \
    vault kv patch secret/broker admin_secret_hash=""
docker compose restart broker
```
Broker re-bootstraps from `ADMIN_SECRET` env on next boot.

**b) Rotate .env and restart**:
```
NEW="$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)"
sed -i "s|^ADMIN_SECRET=.*|ADMIN_SECRET=$NEW|" .env
# Also clear the stored hash as in (a)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d broker
echo "New admin secret: $NEW"
```

### Verify
- Dashboard login with new secret → 200.
- `/v1/admin/orgs` with new `x-admin-secret` header → 200.

---

## 8. "It just doesn't work" — blanket triage

When symptoms don't match any above:

```
# 1. Full state snapshot
docker compose ps -a
docker compose logs --tail=50 broker postgres redis vault

# 2. Quick smoke against a running broker
curl -sk https://broker.example.com/health
curl -sk https://broker.example.com/readyz
curl -sk -H "x-admin-secret: $ADMIN_SECRET" https://broker.example.com/v1/registry/orgs

# 3. If anything above fails, run the demo_network smoke to rule out code bugs
cd demo_network && ./smoke.sh full
# If smoke PASSES but prod FAILS → environment/config issue.
# If smoke FAILS → code regression; bisect vs last green commit.
```

---

## Backups — what to save

| What | How often | Where |
|---|---|---|
| Postgres dump | Daily | `./scripts/pg-backup.sh` → S3/offsite |
| Vault unseal keys | On init | Password manager + cold storage (NOT on the broker host) |
| `vault/broker-token` | On rotation | Secrets manager (rotate yearly) |
| `.env` | On regen | Secrets manager (contains ADMIN_SECRET, POSTGRES_PASSWORD, REDIS_PASSWORD, VAULT_TOKEN) |
| Org CA keys (per-org) | On org onboard | Each org is responsible (out-of-band to the broker operator) |
| Broker signing key | Stored in Vault | Vault backup = backup of the key |

A good quarterly drill: restore Postgres + Vault from backup into a
staging compose, re-run the smoke test against it. If smoke passes, DR
works.
