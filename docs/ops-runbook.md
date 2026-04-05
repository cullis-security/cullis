# Operations Runbook — Agent Trust Network

## Quick Reference

| Action | Command |
|--------|---------|
| Start all services | `docker compose up -d` |
| Stop all services | `docker compose down` |
| View broker logs | `docker compose logs -f broker` |
| Check health | `curl http://localhost:8000/healthz` |
| Check readiness | `curl http://localhost:8000/readyz` |
| Run DB migrations | `docker compose exec broker alembic upgrade head` |
| Backup database | See [Database Backup](#database-backup) |

---

## 1. First Deploy

### Prerequisites
- Docker Engine 24+ with Compose v2
- Domain name with DNS pointing to the server
- TLS certificate (Let's Encrypt or CA-issued)

### Steps

```bash
# 1. Clone and configure
git clone https://github.com/DaenAIHax/Agent-Trust-Network.git
cd Agent-Trust-Network
cp .env.example .env

# 2. Generate secrets
python3 -c "import secrets; print('ADMIN_SECRET=' + secrets.token_urlsafe(32))" >> .env
python3 -c "import secrets; print('DASHBOARD_SIGNING_KEY=' + secrets.token_urlsafe(32))" >> .env

# 3. Edit .env — set at minimum:
#    - ADMIN_SECRET (generated above)
#    - DASHBOARD_SIGNING_KEY (generated above)
#    - BROKER_PUBLIC_URL (your public URL)
#    - TRUST_DOMAIN (your domain)
#    - ALLOWED_ORIGINS (your frontend URLs)

# 4. Generate broker PKI
python3 generate_certs.py

# 5. Place TLS certs for Nginx
cp /path/to/fullchain.pem nginx/certs/server.pem
cp /path/to/privkey.pem nginx/certs/server-key.pem

# 6. Start
docker compose up -d

# 7. Verify
curl -k https://localhost:8443/healthz    # → {"status": "ok"}
curl -k https://localhost:8443/readyz     # → {"status": "ready", ...}
```

---

## 2. Updating

```bash
# Pull latest code
git pull origin main

# Rebuild and restart (zero-downtime with health checks)
docker compose build broker
docker compose up -d broker

# Run pending DB migrations
docker compose exec broker alembic upgrade head

# Verify
curl https://broker.yourcompany.com/readyz
```

---

## 3. Database Backup

### Manual backup
```bash
# Dump to file
docker compose exec postgres pg_dump -U atn agent_trust > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore from file
cat backup_20260405_120000.sql | docker compose exec -T postgres psql -U atn agent_trust
```

### Automated backup (cron)
```bash
# Add to crontab: daily at 3 AM
0 3 * * * cd /path/to/Agent-Trust-Network && docker compose exec -T postgres pg_dump -U atn agent_trust | gzip > /backups/atn_$(date +\%Y\%m\%d).sql.gz
```

### What to back up
- **PostgreSQL** — all broker state (agents, orgs, sessions, audit log, RFQ)
- **Vault data** — broker private keys (if using Vault KMS backend)
- **`.env`** — configuration secrets
- **`certs/`** — broker CA key and certificate

---

## 4. Key Rotation

### Broker CA key
The broker CA key signs all JWT access tokens. Rotation requires:
1. Generate new CA key pair
2. Store in Vault (or replace on disk)
3. Restart broker — new tokens signed with new key
4. Old tokens remain valid until expiry (30 min default)

### Agent certificate rotation
```bash
# Via API (the agent or its org calls this)
POST /v1/registry/agents/{agent_id}/rotate-cert
Authorization: DPoP <token>

# Via dashboard
# Navigate to Agents → click "Rotate Cert" on the agent row
```

### Dashboard signing key
Change `DASHBOARD_SIGNING_KEY` in `.env` and restart. All active dashboard sessions are invalidated (users must re-login).

---

## 5. Revoking an Agent

### Revoke certificate (preventive — blocks future logins)
```bash
# Via API
POST /v1/admin/certs/revoke
X-Admin-Secret: <admin_secret>
{"serial_number": "<cert serial>"}
```

### Revoke tokens (immediate — kills active sessions)
```bash
# Via API (org admin revokes their own agent)
POST /v1/auth/revoke-agent/{agent_id}
X-Org-Id: <org_id>
X-Org-Secret: <org_secret>
```

### Revoke binding (removes authorization)
```bash
POST /v1/registry/bindings/{binding_id}/revoke
X-Org-Id: <org_id>
X-Org-Secret: <org_secret>
```
This also closes all active sessions and disconnects WebSocket.

---

## 6. Monitoring

### Health endpoints
- `GET /healthz` — liveness probe (always 200 if the process is running)
- `GET /readyz` — readiness probe (checks DB + Redis + KMS)

### Jaeger traces
Access Jaeger UI at `http://localhost:16686` (or configure external Jaeger).

Key traces to monitor:
- `auth.issue_token` — authentication latency
- `auth.x509_verify` — certificate verification time
- `broker.create_session` — session creation flow
- `pdp.webhook_call` — policy evaluation latency

### Metrics (OpenTelemetry counters)
- `auth.success` / `auth.deny` — authentication attempts
- `session.created` / `session.denied` — session creation
- `policy.allow` / `policy.deny` — policy decisions
- `rate_limit.reject` — rate limit hits

### Log format
Set `LOG_FORMAT=json` in `.env` for structured logging (SIEM-ready):
```json
{"timestamp": "2026-04-05T12:00:00Z", "level": "INFO", "logger": "agent_trust", "message": "..."}
```

---

## 7. Audit Log

The audit log is append-only with a SHA-256 hash chain. No UPDATE or DELETE operations are allowed.

### Query via API
```bash
# Export as NDJSON (admin only)
GET /v1/admin/audit/export?format=ndjson&start=2026-04-01&end=2026-04-05
X-Admin-Secret: <admin_secret>

# Export as CSV
GET /v1/admin/audit/export?format=csv&org_id=acme&event_type=broker.session_created
```

### Verify hash chain integrity
```bash
# Via dashboard: Audit → "Verify Hash Chain" button (admin only)

# Via API
POST /dashboard/audit/verify
```

---

## 8. Troubleshooting

### Broker won't start
```bash
docker compose logs broker | tail -20
# Common issues:
# - "SECURITY: admin_secret is set to the default" → set ADMIN_SECRET in .env
# - "Cannot connect to PostgreSQL" → check postgres container is healthy
# - "Vault connection failed" → check VAULT_ADDR and VAULT_TOKEN
```

### Agent can't authenticate
1. Check certificate is signed by the org's CA: `openssl verify -CAfile org-ca.pem agent.pem`
2. Check binding is approved: `GET /v1/registry/bindings?org_id=<org>&agent_id=<agent>`
3. Check cert is not revoked: `GET /v1/admin/certs/revoked`
4. Check DPoP nonce: agent should retry on 401 with `use_dpop_nonce` error

### Session creation denied
1. Check policy backend: `POLICY_BACKEND` in `.env`
2. Check PDP webhook is reachable from broker container
3. Check audit log: `GET /v1/admin/audit/export?event_type=policy.session_denied`
4. Both orgs' PDPs must return `{"decision": "allow"}` (default-deny)

### WebSocket not connecting
1. Check Nginx config includes WebSocket proxy headers (`Upgrade`, `Connection`)
2. Check `BROKER_PUBLIC_URL` matches the URL the agent uses
3. Check Redis is running (cross-worker WS pub/sub requires Redis)

---

## 9. Production Checklist

Before going live, verify:

- [ ] `ADMIN_SECRET` is a strong random value (not the default)
- [ ] `DASHBOARD_SIGNING_KEY` is set
- [ ] `ALLOWED_ORIGINS` is set to specific origins (not `*`)
- [ ] `DATABASE_URL` points to PostgreSQL (not SQLite)
- [ ] `KMS_BACKEND=vault` with HTTPS Vault address
- [ ] `REQUIRE_SPIFFE_SAN=true`
- [ ] TLS certificates are real (not self-signed)
- [ ] `VAULT_ALLOW_HTTP` is NOT set
- [ ] Backup cron is configured
- [ ] `LOG_FORMAT=json` for log aggregation
- [ ] Rate limit buckets are tuned for expected load
- [ ] PDP webhooks are configured for all organizations
- [ ] Jaeger/OTLP endpoint is configured for trace collection
