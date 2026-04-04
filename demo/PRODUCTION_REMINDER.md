# Production Reminder — Things disabled/relaxed for the demo

These changes were made to run the demo on localhost without the full
Docker Compose stack. **All must be reverted for production deployment.**

## 1. Cookie secure flag (DISABLED on HTTP)

**File:** `app/dashboard/session.py`
**Change:** `secure=True` is now conditional — only enabled when `BROKER_PUBLIC_URL` contains "https".
**Why:** Browsers refuse to store `secure` cookies over plain HTTP (localhost:8000).
**Production:** Set `BROKER_PUBLIC_URL=https://broker.yourdomain.com` in `.env`. The cookie will automatically use `secure=True`.

## 2. PDP Webhook skip when not configured (ALLOW instead of DENY)

**File:** `app/policy/webhook.py`
**Change:** If an org has no `webhook_url`, the PDP check returns ALLOW instead of DENY.
**Why:** The demo doesn't run mock PDP servers. Without this change, every session request is blocked.
**Production:** Every org MUST have a PDP webhook configured. To restore strict default-deny, revert line ~60 in `webhook.py`:
```python
# Change this (demo):
return WebhookDecision(allowed=True, reason="...skipped", org_id=org_id)

# Back to this (production):
return WebhookDecision(allowed=False, reason="...no PDP webhook configured", org_id=org_id)
```
Or better: ensure all orgs have a webhook URL set during onboarding.

## 3. Services not running in demo

| Service | Demo | Production |
|---------|------|------------|
| Broker | `./run.sh` (uvicorn direct) | Docker container behind reverse proxy (HTTPS) |
| PostgreSQL | Docker container | Docker container or managed DB |
| Redis | Not running (in-memory fallback) | Required for multi-worker (DPoP JTI, rate limit, WebSocket pub/sub) |
| Vault | Not running (local KMS) | Required (broker signing key in Vault, not on disk) |
| Mock PDP | Not running (skipped) | Each org runs their own PDP webhook |
| Reverse proxy | None | nginx/traefik with TLS termination |

## 4. Badge log silencing

**File:** `app/main.py`
**Change:** Added `_QuietBadgeFilter` to suppress `/dashboard/badge/` polling from uvicorn access log.
**Production:** Keep this — it's just log noise reduction, no security impact.
