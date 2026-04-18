---
title: "Migrating off /v1/auth/token direct login"
description: "How to move existing SPIFFE/BYOCA deployments from direct-to-Court login onto the ADR-011 unified enrollment path, with zero downtime."
category: "Identity"
order: 40
updated: "2026-04-18"
---

# Cullis — Migrating off the legacy direct-login path

Before ADR-011, Cullis supported three runtime auth paths:

1. SPIFFE workload API → direct login to the Court at `/v1/auth/token`
2. BYOCA (cert + key) → direct login to the Court
3. Connector / admin-token → API-key + DPoP via the Mastio (ADR-008 / F-B-11)

As of 2026-04-18, **path 3 is the only supported runtime**. Paths 1 and 2 continue to work but are marked deprecated; the Court's `/v1/auth/token` now returns `Deprecation: true` + `Sunset` headers on every 200, and emits `auth.token_issued` audit rows with `details.deprecated = true`. After the 90-day grace window the endpoint will return `410 Gone`.

This guide walks you through re-enrolling your existing SPIFFE / BYOCA agents against the new endpoints with **no downtime** — the legacy login keeps working throughout the migration.

---

## When you're done, you should have

- Every agent authenticating to its Mastio via API-key + DPoP (no direct calls to the Court)
- Zero `auth.token_issued` audit rows with `details.deprecated = true` on your Mastio's dashboard
- `CULLIS_ALLOW_LEGACY_AUTH_LOGIN=false` set on the Court (enforced from grace-period Phase B onwards)
- BYOCA and SPIFFE kept as **enrollment primitives** — you still use the same cert / SVID material; it just becomes the trust anchor at enrollment time rather than the credential on every call

---

## Step 1 — upgrade the Mastio

The Mastio needs the `/v1/admin/agents/enroll/{byoca,spiffe}` endpoints live. Any build tagged after 2026-04-18 includes them. Upgrade your Mastio first; the Court can stay on whatever release you were running.

```bash
# k8s example — bump the chart version on your values file:
helm upgrade cullis-proxy cullis-security/cullis-proxy \
  --values your-values.yaml \
  --set image.tag=<latest-2026-04-18-or-newer>
```

Once the Mastio is on the new build, `POST /v1/admin/agents/enroll/byoca` + `/spiffe` are available. Legacy `POST /v1/admin/agents` is unchanged.

---

## Step 2 — re-enroll each agent via the new endpoint

You keep the same cert/SVID material. The Mastio just verifies it differently.

### SPIFFE agents

```bash
# Operator machine, holds admin_secret + the workload's current SVID:
python -c "
from cullis_sdk import CullisClient
CullisClient.enroll_via_spiffe(
    'https://mastio.acme.corp',
    admin_secret='\$MASTIO_ADMIN_SECRET',
    agent_name='inventory-k8s',
    svid_pem=open('/tmp/svid.pem').read(),
    svid_key_pem=open('/tmp/svid-key.pem').read(),
    trust_bundle_pem=open('/tmp/spire-bundle.pem').read(),
    capabilities=['inventory.read', 'inventory.write'],
    persist_to='/etc/cullis/agent/inventory-k8s/',
)
"
```

The SDK writes `api-key`, `dpop.jwk`, `agent.json` under `persist_to`. Ship these to wherever the agent runs — your secret manager of choice (Vault KV, AWS Secrets Manager, K8s Secret, mounted volume) works fine because the material is per-agent and rotatable.

### BYOCA agents

```bash
python -c "
from cullis_sdk import CullisClient
CullisClient.enroll_via_byoca(
    'https://mastio.acme.corp',
    admin_secret='\$MASTIO_ADMIN_SECRET',
    agent_name='billing-bot',
    cert_pem=open('/tmp/agent.pem').read(),
    private_key_pem=open('/tmp/agent-key.pem').read(),
    capabilities=['billing.read'],
    persist_to='/etc/cullis/agent/billing-bot/',
)
"
```

Both helpers return `201` + the runtime credentials + a `dpop_jkt` the server has pinned. If the cert already carries a SPIFFE URI SAN, it lands on the `spiffe_id` column automatically.

---

## Step 3 — update the agent runtime

Swap the SDK call from `from_spiffe_workload_api` / `login_from_pem` to `from_api_key_file`.

**Before:**

```python
client = CullisClient.from_spiffe_workload_api(
    "https://court.cullis.corp",
    org_id="acme",
    socket_path="/run/spire/sockets/agent.sock",
)
```

**After:**

```python
client = CullisClient.from_api_key_file(
    "https://mastio.acme.corp",
    api_key_path="/etc/cullis/agent/inventory-k8s/api-key",
    dpop_key_path="/etc/cullis/agent/inventory-k8s/dpop.jwk",
)
```

The Mastio URL replaces the Court URL — agents no longer have a direct relationship with the Court; the Mastio forwards whatever crosses org boundaries and signs the counter-signature the Court expects.

---

## Step 4 — watch the deprecation counter go to zero

On the Court's audit dashboard, filter `event_type = auth.token_issued AND details.deprecated = true`. As you re-enroll agents, the counter per org trends down. When it hits zero, you're safe to flip `CULLIS_ALLOW_LEGACY_AUTH_LOGIN=false`.

Raw SQL on the Court if you prefer:

```sql
SELECT COUNT(*) FROM audit_log
 WHERE event_type = 'auth.token_issued'
   AND details::jsonb @> '{"deprecated": true}'
   AND timestamp > now() - interval '24 hours';
```

---

## Step 5 — enforce no-legacy

Once every agent has migrated and the audit counter is zero for a meaningful window (we suggest one deploy cycle, ~72h):

```bash
# On the Court, set in your values / env:
CULLIS_ALLOW_LEGACY_AUTH_LOGIN=false
```

The Court's `validate_config` will refuse to start in production if a non-empty org exists with unmigrated agents. Any remaining caller that hits `/v1/auth/token` now receives 403.

After the full grace window (at least 90 days from sunset advertisement), the endpoint starts returning `410 Gone` and calling code must have moved. At that point `from_spiffe_workload_api` and `login_from_pem` in the SDK also stop working.

---

## FAQ

**Do I need to rotate my certs / SVIDs?**
No. Enrollment uses the same material you already have — the Mastio verifies it once and derives a separate runtime credential. Your PKI policy doesn't change.

**Does the sandbox still demonstrate SPIFFE?**
Yes — the `enterprise_sandbox` bootstrap now enrolls every agent via `/enroll/byoca` (SPIRE stack stays in the compose but the agents don't hit `/v1/auth/token` anymore). You can use it as a reference topology. See the GUIDE in the sandbox repo.

**What if I'm running a Court-only deployment with no Mastio?**
The ADR-009 direction is: every deployment has a Mastio. For small topologies you can run a "thin Mastio" sidecar container next to the Court — footprint is one container + SQLite, no external deps. This is the same container operators use in large deployments; it just runs in standalone mode for tiny cases.

**Can I revert a migration?**
During the grace window, yes — the legacy login still works. After `CULLIS_ALLOW_LEGACY_AUTH_LOGIN=false`, no. After 410 Gone, no.

---

## See also

- [Agent enrollment — the four methods](enrollment.md)
- [Enrollment API reference](enrollment-api-reference.md)
- [SPIFFE onboarding](spiffe-onboarding.md) for deploying SPIRE alongside Cullis
