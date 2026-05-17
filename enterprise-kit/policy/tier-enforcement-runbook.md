# Tier-enforcement runbook (ADR-032 F5)

> Audience: customer CISO / IT admin rolling out device-tier policy on
> a Cullis Mastio deployment. Assumes the Cullis Mastio image is
> already running (open-core or enterprise edition; both gate the
> same way).
> Status: Mastio v0.4.x — F5 in production, hot-reload deferred.

## What this runbook covers

- The 5-tier capability ladder shipped in Mastio v0.4.x
- How to read the default tier matrix Cullis ships
- How to author your own `capability-tiers.yaml` for stricter org policy
- How to roll out the gate progressively (audit-only → enforce)
- How to verify enforcement via audit-log queries
- The env vars that affect enforcement
- The reload procedure when the matrix changes

## The tier ladder

Five orderable tiers, from least to most trusted. Ordering is
strict: a capability requiring `managed` accepts `managed` and
`managed_attested` callers, denies the rest.

| Tier | Composition | Typical principal |
|---|---|---|
| `untrusted` | No MDM AND attestation_strength=soft_only | Connector laptop with no enrollment, no hardware key |
| `byod_isolated` | No MDM AND attestation_strength=hw_isolated | macOS BYOD with Secure Enclave but no MDM |
| `byod_attested` | No MDM AND attestation_strength=hw_attested | Linux/Windows BYOD with TPM 2.0 attestation |
| `managed` | MDM-managed (compliant) AND any strength | Intune-enrolled corporate laptop |
| `managed_attested` | MDM-managed (compliant) AND hw_attested | Defence-in-depth: corp laptop + TPM key |

A macOS BYOD CANNOT exceed `byod_isolated` even with Secure Enclave
key isolation; reaching `managed` requires MDM enrollment
(Jamf, Kandji, or Intune for Mac). See ADR-032 Decision B for the
rationale.

## Default matrix shipped

Cullis ships [`enterprise-kit/policy/capability-tiers.yaml`](capability-tiers.yaml)
as the default. The matrix lives in the bundle so a fresh
deployment has a working baseline without authoring anything.

The shape (see `mcp_proxy/policy/tier_matrix.py:138-234` for the
loader):

```yaml
version: "1.0"
default_min_tier: untrusted

capabilities:
  mcp.read_public:
    min_tier: untrusted
    description: "Public information, no sensitive data"

  mcp.read_customer_db:
    min_tier: managed
    description: "Customer database read"

  mcp.transfer_money:
    min_tier: managed_attested
    description: "Outbound financial transaction"

  "admin.*":
    min_tier: managed_attested
    description: "Admin operations (wildcard match)"
```

Three rules to know:

- Capabilities not listed default to `default_min_tier`.
- Names ending in `.*` are prefix wildcards. `admin.*` matches
  `admin.read` but not `adminstuff` (the trailing dot is required).
- More specific entries win. `admin.read` defined as `managed`
  overrides an `admin.*` rule set to `managed_attested`.

The shipped default keeps high-risk capabilities (`mcp.transfer_money`,
`admin.*`) at `managed_attested` from day one. If your fleet hasn't
reached that tier yet, lower those entries explicitly in your
override (see next section) — the alternative is silent denies.

## Authoring your org matrix

Copy the default, edit it, mount it into the Mastio container at
the same path, and point the process at it. Keeping the override
in your config repo lets `git diff` show every policy change.

1. Copy the bundled file:

   ```bash
   cp enterprise-kit/policy/capability-tiers.yaml \
      /etc/cullis/capability-tiers.yaml
   ```

2. Edit it. Examples covering the four scenarios from ADR-032
   Decision E:

   ```yaml
   capabilities:
     "tools.call.public_data_retrieval":
       min_tier: untrusted          # public reads — any device OK

     "tools.call.customer_db":
       min_tier: managed            # remote-wipeable device required

     "mcp.transfer_money":
       min_tier: managed_attested   # MDM + hardware-attested key

     "admin.*":
       min_tier: managed_attested   # same bar as money moves
   ```

3. Mount and point Mastio at the file:

   ```yaml
   services:
     mcp-proxy:
       volumes:
         - /etc/cullis/capability-tiers.yaml:/etc/cullis/capability-tiers.yaml:ro
       environment:
         - MCP_PROXY_TIER_MATRIX_PATH=/etc/cullis/capability-tiers.yaml
   ```

4. Restart the proxy (see "Reload procedure"). The matrix is
   parsed at lifespan startup and cached for the process lifetime.

If the YAML fails to parse, Mastio falls back to a permissive
matrix (every capability → `untrusted`, `version=0.0-fallback`)
and logs ERROR `tier_matrix load failed`. Alert on that line.

## Progressive rollout (audit-only → enforce)

The gate is best rolled out in four phases. Skipping straight to
strict denies will block legitimate calls from devices that
haven't been enrolled / re-keyed yet.

**Phase 1 — Observe (week 0-2).** Deploy with the default
permissive matrix (`default_min_tier: untrusted`, every override
removed). The gate evaluates and audits but allows every call.
Watch the `policy.tier_evaluated` audit rows accumulate. Build a
distribution of `effective_tier` per agent and per user. Decision
output: which capabilities are realistically callable from which
tier in your fleet today?

**Phase 2 — Tighten staging (week 2-4).** Author the override on a
staging Mastio first. Raise tiers for low-risk capabilities first
(read-only customer data → `managed`). Watch
`tool_execute status="error"` rows with
`denied_reason_code=insufficient_tier` to catch principals that
legitimately need the capability but lack the tier. Iterate until
staging matches the intended posture.

**Phase 3 — Roll to production.** Mount the override into the prod
Mastio. Communicate the cutover to end users 48 hours before —
mainly the `byod_isolated` macOS BYOD population, who may need
MDM enrollment to keep working. Roll forward; monitor the
`insufficient_tier` deny rate.

**Phase 4 — Tighten high-risk capabilities.** Once steady state is
observed, raise `admin.*` and money-moving capabilities to
`managed_attested`. Re-cycle Phase 2 monitoring on a smaller
capability set.

## Verifying enforcement (audit-log queries)

Mastio writes one `policy.tier_evaluated` audit row per gated call
(both allows and denies) and one additional `tool_execute` row on
deny. The detail column carries a canonical JSON payload —
`capability_requested`, `effective_tier`, `required_tier`,
`decision`, optionally `denied_reason_code` and the snapshot
`device_attestation_ref`. The table is `audit_log` (see
`mcp_proxy/db_models.py:86-113` for columns).

Daily deny count per required tier:

```sql
SELECT
  json_extract(detail, '$.required_tier')  AS required,
  json_extract(detail, '$.effective_tier') AS effective,
  count(*)                                 AS denies
FROM audit_log
WHERE action = 'policy.tier_evaluated'
  AND status = 'deny'
  AND timestamp >= date('now', '-1 day')
GROUP BY required, effective
ORDER BY denies DESC;
```

Top agents hitting the gate (find principals that need MDM
enrollment outreach):

```sql
SELECT agent_id, count(*) AS denies
FROM audit_log
WHERE action = 'policy.tier_evaluated'
  AND status = 'deny'
  AND timestamp >= date('now', '-7 day')
GROUP BY agent_id
ORDER BY denies DESC
LIMIT 20;
```

Distribution of effective_tier across the fleet (last 24 h):

```sql
SELECT
  json_extract(detail, '$.effective_tier') AS effective,
  count(DISTINCT agent_id)                 AS distinct_agents
FROM audit_log
WHERE action = 'policy.tier_evaluated'
  AND timestamp >= date('now', '-1 day')
GROUP BY effective
ORDER BY distinct_agents DESC;
```

On Postgres swap `json_extract(detail, '$.field')` for
`detail::jsonb ->> 'field'` and `date('now', ...)` for
`now() - interval '1 day'`; the rest is portable.

## Env vars that affect enforcement

| Variable | Default | Effect |
|---|---|---|
| `MCP_PROXY_TIER_MATRIX_PATH` | unset (uses bundled `enterprise-kit/policy/capability-tiers.yaml`) | Absolute path to your override YAML. Set this in `proxy.env` and add the matching `environment:` mapping in the compose service. |
| `MCP_PROXY_ATTESTATION_STALE_THRESHOLD_SECONDS` | `900` (15 min) | When the last MDM compliance signal is older than this, the resolver applies the stale downgrade per ADR-032 schema sez. 5. Tighten for high-trust deployments. |

Bundle deployments using `docker compose --env-file proxy.env` must
add explicit `environment:` entries for both variables in the
`mcp-proxy` service — env-file substitution does not auto-inject
variables into the container.

## Reload procedure

The matrix is cached at lifespan startup (PR #752). Hot-reload via
admin endpoint is on the roadmap but not yet shipped, so any
change requires a proxy restart.

If only the YAML file changed (mounted volume, image unchanged):

```bash
docker compose --env-file proxy.env up -d --force-recreate --wait mcp-proxy
```

`--wait` is required — `--force-recreate` returns when the
container is spawned, not when uvicorn finishes binding.

If you also need a new image or env change, use `./deploy.sh --pull`
— it sets `COMPOSE_PROJECT_NAME=cullis-mastio` for you. Running
`docker compose up -d` from a different cwd starts a parallel
orphan stack because the project name defaults to the directory.

## Troubleshooting

**Symptom: most calls return `insufficient_tier`.** Most common
root cause: the calling principals have no `last_attestation` row
yet (no MDM enrollment, no F3 hardware claim), so every effective
tier resolves to `untrusted` and any non-`untrusted` requirement
denies. Check the audit-query "distribution of effective_tier
across the fleet" above — if every agent shows `untrusted`, the
gap is enrollment, not policy. A secondary cause is a YAML mount
mismatch: check the boot log for `tier_matrix load failed` (parse
error) and `tier matrix YAML not found at ...` (path mismatch).

**Symptom: typed principals (user / workload) appear to skip the
tier gate entirely.** Expected. PR #755 exempts typed principals
in V1: the gate reads `internal_agents.last_attestation`, and a
typed principal has no row in that table. Per-user attestation is
on the roadmap for ADR-021 v2 (likely landing on `user_sessions`
for shared-mode Frontdesk per migration 0035's forward note).
Until then, typed principals are still subject to the capability
gate but not the device tier gate.

**Symptom: macOS BYOD stuck at `byod_isolated`.** Expected. Secure
Enclave alone cannot reach `managed` — that tier requires MDM
enrollment. See ADR-032 Decision B. Enroll the Mac in Intune,
Jamf, or Kandji to lift the device to `managed`.

**Symptom: a previously-compliant device dropped to `untrusted`
without a fleet-wide change.** The stale downgrade kicked in.
Check the device's last MDM check-in time; if Intune hasn't seen
it in over `MCP_PROXY_ATTESTATION_STALE_THRESHOLD_SECONDS`, the
claim is treated as stale and collapsed. Either reduce the
threshold or get the device to check in.

## See also

- ADR-032 Decision E — the 5-tier ladder spec (internal ADR; see
  Mastio release notes for the public summary).
- `enterprise-kit/intune-setup.md` — MDM enrollment, prerequisite
  for reaching `managed` and above.
- `enterprise-kit/runbook-attestation-revocation.md` — F6
  cert-revocation flow for compliance flips.
- `enterprise-kit/policy/capability-tiers.yaml` — the shipped
  default matrix (start by copying this file).
