# Attestation revocation runbook

> Audience: CISO, compliance officer, SOC analyst on call.
> Status: ADR-032 Phase 1 (Intune). Jamf / WS1 deferred.

This runbook is the operational counterpart of the F6 polling +
revocation flow. It answers the four questions a customer's
compliance team needs before they will trust an agent enforcement
gate that depends on MDM state:

1. How fast does a device flip take effect?
2. How do I prove, from the audit log, that it took effect?
3. What do I do when a user's agent stops working because of this?
4. What happens during a false positive?

## 1. Expected freshness window

Microsoft documents Intune compliance state freshness at 5-15
minutes. The Mastio polling cadence inherits that floor:

| Phase                              | Typical delay |
|------------------------------------|---------------|
| Intune marks device non-compliant  | T+0           |
| Graph API surfaces the new state   | T+5 to T+15 min |
| Mastio polls (default 600 s)       | up to T+10 min after Graph |
| Cert revocation lands in DB        | within the polling tick |
| Agent's next request returns 401   | next handshake (immediate) |

End-to-end worst case: **~25 minutes** from the Intune flip to the
agent being locked out. Customers requiring tighter SLA should
shorten `MCP_PROXY_MDM_INTUNE_POLL_INTERVAL_SECONDS` (minimum 60 s
to stay under Microsoft's throttling budget).

If you observe a transition that took materially longer, check:

* `cullis_mdm_circuit_state{mdm="intune"}` — value `2` (open) means
  the breaker tripped and polling was suspended. Look for the
  preceding `mdm_polling_degraded` audit row for the failure cause.
* `cullis_mdm_poll_total{result="failure"}` rate — sustained
  failures indicate a credential / network issue worth paging.

## 2. Forensic audit queries

The hash-chained `audit_log` table is the source of truth. The
columns added in migration `0037_audit_dev_attest`
(`device_attestation`, `effective_tier`) let you query device
posture at decision time without joining to the (live, mutable)
`mdm_device_state` cache.

```sql
-- Every revocation in the last 24h.
SELECT timestamp, agent_id, detail
  FROM audit_log
 WHERE action = 'agent.revoked'
   AND timestamp > datetime('now', '-1 day')
 ORDER BY timestamp DESC;

-- Every device_attestation event for a specific agent.
SELECT timestamp, action, status, detail, effective_tier
  FROM audit_log
 WHERE agent_id = ?
   AND action = 'device_attestation'
 ORDER BY timestamp DESC;

-- Every compliance flip on a specific Intune device.
SELECT timestamp, agent_id, detail
  FROM audit_log
 WHERE action = 'device_attestation'
   AND detail LIKE '%"device_id":"<intune-uuid>"%'
 ORDER BY timestamp DESC;

-- MDM polling outages: every CLOSED->OPEN breaker transition.
SELECT timestamp, detail
  FROM audit_log
 WHERE action = 'mdm_polling_degraded'
 ORDER BY timestamp DESC;
```

To verify the chain has not been tampered with, run the existing
`mcp_proxy/audit/chain_verifier.py` CLI against the row range of
interest. The F6 helpers insert chain-NULL rows on the per-tx path
(matching the F2 enrollment_hook convention) — the verifier skips
NULL rows. The stale-watcher daemon uses the chained `log_audit`
path, so stale events ARE chained.

## 3. Incident response: agent locked out

When a user complains "my agent suddenly stops working":

1. Confirm the principal: get the `agent_id` from the user's
   Connector logs (top of the dashboard at `:7777`).
2. Check the audit log:
   ```sql
   SELECT timestamp, action, detail
     FROM audit_log
    WHERE agent_id = '<agent_id>'
      AND action IN ('agent.revoked', 'device_attestation')
    ORDER BY timestamp DESC LIMIT 10;
   ```
3. If the most recent event is `agent.revoked` with
   `reason_code: insufficient_compliance`, the Intune flip caused the
   revocation. Tell the user: "Your device is currently marked
   non-compliant by Intune. Once your device returns to compliance,
   re-run the Connector enrollment to issue a new cert."
4. Confirm device state in Intune (Endpoint Manager → Devices →
   the user's device → Device compliance). The `device_id` in the
   audit detail JSON is the Intune-native UUID.

The cert is NOT auto-restored when Intune flips back to
compliant. The Connector has to re-enroll. This is intentional: the
operator stays in the loop, no silent un-revocation. The audit log
will show a `device_attestation` event with subtype `verified` when
Intune flips back, so SOC can correlate.

## 4. False positives

A transient network blip on the device side can cause Intune to
mark it non-compliant briefly. Two patterns:

**Pattern A — short blip, agent re-enrolls within the same hour.**
The audit log will show:

* `device_attestation: revoked` at T0
* `device_attestation: verified` (from polling re-converge) at
  T0+15min
* New `agent.created` + `device_attestation: verified` (subtype
  `enrollment`) when the user re-enrolls

This is the expected flow. No action required beyond user
re-enrollment.

**Pattern B — Intune backend wedged, fleet-wide false positive.**
If the customer sees a wave of revocations:

1. Check `cullis_mdm_circuit_state` — if `0` (closed), Mastio
   trusts the data. Validate against Intune admin centre.
2. Confirm the wave correlates with an Intune incident
   ([status.office.com](https://status.office365.com/)).
3. To pause F6 enforcement during a known upstream incident:
   `MCP_PROXY_MDM_INTUNE_ENABLED=false` + restart the Mastio. The
   cache stays warm but no further revocations fire. Re-enable
   when upstream is healthy. Note this also disables NEW
   revocations from polling; existing revocations stay until
   re-enrollment.

## 5. Audit retention

* All `audit_log` rows are append-only (`UPDATE` / `DELETE`
  blocked by trigger from migration `0031_audit_append_only_v2`).
* The hash chain (`chain_seq`, `prev_hash`, `row_hash`) lets the
  verifier detect tampering at the database level. Run the
  verifier at least quarterly:
  ```bash
  python -m mcp_proxy.audit.chain_verifier
  ```
* WAL archives are out of scope for this runbook; use the
  operator's existing Postgres WAL preservation policy. For
  SQLite (sandbox / pilot), back up the file before any
  maintenance window.

## 6. Tunables (summary)

| Env var | Default | Effect |
|---|---|---|
| `MCP_PROXY_MDM_INTUNE_ENABLED` | `false` | Master switch for Intune polling + F6 revocation. |
| `MCP_PROXY_MDM_INTUNE_POLL_INTERVAL_SECONDS` | `600` | Polling cadence (min 60 s). |
| `MCP_PROXY_ATTESTATION_STALE_THRESHOLD_SECONDS` | `900` | When a claim is considered stale (forces compliance → unknown in policy decisions). |
| `MCP_PROXY_ATTESTATION_STALE_WATCHER_ENABLED` | `true` | Background daemon that emits `device_attestation:stale` audit rows on threshold crossings. |
| `MCP_PROXY_ATTESTATION_STALE_WATCHER_INTERVAL_SECONDS` | `60` | Watcher sweep cadence. |

## 7. What this runbook does not cover

* Jamf / Workspace ONE webhook receivers (Phase 2; not shipped).
* Raw TPM EK CA chain BYOD attestation (deferred per ADR-032
  Decision Q8).
* AppSource publishing of the Cullis Mastio Intune app
  registration (out of scope — customers run their own Entra app).

For ADR rationale see `docs/adrs/adr-032-*.md` (public ratified) /
`imp/adrs/adr-032-*.md` (internal, includes commercial framing).
