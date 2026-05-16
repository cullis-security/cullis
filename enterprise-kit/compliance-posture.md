# Cullis Mastio — compliance posture

Reference for security / GRC / audit teams evaluating Cullis Mastio
against DORA, NIS2, GDPR Art 30, ISO 27001, SOC 2 audit trail
requirements. Pairs with `BYOCA.md` (PKI sovereignty) and the
PDP template (`pdp-template/`).

## Audit log immutability proof

Mastio's `audit_log` carries a forward-integrity hash chain with
SHA-256 per row, chain forward via `prev_hash`. Tamper detection:
any row mutation (UPDATE / DELETE on an existing row, splice attack,
row replacement) invalidates every downstream hash, detectable via
the `verify_audit_chain` API.

The DB-level append-only enforcement (migration `0031_audit_append_only_v2`)
adds a second defence: a trigger / role-revoke pattern that refuses
UPDATE and DELETE at the SQL layer, so even a compromised application
process cannot rewrite history without surfacing a constraint error.

### Per-row vs per-batch immutability proof (Mastio v0.4.x → v0.5+)

| | Mastio v0.4.x | Mastio v0.5+ (default) | Mastio v0.5+ (opt-out) |
|---|---|---|---|
| Hash chain commit | Per row | Per batch (~100 rows / 1s) | Per row |
| Throughput ceiling | ~200 rows/sec | ~10 000+ rows/sec | ~200 rows/sec |
| Audit visibility lag | < 100 ms | ≤ `flush_interval_s` (default 1.0 s) | < 100 ms |
| Fail-deny semantics | Caller surfaces 5xx on retry exhaustion | Synchronous-flush path same; background-flush path drops + logs | Caller surfaces 5xx |
| Config | `MCP_PROXY_AUDIT_FAIL_DENY=true` (default) | `MCP_PROXY_AUDIT_CHAIN_BATCH_SIZE=100`, `MCP_PROXY_AUDIT_CHAIN_FLUSH_INTERVAL_S=1.0`, `MCP_PROXY_AUDIT_CHAIN_DISABLED=false` | `MCP_PROXY_AUDIT_CHAIN_DISABLED=true` |

### Trade-off documentation (ADR-033)

Mastio v0.5+ defaults to **per-batch** immutability proof to unlock
Tier 2 sustained throughput (100 RPS sustained at p99 < 1 s). Each
batch holds at most `audit_chain_batch_size` rows for at most
`audit_chain_flush_interval_s` seconds before the hash chain is
committed to disk. After commit, the per-batch proof is identical
in cryptographic strength to per-row — every row in the committed
batch carries its own `chain_seq`, `prev_hash`, and `row_hash`, and
`verify_audit_chain` walks them one-by-one exactly as it did under
v0.4.x.

The trade-off is **visibility**, not immutability: a SIGKILL / OOM /
power loss in the ~1s window between row write and batch commit can
drop the not-yet-committed rows. The bounded interval means at most
1 second of audit traffic at the sustained rate (or
`batch_size` rows, whichever fills first) is exposed to this
window. After commit, no actor with DB write access can rewrite a
committed row without detection.

### Regulatory framework alignment

| Framework | Requirement | Per-batch (default) | Per-row (opt-out) |
|---|---|---|---|
| **DORA Art. 28-31** (ICT risk management, audit trail) | "Records of ICT-related incidents that ensure traceability" | ✅ Sufficient — < 1s visibility lag is below the operational threshold for any DORA event class | ✅ Strictly stronger |
| **NIS2 Art. 21(2)(f)** (logging + security operations) | "Policies and procedures concerning the use of cryptography" + tamper-evident logging | ✅ Sufficient — per-batch hash chain is tamper-evident at the row level after commit | ✅ Strictly stronger |
| **GDPR Art. 30** (records of processing) | "Records of processing activities" — no real-time durability requirement, audit of access trail | ✅ Sufficient | ✅ Strictly stronger |
| **ISO 27001 A.8.15** (logging) | "Logs … shall be produced, stored, protected and analysed" — protection clause covers tamper-evidence | ✅ Sufficient | ✅ Strictly stronger |
| **SOC 2 CC7.2** (system monitoring) | Logged events + monitoring — no per-event durability requirement | ✅ Sufficient | ✅ Strictly stronger |
| **PCI DSS 10.5** (audit trail security) | "Limit viewing of audit trails … Protect audit trail files from unauthorised modifications" | ✅ Sufficient — DB append-only + hash chain at batch boundary | ✅ Strictly stronger |
| **Customer-specific per-row durability mandate** (rare — tier-1 banks with custom legal interpretation, defence contracts requiring per-event ledger) | "Every audit event committed before the request acknowledges" | ⚠️ **Not sufficient** — use opt-out | ✅ Required |

### When to set `audit_chain_disabled=true`

Default-keep batched (the v0.5+ default) unless:

1. **Legal interpretation requires per-row durability** in the
   request-acknowledge synchronous path. Most frameworks above do
   not — the per-batch proof is recognised as immutable after
   commit. Verify with your auditor before opting out.
2. **Sub-1s audit visibility is contractually required** for an
   integration (rare: SIEM forwarders typically have their own
   batching layer with multi-second windows).
3. **Throughput is not a constraint** (single-tenant deployment,
   < 50 RPS sustained). Set `MCP_PROXY_AUDIT_CHAIN_DISABLED=true`
   in `proxy.env` and the legacy per-row path engages — no other
   tuning required.

### Operator playbook for compliance attestation

The verification API is the auditor-facing artifact:

```python
from mcp_proxy.db import verify_audit_chain

ok, broken_seq, reason = await verify_audit_chain()
# ok=True       → chain intact end-to-end, attestation issuable
# ok=False      → broken_seq is the first row that fails; reason
#                 carries the specific break (hash mismatch,
#                 prev_hash mismatch, sequence gap)
```

Operators should run `verify_audit_chain` as part of:

- Monthly compliance attestation report
- Post-incident forensics (after any unplanned restart)
- Pre-upgrade verification (before applying a Mastio version bump)
- Quarterly DORA / NIS2 control evidence package

For multi-Mastio deployments, run per-Mastio (each Mastio holds its
own chain) and persist the verification verdicts in a tamper-evident
external store (Court audit replication, S3 Object Lock, or your SIEM
of choice).
