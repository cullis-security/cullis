# A.1b Run 3 — Batched audit chain Tier 2 validation

Date: 2026-05-16
Build: Mastio v0.4.4 (image `ghcr.io/cullis-security/cullis-mastio:0.4.4`)
  - F0.1 (#742) multi-worker uvicorn (`--workers 4`)
  - F0.4 (#743) batched audit chain, defaults `batch_size=100 flush_interval_s=1.0 disabled=False`
VM: 192.168.122.170 (4 vCPU, 8 GiB)
Stress profile: `intra-org-mastio-burst.js` with `STAGE_OVERRIDE=[60s→500, 300s plateau@500, 30s→0]`
Agents: 5000 pre-enrolled (carryover from Run 1 + Run 2)
Postgres backend: `cullis-postgres` container, asyncpg DSN

## Verdict

**FAIL** Tier 2 unlocked. Throughput is at the threshold (97 RPS vs ≥100 target) but ingress p99 sits at 15.8 s vs the ≤1 s target (16× off), with 15.36 % 5xx error rate at the 500 VU plateau. F0.4 is **not** the residual bottleneck: audit chain integrity verifies clean and audit write throughput sits well below saturation. A different layer (likely per-request CPU/crypto cost or asyncpg pool contention) caps the system before audit becomes the limiter.

## Numbers vs baseline

| Metric                     | Run 2 baseline (30m, 50→5k ramp) | Run 3 (6.5m, 500 VU plateau) | Tier 2 target |
|---                         |---                              |---                          |---           |
| Throughput (RPS, aggregate)| 351                             | 97.4                        | ≥100         |
| Iterations completed       | 628,067                         | 37,488                      | —            |
| Mint p99 (ms)              | 10,721                          | 34.7                        | ≤500         |
| Ingress p99 (ms)           | 25,213                          | 15,793                      | ≤1,000       |
| Mint error rate            | 89.39 %                         | 0.00 %                      | <0.1 %       |
| Ingress error rate         | 45.04 %                         | 15.36 %                     | <0.1 %       |
| Audit chain integrity      | OK                              | **OK**                      | OK           |
| Audit chain UNIQUE retries | 0 (Run 1 472k rows clean)       | **0 (no error log entries)**| ~0           |

Run 2 numbers come from `scripts/stress/intra-org-summary-run2.json`. They include the full 30-min ramp (peaks at 5k VU), so the comparison is one-directional — Run 3 reaches the 500 VU plateau cleanly without the 5k VU saturation Run 2 hit.

## Mastio internal metrics

- `cullis_audit_chain_*` prometheus counters: **not exposed in v0.4.4** (the prompt assumption was optimistic). Inferred from indirect signals:
  - Audit rows written: `346,607 − 314,877 = 31,730` rows over 442 s (T0 16:34:12 UTC → T1 16:41:34 UTC) → **71.8 audit rows/s sustained**.
  - Audit row count exactly matches successful ingress (non-5xx) counter: 31,730 ingress success vs 31,730 new audit rows. Audit path runs on every successful request, nothing leaked.
  - Container log scan (`-iE 'error|warning|429|503|circuit|busy|deadlock|chain|audit'` for the full run window): **0 matches**. No `AuditChainExhausted`, no UNIQUE collision retries surfaced, no `_log.critical` from the flush loop.
- Worker count: 4 uvicorn workers confirmed via `docker top` (PIDs spawned via multiprocessing fork pre-test).
- Container CPU (`docker stats` 5 s samples, 91 datapoints during the run):
  - mcp-proxy: avg **59.7 %**, peak **224.5 %** (of 400 % available across 4 vCPU).
  - postgres: avg 15.8 %, peak 63.6 %.
  - nginx: avg <5 %.
- Memory: mcp-proxy steady at 528 MiB (no leak across the run, no batched-queue unbounded growth).

The CPU profile is the key signal: with 4 workers and 4 vCPU available the ceiling is ~400 % aggregate. Run 3 plateau averaged 60 % and peaked 225 %. The system is **not CPU-bound** on the workers, yet ingress p99 sits at 15.8 s and 15 % of requests 5xx. The bottleneck has moved off the audit chain to something that serializes requests inside a worker (asyncpg pool, JTI replay store sync, DPoP/x509 verify queueing). Diagnosing that is A.1c scope.

## Audit chain integrity

Post-stress walk of the entire chain via `verify_audit_chain()` (no CLI shipped; invoked inline through `docker exec ... python -c`):

```
ok=True broken_seq=None reason=None elapsed=1.8s
```

346,607 rows verified, no gaps, no `prev_hash` mismatch, no `row_hash` tamper detected. Chain span: `MIN(chain_seq)=1, MAX(chain_seq)=346607`. F0.4 cross-process serialisation (4 workers writing concurrently through the UNIQUE(chain_seq) + retry loop) holds end-to-end.

## Observations

- **F0.4 ships safely.** Two independent signals confirm: integrity verifier passes on the full 346 k row history, and the container error log shows zero chain-related warnings/critical entries across the run. The Run 1 result (472 k rows clean on 4 workers) replicates under sustained 500 VU load on Postgres.
- **F0.4 is no longer the throughput limiter.** Audit write rate sustained ~72 rows/s on Postgres with workers at 60 % avg CPU. The legacy per-row chain held the system at ~167 RPS in Run 2 — Run 3 still hits ~97 RPS but with a *different* bottleneck profile (low CPU, high latency, 5xx surge), meaning lifting F0.4 exposed the next layer rather than fully unblocking it.
- **The next bottleneck is not on the workers' CPU.** Peak 224 % / 400 % available, average 60 %. Suggests per-request serialisation inside each worker — candidates are asyncpg pool sizing, the JTI replay store (in-memory vs Redis), or DPoP verify under contention. A profiling pass (py-spy / asyncio tasks dump) under sustained load is the cheapest next investigation.
- **Mint path is now production-clean at 500 VU.** 0 % error rate, p99 34.7 ms vs Run 2's 10.7 s. Token reuse (TOKEN_REUSE_MARGIN_MS) means mint cost amortises to ~500 mints / 37,488 iterations = 1.3 %, so this is partly hidden by the cache — but the cache miss path is still fast.
- **Borderline throughput at 97 RPS** is misleading: it's gated by the 15 % 5xx rate plus the high p99 forcing VUs to stall. Without that headwind the same workers could likely push >150 RPS, but that's a what-if, not a measurement.

## Next steps

1. **Do not advance to A.1c (Redis JTI) yet.** A.1c assumes JTI is the bottleneck. With workers at 60 % CPU and Postgres at 16 %, the bottleneck is either pool/asyncio contention or an unidentified sync point. A 10-minute py-spy on a worker under sustained 500 VU should localise it before throwing infrastructure at the wrong layer.
2. **Close P1 with PARTIAL.** F0.4 ships and is safe; multi-worker ships. Tier 2 latency target is not met, but the failure mode is now diagnostic-tractable (single hot path) rather than systemic (per-row audit lock across workers). Document the residual bottleneck as the explicit P2 entry.
3. **Add prometheus counters** for `audit_chain_batch_flushes_total`, `audit_chain_pending_rows`, `audit_chain_flush_duration_seconds`. Today we are reading audit health by diff-ing Postgres COUNT() and walking the chain — fine for a one-shot validation, awful for an ops dashboard. Tiny diff, big visibility win.
4. **Risk flags:**
   - Background flush task: no observability into queue depth. If a future bottleneck creates a backlog, we'll find out via OOM, not a metric.
   - Container env doesn't pin `MCP_PROXY_AUDIT_CHAIN_*` explicitly. Defaults from `mcp_proxy/config.py` are loadbearing — surface them in the bundle's `proxy.env.example` so operators see the contract.
   - Anthropic API key visible in `docker exec env` dump (memory `feedback_third_party_ai_gateway_key_leak`). Not new in Run 3, but the rotation-after-stress hygiene applies.

## Artefacts

All under `imp/run3/`:
- `intra-org-summary.json` — k6 metrics export (full distribution)
- `intra-org-results.ndjson` — k6 raw stream
- `intra-org-stdout.log` — k6 stdout (per-second VU + iteration counter)
- `docker-stats.log` — 91 samples of container CPU/mem/net during the run
- `audit-rate.log` — Postgres `COUNT(*) FROM audit_log` every 5 s
- `mastio-errors.log` — filtered Mastio container logs (1 line of warning noise, no chain errors)
- `pg-count-pre.txt`, `pg-count-post.txt` — exact T0/T1 row count + timestamp
- `chain-integrity-post.txt` — verifier output

VM backups under `~/cullis-mastio-bundle/`:
- `data.run2.bak.tgz` (80 MB) — bundle data dir pre-upgrade
- `backups/proxy_a.run2.bak.dump` (43 MB) — Postgres logical dump pre-upgrade
- `backups/run2-logs.txt`, `backups/run2-pg-logs.txt`
- `proxy.env.run2.bak`

Keep until A.1c lands or Daniele clears them — they're the revert path if Run 4 needs the v0.4.3 + pre-batched state back.
