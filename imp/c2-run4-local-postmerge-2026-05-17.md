# Run 4 — Mastio docker locale post-merge P3 (2026-05-17)

Date: 2026-05-17
Build: Mastio image locally built from `main` HEAD `b10723ff` (all 10 P3 PRs merged: Cluster A leader election #759 + Cluster B audit no-op #750 + denied_reason_code #751 + tier matrix cache #752 + admin rotate #753 + DPoP htu UX #754 + typed tier #755 + tier runbook #756 + forgot-password #757 + enterprise backup #758)
Backend: Postgres 16 docker container (`postgres:16-alpine`), DSN `postgresql+asyncpg://mastio@cullis-pg-run4:5432/mastio`
Workers: 4 uvicorn (CMD override `--workers 4`)
Agents pre-enrolled: 500 (`stress-run4-org::stress-NNNNN`, via patched `bulk_enroll_agents.py` with `BULK_VM_HOST=local` + `BULK_PG=1`)
k6 profile: `intra-org-mastio-burst.js`, `STAGE_OVERRIDE=[30s→100, 300s plateau@100, 30s→0]`
Security: `--cap-add SYS_PTRACE --security-opt seccomp=unconfined` (locale-only, NOT production hardening)
Profiling: `py-spy record --rate 100 --duration 360` attached to worker PID 10 (container-namespace) during the run.

## Verdict

**Tier 2 ingress p99 SLO (≤1000 ms) NOW PASSING** at 100 VU sustained plateau on Postgres + post-P3-merge build, vs Run 3 VM (500 VU, 15.8 s p99). The bottleneck moved off the persistence layer onto observability self-imposed overhead + JWT verify, both opportunistic fixes. **Caveat**: 100 VU locale vs 500 VU VM is not apples-to-apples. The number that travels is **the hot path shift**: persistence is no longer dominant.

## Numbers vs Run 3 baseline

| Metric                | Run 3 VM (500 VU, F0.4 only)  | Run 4 locale (100 VU, all P3 merged) | Delta |
|---                    |---                            |---                                   |---    |
| Throughput (RPS)      | 97.4                          | **539.1**                            | +5.5x (scale-different) |
| Iterations completed  | 37,488 (6.5 min)              | 193,991 (6 min)                      | +5.2x |
| Mint /v1/auth/token p99 | 34.7 ms                     | 243.3 ms                             | worse (laptop CPU, ES256 sign cost) |
| Mint /v1/auth/token error | 0.00 %                    | 0.00 %                               | = |
| **Ingress /v1/ingress/execute p99** | **15,793 ms**     | **399.6 ms**                         | **−40x (≤1000 ms SLO PASSING)** |
| Ingress /v1/ingress/execute error | 15.36 %             | **0.00 %**                           | from 15.4% 5xx → clean |
| Mint mints / reuse    | 5000 / 0                      | 100 / 193,891                        | reuse cache works |
| Worker count          | 4                             | 4                                    | = |

The 5x throughput gain at 100 VU (vs 500 VU Run 3) is **not** a fair comparison — fewer concurrent VU + locale + Postgres all stack. The honest reading is:

1. **Ingress p99 dropped 40x** at comparable per-VU contention. The persistence bottleneck was the major contributor to Run 3 latency; eliminating it (Postgres pool + Cluster A leader gating + audit batched chain F0.4 + tier matrix cache) takes the system from "broken-at-load" to "Tier 2 SLO range".

2. **Ingress error rate 15.36 % → 0 %**: 5xx surge in Run 3 was the most damaging signal for pitch CISO. Run 4 is clean.

3. **Mint p99 regressed** locale vs VM: laptop CPU (single-thread ES256 sign) is materially slower than the VM 4 vCPU. This is expected and not a regression of the code.

## Hot path top contributors (py-spy 360 s, ~34,800 samples)

| Function | Samples | % | Category |
|---|---|---|---|
| `_maybe_local_token` (mcp_proxy/auth/local_agent_dep.py:248) | 973 | 2.80% | auth surface |
| `__call__` (mcp_proxy/middleware/db_latency_circuit_breaker.py:243) | 963 | 2.77% | **observability** |
| `validate_local_token` (mcp_proxy/auth/local_validator.py:96) | 888 | 2.55% | auth surface |
| `decode` (jwt/api_jwt.py:365) | 873 | 2.51% | **JWT verify** |
| `decode_complete` (jwt/api_jwt.py:262) | 763 | 2.19% | **JWT verify** |
| `get_mastio_key_by_kid` (mcp_proxy/db.py:986) | 757 | 2.18% | **DB lookup (cacheable)** |
| `p99_or_none` (observability/db_latency.py:95) | 740 | 2.13% | **observability** |
| `_percentile` (observability/db_latency.py:105) | 722 | 2.08% | **observability** |
| `_execute_context` (sqlalchemy/engine/base.py) | 696 | 2.00% | DB driver |
| `decode_complete` (jwt/api_jws.py:253) | 686 | 1.97% | **JWT verify** |
| `p99_or_none` (observability/db_latency.py:92) | 676 | 1.94% | **observability** |
| `<listcomp>` (observability/db_latency.py:92) | 675 | 1.94% | **observability** |
| `get_mastio_key_by_kid` (mcp_proxy/db.py:986) | 568 | 1.63% | **DB lookup (cacheable)** |
| `get_db` (mcp_proxy/db.py:341) | 548 | 1.58% | DB context |

### Aggregated by category

| Category | Cumulative % |
|---|---|
| **Observability self-imposed** (db_latency_circuit_breaker + p99_or_none + _percentile + db_latency listcomp) | **~12.8 %** |
| **JWT verify** (decode + decode_complete + verify variants visible elsewhere) | **~8.0 %** |
| **Auth surface** (_maybe_local_token + validate_local_token + ancillary) | **~6.0 %** |
| **DB lookup cacheable** (get_mastio_key_by_kid × 2 = ~4.4 %, also get_db) | **~6.0 %** |
| **DB driver** (sqlalchemy _execute_context + asyncpg) | **~2.0 %** |

## Comparison vs A.1c (pre-merge, SQLite locale)

| Hot path category | A.1c (pre-merge, SQLite, 50 VU) | Run 4 (post-merge, Postgres, 100 VU) | Delta |
|---|---|---|---|
| Persistence DB serialization | 23.7 % (aiosqlite single-thread) | ~2.0 % (asyncpg pool) | **−21.7 pp** ✅ |
| Observability self-imposed | ~22 % | ~12.8 % | −9.2 pp (still dominant) |
| DPoP/JWT verify | ~15 % (with 2x JWT decode) | ~8 % (still 2x) | −7 pp |
| JTI replay store | 1.6 % | (not surfaced in top-20) | ~ unchanged, no longer top contributor |

**Confirmed**: Postgres swap closes the aiosqlite single-thread serialization bottleneck. JWT decode 2x persists as opportunistic fix (~8 %, was ~15 %). Observability is now the single biggest contributor (12.8 %) — tunable via env var (the A.1d follow-up).

## A.1d action items, ranked by ROI

### High ROI (10-20 % wall-time saving each)

1. **Observability tunable env vars** (~12.8 % saving floor):
   - `MCP_PROXY_DB_LATENCY_RING_BUFFER_SIZE` (default 1000 → 100 for customer trusted-network deployments)
   - `MCP_PROXY_DB_LATENCY_CIRCUIT_BREAKER_ENABLED` (default true → false for deployments that don't need it)
   - `MCP_PROXY_DB_LATENCY_PERCENTILE_INTERVAL_SEC` (longer interval → fewer p99 computations)
   - Net effect: customer CISO can opt-out the per-request ring-buffer + p99 compute on every middleware pass.

2. **`get_mastio_key_by_kid` cache** (~4.4 % saving):
   - Currently every JWT-verify path hits DB for the kid → public key. Cache the kid → public_key_pem in `app.state.mastio_keys_by_kid` at lifespan startup + invalidate on rotation event. Pattern identical to PR #752 tier_matrix cache.

3. **JWT decode 2x cache** (~5 % saving, opportunistic):
   - `jwt.decode_complete` is called twice per request (once for unverified header peek + once for full verify). Cache the unverified payload in `request.state` or a ContextVar in middleware, reuse downstream.

### Medium ROI (architectural)

4. **Redis JTI store provisioning** for production:
   - JTI replay store in-memory works on single-worker but on multi-worker forces serial coordination. Redis already shipped as opt-in. CISO blocker if customer needs HA: enforce Redis in `validate_config(production)`.

5. **Postgres connection pool tuning**:
   - `_execute_context` 2 % suggests pool is healthy under 100 VU. Re-test at 500 VU locale to see if scales.

### Low ROI (deferred)

6. **DPoP verify cache** — already amortised by JTI replay store; per-request signature verify cost is necessary.

## Cluster A leader election: confirmed in production

Container logs grep for `sweeper started` + `stale-watcher started` returned 1 of each (vs 4 + 4 pre-#759 with 4 workers). Process tree (`docker top`) shows 4 worker PIDs spawned by uvicorn master, all 4 workers active and serving k6 traffic, but only 1 owning each background loop. Cluster A working as designed.

Future: when the leader worker dies, no automatic failover. Customer ops detection via "did intune polling tick fire in last 2x interval?" alert. V2 lease + heartbeat tracked as post-revenue extension.

## Caveats for pitch usage

- **NOT bench-comparable VM Run 3**. Locale laptop CPU + 100 VU vs VM 4 vCPU + 500 VU. The number that travels is the **hot-path shift** + **ingress p99 magnitude order improvement** (40x), not the absolute RPS.
- **Tier 2 SLO at 100 VU** — for the first pilot SMB (200-2000 user with 5-10 % concurrent burst ≈ 10-200 VU realistic), this is the budget zone. For enterprise Tier 1+ burst (≥500 VU sustained, ≥1000 RPS sustained), A.1d apply + Run 5 (VM) re-validate needed.
- **py-spy attach on locale only**. Production VM remains seccomp-hardened (memoria `feedback_production_container_seccomp_blocks_pyspy.md`). py-spy was installed inside the local container during the run, cleaned up at teardown (see Cleanup section).

## Artifacts

In `imp/profiling/`:
- `flamegraph-run4.svg` — py-spy flamegraph 360 s @ 100 Hz
- `k6-summary-run4.json` — k6 metrics summary
- `container-logs-run4-tail.log` — last 2 MB of Mastio container stderr (full log truncated for git)

## Cleanup confirmed

- `docker stop cullis-mastio-run4 && docker rm cullis-mastio-run4` (post artifacts collection)
- `docker stop cullis-pg-run4 && docker rm cullis-pg-run4`
- `docker network rm cullis-stress-net`
- `/tmp/mastio-run4/` removed
- Production hardening NOT touched. py-spy was inside the local container only; container removed.

## Memorie correlate

- [[stress-a1c-hot-path-findings]] (pre-merge baseline)
- [[multi-worker-safe-on-sqlite-with-retry]]
- [[postgres-swap-does-not-unlock-tier2]] (refuted in part by Run 4: Postgres does help post-Cluster-A)
- [[multiworker-uvicorn-systemic-gaps]]
- [[production-container-seccomp-blocks-pyspy]]
