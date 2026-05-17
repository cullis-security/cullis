# A.1c — Mastio locale + py-spy hot path (2026-05-17)

## Setup

| Param | Value |
|---|---|
| Build | `ghcr.io/cullis-security/cullis-mastio:0.4.4` |
| Mode | standalone (`MCP_PROXY_STANDALONE=true`) |
| Backend | SQLite (`/data/mcp_proxy.db`, WAL) |
| Workers | 4 (`uvicorn --workers 4`) |
| Host port | `9100` (plain HTTP, no TLS sidecar) |
| Container caps | `--cap-add SYS_PTRACE --security-opt seccomp=unconfined` (locale only) |
| Agents pre-enrolled | 500 (`stressa1c-NNNNN`, scaled 1/10 vs Run 3) |
| k6 scenario | `intra-org-mastio-burst.js`, `STAGE_OVERRIDE=[30s→50, 180s@50, 30s→0]` |
| Sampler | `py-spy record --rate 100 --duration 240`, attached to worker PID 8 |

py-spy attach VM è BLOCCATO da seccomp production (memoria `feedback_production_container_seccomp_blocks_pyspy.md`). Workaround: container locale `--cap-add SYS_PTRACE`. Locale ≠ VM (laptop CPU, SQLite, 50 VU vs 500), quindi i numeri assoluti NON sono bench-comparable con Run 3 — il valore è il flamegraph qualitativo.

## Verdict

**Hot path = aiosqlite worker thread + DPoP/JWT verify + observability middleware.** Il bottleneck NON è la crittografia DPoP/JWT da sola (~10-12% cumulativo), bensì la **serializzazione DB attraverso il single connection worker thread di aiosqlite (23.7% del campionamento)** sommata a **due middleware self-imposed: `db_latency_circuit_breaker` + `observability/db_latency` (7-10%)** e **`strip_x_cullis_headers` middleware (7.4%)**. Conferma parziale dell'ipotesi Run 3 (DB pool contention) e smentita parziale (DPoP verify queueing non è dominante). Sorpresa: l'osservabilità DB-latency da sola consuma ~7-10% del worker time.

## Hot path top 15 (dal flamegraph, samples inclusive)

| % | Samples | Frame |
|---|---|---|
| 23.68 | 707 | `_connection_worker_thread (aiosqlite/core.py:59)` — single SQLite I/O thread per connection |
| 15.41 | 460 | `get_authenticated_agent (mcp_proxy/auth/dependencies.py:28)` — auth dep totale (DPoP+JWT+JTI+lookup) |
| 8.47 | 253 | `execute (sqlalchemy/engine/base.py:1419)` — SQL execute |
| 8.37 | 250 | `_execute_on_connection (sqlalchemy/sql/elements.py:527)` |
| 7.43 | 222 | `__call__ (mcp_proxy/middleware/strip_x_cullis_headers.py:107)` — header strip per-request |
| 7.30 | 218 | `__call__ (mcp_proxy/middleware/global_rate_limit.py:164)` — rate-limit check per-request |
| 5.93 | 177 | `_maybe_local_token (mcp_proxy/auth/local_agent_dep.py:213)` — LOCAL_TOKEN dispatch |
| 5.63 | 168 | `_enforce_local_token_dpop_binding (mcp_proxy/auth/local_agent_dep.py:111)` — DPoP cnf.jkt binding |
| 5.16 | 154 | `execute_tool (mcp_proxy/ingress/router.py:55)` — ingress handler entry |
| 4.82 | 144 | `run (mcp_proxy/tools/executor.py:94)` — executor entry |
| 3.68 | 110 | `__call__ (mcp_proxy/middleware/db_latency_circuit_breaker.py:233)` — ADR-013 layer 6 |
| 3.62 | 108 | `p99_ms (mcp_proxy/observability/db_latency.py:272)` — ring-buffer p99 compute |
| 3.52 | 105 | `__call__ (mcp_proxy/middleware/db_latency_circuit_breaker.py:243)` |
| 3.08 |  92 | `validate_local_token (mcp_proxy/auth/local_validator.py:96)` — JWT decode + verify |
| 3.08 |  92 | `decode (jwt/api_jwt.py:365)` — PyJWT decode |

**Cluster aggregati:**

- **DB I/O (aiosqlite + SQLAlchemy execute/compile/connect):** ~50% cumulative
- **DPoP/JWT verify path (decode + verify + binding + JTI consume):** ~15% cumulative
  - `verify_dpop_proof` (2.18% + 1.67% = 3.85%)
  - JWT decode (3.08% + 2.75% + 2.48% = 8.31%) — la decode è chiamata 2x per request (LOCAL_TOKEN + DPoP proof)
  - JTI consume (`dpop_jti_store.py:58`, 1.61%) — in-memory, NON è il bottleneck
- **Self-imposed observability/middleware overhead:** ~22% cumulative
  - `strip_x_cullis_headers` 7.4% — P1.3 header sanitization, per-request
  - `global_rate_limit` 7.3% — ADR-013 layer 2 (DB-backed sliding window)
  - `db_latency_circuit_breaker` + `observability/db_latency` ~10% — paghi per misurare la latency DB
- **Audit chain (`log_audit` + `_audit_chain_head` + `compute_audit_row_hash`):** ~3-4% cumulative — confermato F0.4 batched audit è ship-safe, non è più il bottleneck (allineato a Run 3 verdict)

## Numbers (interno A.1c, NON comparare con VM Run 3)

| Metric | Value |
|---|---|
| Total requests | 54,615 |
| Sustained RPS | 227.6 |
| Iterations | 54,565 |
| Mint /v1/auth/token error rate | 0.00 % |
| Mint p50 / p95 / p99 / max | 4.2 / 19.9 / 31.9 / 36.2 ms |
| Ingress /v1/ingress/execute error rate | 1.61 % (876 / 54565, deliberate unknown-tool 404s) |
| Ingress p50 / p95 / p99 / max | 96.9 / 683.2 / 1219.0 / 4724.2 ms |
| Container CPU (peak / avg plateau) | 281 % / 200 % (di 400 % disponibile) |
| Container memory steady | 526 MiB |
| Auth-token mints / reuse | 50 / 54,515 |
| DPoP nonce retries | 0 |

CPU peak 281% / 400% available → 4 workers funzionano in parallelo ma non saturano la CPU. La curva CPU scala fra 250-280% durante i primi ~90s del plateau e poi cala a 170-200% per il resto: il sistema non è CPU-bound, è I/O-bound sul DB.

## Caveats

- Locale ≠ VM. Laptop CPU (più veloce per single thread), SQLite (no network roundtrip, no asyncpg pool), 50 VU vs 500 VU. **I numeri assoluti NON sono bench-comparable.**
- Il p99 1.2s qui non significa "su VM avremo 1.2s con tuning analogo" — significa "il sistema mostra coda DB anche a 50 VU su laptop, e a 500 VU su VM con Postgres remoto la coda è più lunga".
- Il flamegraph è preso su 1 dei 4 worker (PID 8). Gli altri 3 worker hanno carico simmetrico (k6 chiama una sola porta, uvicorn round-robin) ma il sample è del singolo worker.
- py-spy attach ha overhead trascurabile a `--rate 100` (~1% CPU). La signature di hot path è preservata.
- Il bottleneck DB sul VM è **asyncpg pool contention**; localmente è **aiosqlite single worker thread**. Sono manifestazioni diverse dello stesso pattern (DB I/O serialization downstream del worker uvicorn). Le hypothesis Run 3 (asyncpg pool / JTI / DPoP verify) sono raffinate così:
  - asyncpg pool / DB I/O serialization → **confermato** (proxy: aiosqlite worker thread 23.7%)
  - JTI replay store → **smentito** (1.6%, in-memory, non bottleneck)
  - DPoP verify queueing → **parzialmente confermato** (~15% cumulative, ma sotto il DB)

## Surprises (non in hypothesis Run 3)

1. **`mcp_proxy.observability.db_latency` + `db_latency_circuit_breaker` middleware costano ~10% cumulativo.** Si paga circa 1 sample su 10 per misurare la latency DB. Il ring buffer `_percentile` (`list comprehension` + `sort`) è il sub-frame più ricorrente. ADR-013 layer 6 è un fail-safe utile, ma il costo non era contabilizzato.
2. **`strip_x_cullis_headers` middleware (7.4%) è inaspettatamente caro.** P1.3 fa un loop su tutti gli header request per filtrare quelli `X-Cullis-*`. Su 50 VU sustained pesa più del DPoP verify completo.
3. **JWT decode è chiamato 2x per request** (LOCAL_TOKEN + DPoP proof header), totale 8.3% cumulative. Era atteso 1x, suggerisce ottimizzazione possibile cacheando il decode result tra middleware/dependency.

## A.1d follow-up (azioni concrete)

| Priorità | Azione | Razionale dal hot path |
|---|---|---|
| 1 | **Asyncpg pool size tuning su VM** (default 10 → `workers * 4` = 16) | aiosqlite worker thread 23.7% locale = proxy del pool contention su Postgres. F0.2 Postgres migration deve includere il pool sizing. |
| 2 | **Ottimizza `_percentile` in `mcp_proxy/observability/db_latency.py`** | Sostituire `sorted(list[:])` con TDigest o reservoir sampling. Riduce ~3-4% per-request. |
| 3 | **Profilare `strip_x_cullis_headers.py:107`** (7.4% overhead inaspettato) | Sostituire loop manuale con MutableHeaders filter pre-compilato o early-return se nessun header match. |
| 4 | **Cache `validate_local_token` result tra middleware e dependency** | JWT decode 2x per request (8.3% cumulative). Memoizzare per-request via `request.state.local_token`. |
| 5 | **Verificare `global_rate_limit` su Redis vs in-memory** | 7.3% del worker time. Memoria `feedback_h4_convergent_pattern_fallback_insecure_default.md` dice in-memory è fallback; con Redis disponibile l'I/O è async + non blocca worker. |
| 6 | **Audit chain non serve ottimizzare** | 3-4% cumulative, F0.4 batched è già ship-safe. |
| 7 | **DPoP verify (3.85% verify + JTI 1.6%)** non è urgente | Sotto la soglia di interesse. Cache JWK Thumbprint compute (RFC 7638) potrebbe aiutare margine ma non sposta il bottleneck. |

## Pitch CISO data point

Il throughput a 50 VU locale su SQLite tocca 227 RPS con p99 ingress ~1.2s. La signature del hot path mostra che la coda è I/O DB (single-writer SQLite o pool asyncpg) e non crittografia (DPoP + JWT verify pesano <15% cumulative). **Implicazione:** scalare orizzontalmente i worker uvicorn (F0.1 multi-worker già shipped) non basta — serve scalare il backend DB. La crittografia zero-trust di Cullis non è il bottleneck di throughput; il bottleneck è la persistenza dello stato di sicurezza (token replay store, audit chain, rate-limit counter). Su Postgres remoto (F0.2) con pool tuning corretto la coda DB si distribuisce su connessioni multiple invece di serializzare su un thread per worker.

## Artifacts

- `imp/profiling/flamegraph-a1c.svg` — flamegraph py-spy (124 KB)
- `imp/profiling/k6-summary-a1c.json` — k6 summary export
- `imp/profiling/k6-stdout-a1c.log` — k6 stdout con summary di fine run
- `imp/profiling/docker-stats-a1c.log` — `docker stats` 5s samples (51 datapoints)
- `imp/profiling/container-logs-a1c.log` — Mastio container logs (0 ERROR/exception)

Il file `k6-results-a1c.ndjson` (242 MB raw events) NON è committed; vive in `/tmp/mastio-stress-a1c/` per la durata della sessione locale.
