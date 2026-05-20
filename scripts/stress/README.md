# scripts/stress: Mastio stress test harness

> k6 scripts for measuring how much load the Mastio bundle can sustain.
> Shipped in the public repo so operators can re-run them on their own
> hardware. The narrative summary lives in
> `site/src/content/docs/operate/capacity-planning.md`.

## Scenarios

| Script | What it stresses | Status |
|---|---|---|
| `health-throughput.js` | TLS edge + nginx → mcp-proxy plumbing (cheap read) | live |
| `soak-stability.js` | Same path, 50 VUs sustained 1h — memory leak detection | live |
| `intra-org-mastio-burst.js` | Full intra-org auth+audit chain at 50→5k VUs | live (C2.A.1) |
| `frontdesk-multiuser-mock.js` | Frontdesk user-path (login + list_models) w/o LLM | live |
| `frontdesk-multiuser-ollama.js` | Same shape + chat_completions against real Ollama | live |
| `dpop-egress.js` | DPoP signature verification + token issuance | TODO |
| `a2a-routing.js` | Intra-org A2A message dispatch via PDP + broker | TODO |
| `enrollment-burst.js` | Concurrent CSR issuance + DB insert | TODO |

`health-throughput.js`, `soak-stability.js`, `intra-org-mastio-
burst.js`, and the two `frontdesk-multiuser-*.js` scenarios are wired
today. The remaining scenarios are listed so future work can land in
one place. Each new scenario should keep the same conventions:
human-readable `handleSummary` for the maintainer + a JSON dump
(`summary.json`, `soak-summary.json`, `intra-org-summary.json`,
`frontdesk-summary-*.json`) for diffable artefacts.

## How to run

```bash
# Bring up a Mastio stack (see operate/runbook.md for the full
# walkthrough). The script targets the public TLS edge by default.
./deploy.sh

# Quick smoke / triage (<10 min): run k6 directly, summary only.
cd scripts/stress
nix-shell -p k6 --run "k6 run --insecure-skip-tls-verify health-throughput.js"

# Soak / burst (any run that writes raw NDJSON output): use the
# wrapper. It traps EXIT and drops the ndjson if it exceeds 1 GiB
# (or skip it entirely with K6_SKIP_NDJSON=1 for high-RPS targets),
# keeping the summary JSON. See "NDJSON cleanup wrapper" below for
# why this matters and which mode each scenario wants.
K6_SKIP_NDJSON=1 nix-shell -p k6 --run "bash _run-k6.sh soak-stability.js"
K6_KEEP_NDJSON=1 K6_RESULTS_DIR=. nix-shell -p k6 --run "bash _run-k6.sh intra-org-mastio-burst.js"

# Or against a remote stack:
BASE_URL=https://mastio.example.com:9443 \
    nix-shell -p k6 --run "bash _run-k6.sh health-throughput.js"

# Shorter soak smoke (e.g. validate the script itself):
SOAK_MINUTES=2 bash _run-k6.sh soak-stability.js
```

The scripts write `summary.json` / `soak-summary.json` next to
themselves and print a one-screen text summary to stdout. Both JSON
artefacts are gitignored.

### NDJSON cleanup wrapper (`_run-k6.sh`)

`k6 --out json=` writes one NDJSON line per HTTP sample. At 2k req/s
that's ~30 MiB/min — a 1h soak is ~1.8 GiB, a 30-min 5k-VU burst is
~18 GiB, a 3h partial soak filled 89 GiB on 2026-05-18 and killed k6
mid-run with ENOSPC. `_run-k6.sh` invokes k6 with the same `--out
json=` + `--summary-export=` pair, then on EXIT (success or failure)
drops the ndjson if it exceeded a threshold. The summary always
survives.

Tunables (env):

- `K6_SKIP_NDJSON=1` — do not write the ndjson at all. Use this for
  high-RPS scenarios against fast targets (e.g. `soak-stability.js`
  or `health-throughput.js` against a local Mastio bundle), where
  post-run cleanup is too late because the file grows faster than
  disk can hold it. Observed 2026-05-18: `soak-stability.js` against
  the local bundle sustained 7k req/s and produced ~110 GiB/h of
  NDJSON, hitting ENOSPC well before the 1h run finished. Wins over
  `K6_KEEP_NDJSON`.
- `K6_KEEP_NDJSON=1` — never drop the ndjson. Use this when you plan
  to run `_analyze_burst.py` against it, or need forensic per-sample
  data. Make sure the output dir lives on a disk with enough room.
  Ignored when `K6_SKIP_NDJSON=1`.
- `K6_NDJSON_KEEP_THRESHOLD_MB=<N>` — drop only if the ndjson grew
  past N MiB. Default 1024.
- `K6_RESULTS_DIR=<path>` — where to write ndjson + summary. Default
  `/tmp/k6-run-<scenario>-<epoch>`. Point this at `/var/tmp` or a
  dedicated mount when `K6_KEEP_NDJSON=1` for long runs, since `/`
  hitting 100 % poisons every other process on the box.
- `K6_EXTRA_ARGS="..."` — extra args appended to the k6 invocation.

The wrapper also pre-flights `df` on the output dir and warns when
less than 5 GiB is free (skipped when `K6_SKIP_NDJSON=1`).

### When to use which mode

| Scenario | Recommended mode | Why |
|---|---|---|
| `soak-stability.js` against any target | `K6_SKIP_NDJSON=1` | Read-only `/health` loop, summary covers all assertions, no analyzer reads the ndjson. |
| `health-throughput.js` smoke / triage | `K6_SKIP_NDJSON=1` | Same — high RPS, no per-sample analysis needed. |
| `intra-org-mastio-burst.js` baseline | `K6_KEEP_NDJSON=1` + `K6_RESULTS_DIR=scripts/stress` | `_analyze_burst.py` walks the ndjson for per-plateau aggregation. Run on a disk with at least 50 GiB free. |
| Quick local probe (<2 min) | default | Default threshold 1024 MiB will keep the small ndjson, useful if you want to peek at raw samples. |

## When to re-run

- After any change to `packaging/mastio-*/nginx/mastio/*.conf`: that's
  the layer with the most measurable RPS impact.
- After bumping the base image or upgrading nginx (regression check).
- Before cutting a `mastio-v*` or `mastio-enterprise-v*` release that
  ships nginx-layer changes.
- When operators report latency spikes or ENADDRNOTAVAIL upstream
  errors at scale.
- Before a release that ships changes to long-lived resources (DB
  connection pools, MCP session caches, audit hash chain accumulators):
  re-run `soak-stability.js` for at least 1h and compare RSS at start
  vs end — anything > 10 % drift is worth investigating.

## How to read the output

The `handleSummary` block prints:

- **Requests total** + **Requests per sec**: gross throughput nginx
  saw, including failures.
- **Errors**: fraction of requests that did not get a 2xx response or
  failed at the TCP layer. Anything above ~0.1 % is worth investigating.
- **Latency (success-only)**: distribution of `http_req_duration` for
  responses that passed the body+status check. Reported as avg / p50 /
  p95 / p99 / max.

The thresholds in `health-throughput.js` (p95 < 250 ms, error rate
< 1 %) make k6 exit non-zero on breach, so the script doubles as a
pre-release sanity gate.

## Intra-org baseline benchmark

`intra-org-mastio-burst.js` is the C2.A.1 baseline scenario: full
auth chain (`/v1/auth/token` mint with ES256 client_assertion + DPoP
proof) + tool execute (`/v1/ingress/execute` Bearer-DPoP with `ath`),
ramping 50 → 500 → 2k → 5k VUs across 30 minutes. Exercises DPoP
verify, x509 chain verify, LOCAL_TOKEN issuance, JTI replay store,
and the per-write audit hash chain end-to-end.

The harness is N pre-enrolled identities. k6 can't run the
device-code enrollment flow inline (overhead explodes per VU), so
the agents are seeded directly into `internal_agents` before the run
and torn down after.

### Pre-requisites

- Mastio reachable on `BASE_URL` (default `https://192.168.122.170:
  9443`). The bundle's nginx TLS edge is the natural target.
- SSH access to the VM that runs Mastio, so the bulk-enroll script
  can shell into the `mcp-proxy` container and the monitoring loops
  can sample `docker stats` + `audit_log.COUNT(*)`. Defaults assume
  `cullis@192.168.122.170`; override via `BULK_VM_HOST` /
  `BULK_CONTAINER`.
- k6 v1.4+ (uses WebCrypto). `nix-shell -p k6` works on NixOS;
  upstream binary works everywhere else.
- Python 3.11 with `cryptography` for the bulk-enroll orchestrator
  and the smoke harness. `nix-shell -p python311Packages.
  cryptography python311Packages.pyjwt python311Packages.requests
  --run "..."` covers all of it on NixOS.

### Setup

```bash
# 1. Seed N pre-enrolled agents into internal_agents. Idempotent
#    (INSERT OR REPLACE); --wipe removes any prior <prefix>-* rows
#    first.
python scripts/stress/bulk_enroll_agents.py --n 5000 --wipe

# 2. Optional: validate the auth chain on the first agent before
#    pointing 5000 VUs at the box. Confirms cnf.jkt binding (DPoP
#    htu / Host port-stripping trap, see _auth_smoke.py header).
python scripts/stress/_auth_smoke.py
```

`bulk_enroll_agents.py` writes `stress_agents.json` next to itself
(~8 MB at 5000 agents) — **gitignored**, carries per-agent PKCS8
PEMs for the leaf cert + DPoP keypair. Never commit it.

#### Postgres bulk inject helper

`_bulk_inject_pg.py` is the Postgres counterpart of `_bulk_inject.py`
for Mastio deployments where `MCP_PROXY_DATABASE_URL` points at
Postgres (asyncpg DSN). Same in-container streaming pattern as
the SQLite payload, but talks to the Mastio's Postgres backend via
asyncpg (already pinned in the Mastio image — no extra deps).

When to reach for it:

- A Mastio bundle has been re-pointed at Postgres for an A.1b-style
  multi-worker + Postgres backend benchmark.
- Any future stress scenario that needs N pre-enrolled agents inside
  a Postgres-backed Mastio without going through the device-code
  enrollment HTTP path.

Schema-aware differences from the SQLite payload: `federated_at` is
`TIMESTAMPTZ` on Postgres (passes a Python `datetime`), `is_active`
is `INTEGER`, `federated` is `BOOLEAN`. The payload uses
`ON CONFLICT (agent_id) DO UPDATE` for idempotency, so re-runs
overwrite `cert_pem` / `dpop_jkt` / `enrolled_at` while preserving
admin-managed columns.

Run it the same way as the SQLite variant — the orchestrator stays
the SSH+docker-exec stream-via-stdin pattern:

```bash
# Assumes Postgres container is reachable from inside the Mastio
# container at the hostname `postgres:5432` (set via docker
# --network-alias postgres at deploy time).
ssh cullis@192.168.122.170 'docker exec -i \
    -e N_AGENTS=5000 -e PREFIX=stress -e WIPE_PREFIX=1 \
    -e TRUST_DOMAIN=cullis.local -e AGENT_CAPABILITIES= \
    cullis-mastio-mcp-proxy-1 python -' \
        < scripts/stress/_bulk_inject_pg.py \
        > scripts/stress/stress_agents.json
```

Override `DSN` env if the asyncpg connection string differs from the
default `postgres://cullis_proxy:cullis_proxy_dev@postgres:5432/
proxy_a` (e.g. a different superuser, or a Postgres on a non-default
network alias).

The harness keeps a single `stress_agents.json` shape across both
helpers, so the k6 scenario and `_auth_smoke.py` work unchanged
against a Postgres-backed Mastio. Only the bulk-inject payload
differs.

### Run

```bash
# 3. Launch monitoring streams in 3 background terminals.
ssh cullis@192.168.122.170 'while true; do docker stats --no-stream \
    --format "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}" \
    cullis-mastio-mcp-proxy-1 cullis-mastio-mastio-nginx-1; sleep 5; \
done' > scripts/stress/docker-stats.log &

ssh cullis@192.168.122.170 'while true; do docker exec \
    cullis-mastio-mcp-proxy-1 python3 -c "
import sqlite3,os
c=sqlite3.connect(\"/data/mcp_proxy.db\")
print(c.execute(\"SELECT COUNT(*) FROM audit_log\").fetchone()[0],
      \"db=\"+str(os.path.getsize(\"/data/mcp_proxy.db\")),
      \"wal=\"+str(os.path.getsize(\"/data/mcp_proxy.db-wal\")
                  if os.path.exists(\"/data/mcp_proxy.db-wal\") else 0))"
sleep 10; done' > scripts/stress/audit-rate.log &

ssh cullis@192.168.122.170 "docker logs -f cullis-mastio-mcp-proxy-1 \
    2>&1 | grep -iE 'error|warning|429|503|circuit|busy|deadlock'" \
    > scripts/stress/mastio-errors.log &

# 4. Run k6. Use the wrapper with K6_KEEP_NDJSON=1 because the
#    per-plateau analyzer (_analyze_burst.py) needs the raw ndjson.
#    Point the output dir at the repo so the analyzer finds it.
nix-shell -p k6 --run "K6_KEEP_NDJSON=1 \
    K6_RESULTS_DIR=scripts/stress \
    bash scripts/stress/_run-k6.sh intra-org-mastio-burst.js"
# Wrapper writes scripts/stress/results.ndjson + scripts/stress/summary.json.
# Rename to intra-org-* if you want the legacy file names the analyzer
# defaults to, or pass the paths explicitly to _analyze_burst.py.
# When the analysis is done, drop the ndjson — at 5k VUs it's
# ~10 GiB per 30-min run.
```

The k6 scenario can be re-shaped via env:

- `STAGE_OVERRIDE='[{"duration":"60s","target":500}]'` for triage
  runs that only hit one plateau.
- `BASE_URL=https://other.host:9443` to point at a different bundle.
- `HTU_OVERRIDE=https://mastio.example.com` to force a specific
  DPoP `htu` when nginx Host-stripping doesn't behave like the
  default :9443 sidecar (the bundled nginx forwards `Host: $host`
  which strips the port — see the inline doc comment at
  `DEFAULT_HTU` for the gotcha).
- `THINK_MS=200` to add a fixed inter-cycle sleep when measuring
  *sustained* rather than *back-to-back* iterations.

### Analyze

```bash
# 5. Per-plateau aggregation (mint / ingress p50/p95/p99, error rate,
#    mcp+nginx CPU, audit/s, DB/WAL growth). Reads the four logs
#    written by steps 3+4 and emits a markdown table on stdout.
python scripts/stress/_analyze_burst.py
```

The analyzer walks the ndjson once (linear scan; 9-10 GB / 30-min
run takes a few minutes on a modern laptop) and buckets each
datapoint into a plateau by elapsed time. Plateau bounds match the
default `STAGES` in the k6 scenario.

For the C2.A.1 reference baseline (Mastio v0.4.3 bundle as-shipped
against the 4 vCPU disposable VM), see the maintainer-local report
at `imp/c2-a1-intra-org-baseline-2026-05-16.md`. Headline: the
bundle is Tier 1 ready at ~130 RPS sustained, but the
single-uvicorn-worker GIL + global asyncio audit-chain lock cap
throughput well below Tier 2+ targets. Architectural changes
(multi-worker uvicorn, Postgres backend, Redis JTI) are required
before re-running this scenario for Tier 2+ feasibility.

## Frontdesk multi-user benchmark

`frontdesk-multiuser-mock.js` and `frontdesk-multiuser-ollama.js`
stress the **Frontdesk** bundle (not Mastio). Each VU is a pre-seeded
Frontdesk user; the cycle is login → list_models (mock) or login →
chat_completions (ollama). Login is a one-shot per VU; the per-VU
cookie jar carries the session through subsequent iterations.

The mock variant isolates Frontdesk software overhead — auth, per-user
credential fork via `LocalUserProvisioner`, nginx TLS sidecar,
Frontdesk→Mastio mTLS hop — because `/v1/models` is a cheap read that
forwards to Mastio without touching an LLM. The ollama variant adds
`/v1/chat/completions` against the real LLM upstream, so latency
includes inference time and reflects the demo end-to-end.

### Setup

```bash
# 1. Bring up the Frontdesk + Mastio stack. The sandbox dogfood spins
#    both bundles + Ollama on the shared bridge and runs the workload
#    enrollment + AI provider configuration end-to-end.
bash sandbox/dogfood-frontdesk.sh

# 2. Seed N test users directly into the Frontdesk users.db. Same
#    shared bcrypt hash for all N (test only; checkpw still runs on
#    the hot path so the auth code path is exercised). --warmup
#    runs a parallel pre-login on all users to populate the
#    LocalUserProvisioner cert cache before the k6 stages start.
nix-shell -p python311Packages.bcrypt python311Packages.aiohttp --run \
    "python scripts/stress/bulk_create_frontdesk_users.py \
        --n 100 --wipe --warmup \
        --base-url http://localhost:18080"
```

`stress_frontdesk_users.json` (carrying the shared cleartext password)
is gitignored alongside `stress_agents.json`. NEVER commit.

### Run

```bash
# Mock (no LLM) — pure Frontdesk perf, default stages 50→200→500 VUs
nix-shell -p k6 --run "K6_SKIP_NDJSON=1 \
    bash scripts/stress/_run-k6.sh frontdesk-multiuser-mock.js"

# Ollama (full LLM path) — customer-realistic, default stages 10→30→50 VUs
nix-shell -p k6 --run "K6_SKIP_NDJSON=1 \
    bash scripts/stress/_run-k6.sh frontdesk-multiuser-ollama.js"

# Short triage:
STAGE_OVERRIDE='[{"duration":"60s","target":50}]' \
    nix-shell -p k6 --run "bash scripts/stress/_run-k6.sh \
        frontdesk-multiuser-mock.js"
```

The mock script writes `frontdesk-summary-mock.json`; the ollama
variant writes `frontdesk-summary-ollama.json`. Both are gitignored.

### When to re-run

- Before a Frontdesk-impacting release (anything touching
  `packaging/frontdesk-bundle/`, `cullis_connector/auth/`,
  `cullis_connector/ambassador/`, or the nginx sidecar in
  `packaging/frontdesk-bundle/nginx-tls/`).
- After any change to `LocalUserProvisioner` / `UserCredentialCache`
  semantics — per-user fork is the dominant overhead on the Frontdesk
  user-path.
- When a customer reports latency spikes at >10 concurrent users.

## Historical baselines

Per-release baseline runs are kept in the operator docs at
`site/src/content/docs/operate/capacity-planning.md` and in the
maintainer notes (`imp/stress-test-baseline-*.md`, local-only).
