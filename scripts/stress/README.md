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
| `dpop-egress.js` | DPoP signature verification + token issuance | TODO |
| `a2a-routing.js` | Intra-org A2A message dispatch via PDP + broker | TODO |
| `enrollment-burst.js` | Concurrent CSR issuance + DB insert | TODO |

`health-throughput.js`, `soak-stability.js`, and `intra-org-mastio-
burst.js` are wired today. The remaining scenarios are listed so
future work can land in one place. Each new scenario should keep the
same conventions: human-readable `handleSummary` for the maintainer +
a JSON dump (`summary.json`, `soak-summary.json`,
`intra-org-summary.json`) for diffable artefacts.

## How to run

```bash
# Bring up a Mastio stack (see operate/runbook.md for the full
# walkthrough). The script targets the public TLS edge by default.
./deploy.sh

# Run the scenario (override BASE_URL when the stack is elsewhere).
cd scripts/stress
nix-shell -p k6 --run "k6 run --insecure-skip-tls-verify health-throughput.js"

# Or against a remote stack:
BASE_URL=https://mastio.example.com:9443 \
    k6 run --insecure-skip-tls-verify health-throughput.js

# Soak (1h sustained 50 VUs, watch for RSS drift in a second terminal):
nix-shell -p k6 --run "k6 run --insecure-skip-tls-verify soak-stability.js"
docker stats --no-stream cullis-mastio-mcp-proxy-1   # in another shell

# Shorter soak smoke (e.g. validate the script itself):
SOAK_MINUTES=2 k6 run --insecure-skip-tls-verify soak-stability.js
```

The scripts write `summary.json` / `soak-summary.json` next to
themselves and print a one-screen text summary to stdout. Both JSON
artefacts are gitignored.

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

# 4. Run k6. Saves the raw ndjson stream + the summary export.
nix-shell -p k6 --run "k6 run --insecure-skip-tls-verify \
    --out json=scripts/stress/intra-org-results.ndjson \
    --summary-export=scripts/stress/intra-org-summary.json \
    scripts/stress/intra-org-mastio-burst.js"
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

## Historical baselines

Per-release baseline runs are kept in the operator docs at
`site/src/content/docs/operate/capacity-planning.md` and in the
maintainer notes (`imp/stress-test-baseline-*.md`, local-only).
