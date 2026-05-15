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
| `dpop-egress.js` | DPoP signature verification + token issuance | TODO |
| `a2a-routing.js` | Intra-org A2A message dispatch via PDP + broker | TODO |
| `enrollment-burst.js` | Concurrent CSR issuance + DB insert | TODO |

`health-throughput.js` and `soak-stability.js` are wired today. The
remaining scenarios are listed so future work can land in one place.
Each new scenario should keep the same conventions: human-readable
`handleSummary` for the maintainer + a JSON dump (`summary.json` or
`soak-summary.json`) for diffable artefacts.

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

## Historical baselines

Per-release baseline runs are kept in the operator docs at
`site/src/content/docs/operate/capacity-planning.md` and in the
maintainer notes (`imp/stress-test-baseline-*.md`, local-only).
