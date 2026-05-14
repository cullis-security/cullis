---
title: "Capacity planning"
description: "Throughput and latency baseline for the Cullis Mastio bundle, measurement methodology, and a recipe to repeat the test on your own hardware."
category: "Operate"
order: 7
updated: "2026-05-14"
---

# Capacity planning

This page gives you a defensible floor for how much traffic a single
Mastio container can take, plus the methodology to repeat the test on
your own hardware. CISO due-diligence usually asks "what RPS does this
sustain?": we answer with numbers, the script that produced them, and
the explicit caveats.

## Headline numbers

Measured against `mastio-enterprise-bundle-v0.3.0` on a development
workstation (AMD Ryzen 7 3700X, 16 logical cores, 31 GiB RAM, NixOS
kernel 7.0.0), enterprise license active with all nine plugins loaded:

- **Sustained throughput on `/health`:** ~ 1900 requests per second
  with zero errors across a four-minute mixed-load profile (ramp to
  50 VUs, hold, ramp to 100 VUs, ramp down).
- **Latency at that load:** p(50) = 22 ms, p(95) = 74 ms, p(99) = 96 ms,
  max = 106 ms: all measured end-to-end including TLS termination.
- **CPU headroom at 100 VUs:** the bundle did not saturate the host;
  nginx workers and the FastAPI process together stayed well under
  full core utilisation.

For a cloud VPS of similar shape (8+ cores, 8+ GiB RAM) we recommend
planning around a conservative **floor of ~ 1500 RPS sustained reads**
on the cheap path, and re-measuring on your own hardware before you
commit to numbers in an SLA.

## What the workload represents

The `health-throughput.js` k6 scenario exercises the full TLS edge
plus the nginx → mcp-proxy plumbing, but with the cheapest possible
FastAPI handler at the end. That makes it a useful **upper-bound
proxy** for "how many requests can the network layer of this stack
move per second before something other than the app layer becomes the
bottleneck".

Mixed workloads with DPoP signature verification, audit log writes,
or LLM gateway hops will be slower per request and will hit different
limits (CPU on signature math, IOPS on SQLite writes, upstream
provider rate limits respectively). Future revisions of this doc will
add scenarios that measure those paths: see *Limitations* below.

## Methodology

We ship the k6 script and the run recipe in the repo:

```bash
# Bring up the bundle (see operate/runbook.md for the full first-boot
# walkthrough).
./deploy.sh

# Clone the repo for the test harness: k6 scripts live in scripts/stress/
git clone https://github.com/cullis-security/cullis.git
cd cullis/scripts/stress

# Run the scenario against your stack
BASE_URL=https://your-mastio.example.com:9443 \
    k6 run --insecure-skip-tls-verify health-throughput.js
```

The script prints a one-screen summary at the end:

```
════ Cullis Mastio /health throughput summary ════

  Base URL:           https://your-mastio.example.com:9443
  Requests total:     464,136
  Requests per sec:   1933.9 RPS
  Errors:             0.000 %

  Latency (success-only):
    avg     27.3 ms
    p(50)   22.4 ms
    p(95)   74.4 ms
    p(99)   95.5 ms
    max     106.3 ms
```

It also writes `summary.json` next to the script for diffable
artefacts. The thresholds inside the script (p(95) < 250 ms, error
rate < 1 %) make k6 exit non-zero on breach, so the same file doubles
as a pre-release sanity gate you can wire into your own CI.

## Profile details

The default profile is a four-minute mixed shape:

| Phase | Duration | Virtual users |
|---|---|---|
| Ramp up | 30 s | 0 → 50 |
| Plateau | 120 s | 50 |
| Plateau | 60 s | 50 → 100 |
| Ramp down | 30 s | 100 → 0 |

You can override the profile by editing the `stages` array near the
top of the script. The shape is deliberately short so it fits inside a
"between deploys" window; for soak tests (sustained leak detection
over an hour or more), see the H7 follow-up below.

## Limitations

Two caveats worth quoting back to anyone asking for numbers:

- **Locally measured.** Cloud VPS instances at similar core counts
  typically run 20 - 30 % slower under the same workload. Re-measure
  on the hardware you intend to ship on. The recipe above is one
  command: there is no excuse not to.
- **`/health` is the cheapest endpoint.** It does TLS, nginx routing,
  and a FastAPI handler that returns immediately. Endpoints that do
  real work: `/v1/egress/...` with DPoP verification, `/v1/llm/...`
  through the embedded AI gateway, `/v1/agents/...` enrolment: are
  bound by separate limits (signature math, IOPS, upstream provider
  rate). We will publish per-scenario numbers as we add k6 scripts
  for them.

## Tuning levers we already pulled

The default bundle has nginx upstream keep-alive configured (pool
size 64, 1000 requests per connection, 60 s idle timeout) plus the
matching `proxy_set_header Connection` plumbing across every
location. Without those, the bundle hit a hard wall at about 600 RPS
on the same host because nginx exhausted ephemeral ports opening a
fresh TCP socket to mcp-proxy on every request. Upgrade from
`mastio-bundle-v0.4.2` (or earlier) to pick up the fix: and watch
your nginx error log for `Address not available` lines if you ever
build a custom sidecar that re-opens this hole.

## Followups (planned)

- **DPoP egress throughput**: measure how many `/v1/egress/...`
  calls per second the proxy can sign-and-verify. CPU-bound on the
  RSA/ECDSA path.
- **A2A intra-org routing**: measure end-to-end message dispatch
  through PDP plus broker plus E2E encryption.
- **Enrolment burst**: measure concurrent CSR issuance + DB insert.
- **Soak / leak detection**: one-hour continuous run at 50 VUs,
  watching RSS for drift.

The placeholders for each scenario live alongside the live script in
`scripts/stress/` in the repo.

## Hardware sizing rule of thumb

Until per-scenario numbers exist, we recommend sizing by the cheap
path floor and applying a per-feature multiplier from operational
experience rather than theory:

- **Up to ~ 1500 sustained RPS** of read-shaped traffic on a single
  Mastio container (~ 8 cores, ~ 8 GiB RAM).
- **Halve** that floor if every request also involves a DPoP
  signature verification.
- **Halve again** if every request takes the AI gateway path
  (upstream provider latency dominates anyway).
- Scale horizontally: multiple Mastio containers behind a load
  balancer, sharing the same Postgres: once you cross the floor.
  Standalone SQLite mode tops out before that point; Postgres mode
  scales linearly with replicas.

We will replace the rule of thumb with measured numbers as the k6
scenarios land.
