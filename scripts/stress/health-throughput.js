// Cullis Mastio: /health throughput baseline.
//
// Run with:
//   nix-shell -p k6 --run "k6 run --insecure-skip-tls-verify health-throughput.js"
//
// Default target is the bundled mastio-nginx sidecar at https://localhost:9443.
// Override with: BASE_URL=https://example.com:9443 k6 run health-throughput.js
//
// Profile (cheap read-only probe: upper-bound RPS the public TLS edge can sustain):
//   30s   ramp  0 → 50 VUs
//   120s  plateau at 50 VUs
//   60s   plateau at 100 VUs
//   30s   ramp 100 → 0 VUs
//
// Threshold gates: p95 < 250 ms, error rate < 1 %.
// k6 exits non-zero if either is breached, so this script doubles as a
// pre-release sanity check.

import http from "k6/http";
import { check } from "k6";
import { Rate, Trend } from "k6/metrics";

const BASE_URL = __ENV.BASE_URL || "https://localhost:9443";

export const options = {
    insecureSkipTLSVerify: true,
    scenarios: {
        health_ramp: {
            executor: "ramping-vus",
            startVUs: 0,
            stages: [
                { duration: "30s", target: 50 },
                { duration: "120s", target: 50 },
                { duration: "60s", target: 100 },
                { duration: "30s", target: 0 },
            ],
            gracefulRampDown: "10s",
        },
    },
    thresholds: {
        "http_req_failed": ["rate<0.01"],
        "http_req_duration{expected_response:true}": ["p(95)<250", "p(99)<500"],
    },
};

const failures = new Rate("cullis_health_failure_rate");
const ok_latency = new Trend("cullis_health_ok_latency_ms");

export default function () {
    const res = http.get(`${BASE_URL}/health`, {
        tags: { endpoint: "health" },
    });

    const ok = check(res, {
        "status 200": (r) => r.status === 200,
        "body has status": (r) => r.body && r.body.includes("\"status\""),
    });

    failures.add(!ok);
    if (ok) {
        ok_latency.add(res.timings.duration);
    }
}

export function handleSummary(data) {
    return {
        stdout: textSummary(data),
        "summary.json": JSON.stringify(data, null, 2),
    };
}

function textSummary(data) {
    const m = data.metrics;
    const lines = [];
    lines.push("");
    lines.push("════ Cullis Mastio /health throughput summary ════");
    lines.push("");
    lines.push(`  Base URL:           ${BASE_URL}`);
    lines.push(`  Requests total:     ${m.http_reqs?.values?.count ?? "?"}`);
    lines.push(`  Requests per sec:   ${(m.http_reqs?.values?.rate ?? 0).toFixed(1)} RPS`);
    lines.push(`  Errors:             ${((m.http_req_failed?.values?.rate ?? 0) * 100).toFixed(3)} %`);
    lines.push("");
    lines.push("  Latency (success-only):");
    const okMs = m.cullis_health_ok_latency_ms?.values || {};
    lines.push(`    avg     ${(okMs.avg ?? 0).toFixed(1)} ms`);
    lines.push(`    p(50)   ${(okMs.med ?? 0).toFixed(1)} ms`);
    lines.push(`    p(95)   ${(okMs["p(95)"] ?? 0).toFixed(1)} ms`);
    lines.push(`    p(99)   ${(okMs["p(99)"] ?? 0).toFixed(1)} ms`);
    lines.push(`    max     ${(okMs.max ?? 0).toFixed(1)} ms`);
    lines.push("");
    return lines.join("\n");
}
