// Cullis Mastio: 1-hour soak / leak detection.
//
// Run with:
//   nix-shell -p k6 --run "k6 run --insecure-skip-tls-verify soak-stability.js"
//
// Companion to ``health-throughput.js``. Same endpoint, sustained 50
// VUs for one hour. Lets the operator watch RSS via ``docker stats``
// in a second terminal and confirm there's no slow leak in either the
// FastAPI process or the nginx sidecar.
//
// Thresholds are deliberately wider than the ramp scenario because
// the goal is leak detection over time, not peak RPS:
//
//   * p(95) < 250 ms (same)
//   * error rate < 0.5 % (steady-state should be cleaner than ramp)
//
// Override with: BASE_URL=https://example.com:9443 k6 run soak-stability.js
//
// Soak duration override: SOAK_MINUTES=15 k6 run soak-stability.js
// (Default 60. Useful for smoke-soaking the script change itself
// before committing.)

import http from "k6/http";
import { check } from "k6";
import { Rate, Trend } from "k6/metrics";

const BASE_URL = __ENV.BASE_URL || "https://localhost:9443";
const SOAK_MINUTES = parseInt(__ENV.SOAK_MINUTES || "60", 10);

export const options = {
    insecureSkipTLSVerify: true,
    // Default Trend stats omit p(99); declare explicitly so handleSummary
    // and threshold breaches both report it.
    summaryTrendStats: ["avg", "min", "med", "max", "p(95)", "p(99)"],
    scenarios: {
        soak: {
            executor: "constant-vus",
            vus: 50,
            duration: `${SOAK_MINUTES}m`,
        },
    },
    thresholds: {
        "http_req_failed": ["rate<0.005"],
        "http_req_duration{expected_response:true}": ["p(95)<250", "p(99)<500"],
    },
};

const failures = new Rate("cullis_soak_failure_rate");
const ok_latency = new Trend("cullis_soak_ok_latency_ms");

export default function () {
    const res = http.get(`${BASE_URL}/health`, { tags: { endpoint: "health" } });

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
        "soak-summary.json": JSON.stringify(data, null, 2),
    };
}

function textSummary(data) {
    const m = data.metrics;
    const lines = [];
    lines.push("");
    lines.push(`════ Cullis Mastio soak (${SOAK_MINUTES} min) summary ════`);
    lines.push("");
    lines.push(`  Base URL:           ${BASE_URL}`);
    lines.push(`  Requests total:     ${m.http_reqs?.values?.count ?? "?"}`);
    lines.push(`  Requests per sec:   ${(m.http_reqs?.values?.rate ?? 0).toFixed(1)} RPS`);
    lines.push(`  Errors:             ${((m.http_req_failed?.values?.rate ?? 0) * 100).toFixed(3)} %`);
    lines.push("");
    lines.push("  Latency (success-only):");
    const okMs = m.cullis_soak_ok_latency_ms?.values || {};
    lines.push(`    avg     ${(okMs.avg ?? 0).toFixed(1)} ms`);
    lines.push(`    p(50)   ${(okMs.med ?? 0).toFixed(1)} ms`);
    lines.push(`    p(95)   ${(okMs["p(95)"] ?? 0).toFixed(1)} ms`);
    lines.push(`    p(99)   ${(okMs["p(99)"] ?? 0).toFixed(1)} ms`);
    lines.push(`    max     ${(okMs.max ?? 0).toFixed(1)} ms`);
    lines.push("");
    lines.push("  Watch RSS drift in a second terminal:");
    lines.push("    docker stats --no-stream cullis-mastio-mcp-proxy-1");
    lines.push("    docker stats --no-stream cullis-mastio-enterprise-mcp-proxy-1");
    lines.push("");
    return lines.join("\n");
}
