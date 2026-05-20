// Cullis Frontdesk multi-user mock burst.
//
// Stresses the Frontdesk user-path WITHOUT involving an LLM upstream, so
// the resulting RPS curve reflects auth + per-user credential fork +
// nginx TLS sidecar + Frontdesk -> Mastio mTLS hop — not the LLM.
//
// Each VU = one pre-seeded Frontdesk user (see
// ``scripts/stress/bulk_create_frontdesk_users.py``). First iteration
// per VU: POST /api/auth/login (cookie cached in the per-VU jar).
// Subsequent iterations: GET /v1/models loop. List models is cookie-
// authed, forwards to Mastio via the user cert minted by the
// LocalUserProvisioner during login.
//
// Run::
//
//   nix-shell -p k6 --run "K6_SKIP_NDJSON=1 \\
//       bash scripts/stress/_run-k6.sh frontdesk-multiuser-mock.js"
//
// Tuning hooks (env):
//
//   - USERS_FILE      path to stress_frontdesk_users.json
//                     (default sibling of this script)
//   - STAGE_OVERRIDE  JSON ramp override
//                     (e.g. '[{"duration":"30s","target":100}]')
//   - THINK_MS        inter-iteration sleep (default 0)
//   - REQ_TIMEOUT_S   per-request timeout (default 30)
//   - LOGIN_AT_START  if "1" (default), per-VU login on first iter;
//                     useful when pre-warmup populated the cache
//                     already and we just need the cookie

import http from "k6/http";
import { check, sleep, fail } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";
import { SharedArray } from "k6/data";


// ── Tunables ──────────────────────────────────────────────────────────

const USERS_FILE = __ENV.USERS_FILE || "./stress_frontdesk_users.json";
const THINK_MS = parseInt(__ENV.THINK_MS || "0", 10);
const REQ_TIMEOUT = `${parseInt(__ENV.REQ_TIMEOUT_S || "30", 10)}s`;
const LOGIN_AT_START = (__ENV.LOGIN_AT_START || "1") === "1";


// ── Stages ────────────────────────────────────────────────────────────

const DEFAULT_STAGES = [
    { duration: "30s",  target: 50 },
    { duration: "120s", target: 50 },
    { duration: "30s",  target: 200 },
    { duration: "120s", target: 200 },
    { duration: "30s",  target: 500 },
    { duration: "120s", target: 500 },
    { duration: "30s",  target: 0 },
];

const STAGES = __ENV.STAGE_OVERRIDE
    ? JSON.parse(__ENV.STAGE_OVERRIDE)
    : DEFAULT_STAGES;


// ── Shared data ───────────────────────────────────────────────────────

const MANIFEST = new SharedArray("frontdesk-users", () => {
    const bundle = JSON.parse(open(USERS_FILE));
    if (!bundle.users || bundle.users.length === 0) {
        fail(`USERS_FILE ${USERS_FILE} contains no users`);
    }
    if (!bundle.base_url) {
        fail(`USERS_FILE ${USERS_FILE} missing base_url`);
    }
    // SharedArray expects an array. We pack base_url onto each user so
    // the VU code can read it without crossing isolation boundaries.
    return bundle.users.map((u) => ({
        user_name: u.user_name,
        password: u.password,
        base_url: bundle.base_url,
    }));
});


// ── Metrics ───────────────────────────────────────────────────────────

const loginLatency = new Trend("cullis_fd_login_latency_ms");
const modelsLatency = new Trend("cullis_fd_models_latency_ms");
const loginErrors = new Rate("cullis_fd_login_error_rate");
const modelsErrors = new Rate("cullis_fd_models_error_rate");
const loginCount = new Counter("cullis_fd_login_count");
const modelsCount = new Counter("cullis_fd_models_count");
const provDeferred = new Counter("cullis_fd_provisioning_deferred");


// ── Options ───────────────────────────────────────────────────────────

export const options = {
    insecureSkipTLSVerify: true,
    discardResponseBodies: false,
    summaryTrendStats: ["avg", "min", "med", "p(95)", "p(99)", "max"],
    scenarios: {
        frontdesk_burst: {
            executor: "ramping-vus",
            startVUs: 0,
            stages: STAGES,
            gracefulRampDown: "30s",
        },
    },
    thresholds: {
        // Loose thresholds — this is a stress test, not a release gate.
        "cullis_fd_login_error_rate":  ["rate<0.50"],
        "cullis_fd_models_error_rate": ["rate<0.50"],
    },
};


// ── Per-VU state ──────────────────────────────────────────────────────

const vuState = new Map();  // VU index -> { loggedIn: bool, userIdx: int }

function getVuUser() {
    const idx = (__VU - 1) % MANIFEST.length;
    return MANIFEST[idx];
}


// ── Endpoints ─────────────────────────────────────────────────────────

function login(user) {
    const resp = http.post(
        `${user.base_url}/api/auth/login`,
        JSON.stringify({
            user_name: user.user_name,
            password: user.password,
        }),
        {
            headers: {
                "Content-Type": "application/json",
                "Origin": user.base_url,
            },
            timeout: REQ_TIMEOUT,
            tags: { endpoint: "auth_login" },
        },
    );
    loginLatency.add(resp.timings.duration);
    const ok = check(resp, {
        "login 200": (r) => r.status === 200,
    });
    loginErrors.add(!ok);
    loginCount.add(1);
    if (ok && resp.body) {
        // ``provisioning`` is one of ok / deferred / skipped. Count
        // deferred separately so the operator can spot Mastio outages
        // mid-run without parsing the full ndjson.
        if (resp.body.indexOf("\"provisioning\":\"deferred\"") >= 0) {
            provDeferred.add(1);
        }
    }
    return ok;
}

function listModels(user) {
    const resp = http.get(
        `${user.base_url}/v1/models`,
        {
            timeout: REQ_TIMEOUT,
            tags: { endpoint: "v1_models" },
        },
    );
    modelsLatency.add(resp.timings.duration);
    // 502 from Frontdesk means provisioning was deferred and the
    // upstream cert is missing — treat as model-call failure but
    // don't crash the VU; the next login may recover.
    const ok = resp.status === 200;
    modelsErrors.add(!ok);
    modelsCount.add(1);
    return ok;
}


// ── VU body ───────────────────────────────────────────────────────────

export default function () {
    let state = vuState.get(__VU);
    if (!state) {
        state = { loggedIn: false, user: getVuUser() };
        vuState.set(__VU, state);
    }

    if (LOGIN_AT_START && !state.loggedIn) {
        if (!login(state.user)) {
            // Failed login — sleep briefly so we don't burn CPU on
            // retry storms. The error rate already captured it.
            sleep(1);
            return;
        }
        state.loggedIn = true;
    }

    listModels(state.user);

    if (THINK_MS > 0) sleep(THINK_MS / 1000);
}


// ── Summary ───────────────────────────────────────────────────────────

export function handleSummary(data) {
    return {
        stdout: textSummary(data),
        "frontdesk-summary-mock.json": JSON.stringify(data, null, 2),
    };
}

function textSummary(data) {
    const m = data.metrics;
    function pct(metric, key) {
        return ((metric?.values?.[key]) || 0).toFixed(1);
    }
    const lines = [];
    lines.push("");
    lines.push("════ Cullis Frontdesk multi-user MOCK summary ════");
    lines.push("");
    lines.push(`  Users loaded:        ${MANIFEST.length}`);
    lines.push(`  Total requests:      ${m.http_reqs?.values?.count ?? 0}`);
    lines.push(`  Requests per sec:    ${(m.http_reqs?.values?.rate ?? 0).toFixed(1)} RPS`);
    lines.push(`  Logins:              ${m.cullis_fd_login_count?.values?.count ?? 0}`);
    lines.push(`  Models calls:        ${m.cullis_fd_models_count?.values?.count ?? 0}`);
    lines.push(`  Provisioning defer:  ${m.cullis_fd_provisioning_deferred?.values?.count ?? 0}`);
    lines.push("");
    lines.push("  POST /api/auth/login:");
    lines.push(`    error rate   ${((m.cullis_fd_login_error_rate?.values?.rate ?? 0) * 100).toFixed(2)} %`);
    lines.push(`    avg / p50    ${pct(m.cullis_fd_login_latency_ms, "avg")} / ${pct(m.cullis_fd_login_latency_ms, "med")} ms`);
    lines.push(`    p95 / p99    ${pct(m.cullis_fd_login_latency_ms, "p(95)")} / ${pct(m.cullis_fd_login_latency_ms, "p(99)")} ms`);
    lines.push(`    max          ${pct(m.cullis_fd_login_latency_ms, "max")} ms`);
    lines.push("");
    lines.push("  GET /v1/models:");
    lines.push(`    error rate   ${((m.cullis_fd_models_error_rate?.values?.rate ?? 0) * 100).toFixed(2)} %`);
    lines.push(`    avg / p50    ${pct(m.cullis_fd_models_latency_ms, "avg")} / ${pct(m.cullis_fd_models_latency_ms, "med")} ms`);
    lines.push(`    p95 / p99    ${pct(m.cullis_fd_models_latency_ms, "p(95)")} / ${pct(m.cullis_fd_models_latency_ms, "p(99)")} ms`);
    lines.push(`    max          ${pct(m.cullis_fd_models_latency_ms, "max")} ms`);
    lines.push("");
    return lines.join("\n");
}
