// Cullis Frontdesk multi-user Ollama burst.
//
// Customer-realistic stress: each VU logs in once, then loops
// chat_completion against the LLM provider configured on the Mastio
// (default Ollama qwen2.5:0.5b — see ``sandbox/dogfood-frontdesk.sh``
// for the bring-up). RPS curve reflects the FULL chat path including
// Ollama inference time, so latency numbers cannot be compared directly
// to the mock burst — read this as "what does the demo end-to-end look
// like under N concurrent users".
//
// VU cycle:
//   1. (first iteration) POST /api/auth/login → cookie jar caches
//      session, LocalUserProvisioner cache populated by Mastio CSR.
//   2. POST /v1/chat/completions with a short fixed prompt.
//
// Run::
//
//   nix-shell -p k6 --run "K6_SKIP_NDJSON=1 \\
//       bash scripts/stress/_run-k6.sh frontdesk-multiuser-ollama.js"
//
// Tuning hooks (env):
//   - USERS_FILE      path to stress_frontdesk_users.json
//   - STAGE_OVERRIDE  JSON ramp override
//   - THINK_MS        inter-iteration sleep (default 500 — LLM-bound)
//   - REQ_TIMEOUT_S   per-request timeout (default 60 — LLM cold start)
//   - MODEL           LiteLLM model identifier
//                     (default ollama_chat/qwen2.5:0.5b)
//   - MAX_TOKENS      cap on response length (default 16 — keep LLM cost low)

import http from "k6/http";
import { check, sleep, fail } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";
import { SharedArray } from "k6/data";


// ── Tunables ──────────────────────────────────────────────────────────

const USERS_FILE = __ENV.USERS_FILE || "./stress_frontdesk_users.json";
const THINK_MS = parseInt(__ENV.THINK_MS || "500", 10);
const REQ_TIMEOUT = `${parseInt(__ENV.REQ_TIMEOUT_S || "60", 10)}s`;
const MODEL = __ENV.MODEL || "ollama_chat/qwen2.5:0.5b";
const MAX_TOKENS = parseInt(__ENV.MAX_TOKENS || "16", 10);


// ── Stages ────────────────────────────────────────────────────────────

// Ollama on a single small model saturates quickly — lower ceilings
// than the mock burst on purpose. Override via STAGE_OVERRIDE on
// fatter LLM upstreams (e.g. cluster of Ollama replicas).
const DEFAULT_STAGES = [
    { duration: "30s",  target: 10 },
    { duration: "60s",  target: 10 },
    { duration: "30s",  target: 30 },
    { duration: "120s", target: 30 },
    { duration: "30s",  target: 50 },
    { duration: "120s", target: 50 },
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
    return bundle.users.map((u) => ({
        user_name: u.user_name,
        password: u.password,
        base_url: bundle.base_url,
    }));
});


// ── Metrics ───────────────────────────────────────────────────────────

const loginLatency = new Trend("cullis_fd_login_latency_ms");
const chatLatency = new Trend("cullis_fd_chat_latency_ms");
const loginErrors = new Rate("cullis_fd_login_error_rate");
const chatErrors = new Rate("cullis_fd_chat_error_rate");
const loginCount = new Counter("cullis_fd_login_count");
const chatCount = new Counter("cullis_fd_chat_count");
const chatTimeouts = new Counter("cullis_fd_chat_timeouts");


// ── Options ───────────────────────────────────────────────────────────

export const options = {
    insecureSkipTLSVerify: true,
    discardResponseBodies: false,
    summaryTrendStats: ["avg", "min", "med", "p(95)", "p(99)", "max"],
    scenarios: {
        frontdesk_ollama: {
            executor: "ramping-vus",
            startVUs: 0,
            stages: STAGES,
            gracefulRampDown: "30s",
        },
    },
    thresholds: {
        "cullis_fd_login_error_rate": ["rate<0.50"],
        "cullis_fd_chat_error_rate":  ["rate<0.50"],
    },
};


// ── Per-VU state ──────────────────────────────────────────────────────

const vuState = new Map();

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
    const ok = resp.status === 200;
    loginErrors.add(!ok);
    loginCount.add(1);
    return ok;
}

function chatCompletion(user) {
    const body = JSON.stringify({
        model: MODEL,
        messages: [
            { role: "user", content: "Reply with exactly the word: cullis" },
        ],
        max_tokens: MAX_TOKENS,
    });
    const resp = http.post(
        `${user.base_url}/v1/chat/completions`,
        body,
        {
            headers: {
                "Content-Type": "application/json",
                "Origin": user.base_url,
            },
            timeout: REQ_TIMEOUT,
            tags: { endpoint: "v1_chat_completions" },
        },
    );
    chatLatency.add(resp.timings.duration);
    const ok = resp.status === 200;
    chatErrors.add(!ok);
    chatCount.add(1);
    if (resp.status === 0) {
        // k6 reports status 0 on timeout / connection reset.
        chatTimeouts.add(1);
    }
    return ok;
}


// ── VU body ───────────────────────────────────────────────────────────

export default function () {
    let state = vuState.get(__VU);
    if (!state) {
        state = { loggedIn: false, user: getVuUser() };
        vuState.set(__VU, state);
    }

    if (!state.loggedIn) {
        if (!login(state.user)) {
            sleep(1);
            return;
        }
        state.loggedIn = true;
    }

    chatCompletion(state.user);

    if (THINK_MS > 0) sleep(THINK_MS / 1000);
}


// ── Summary ───────────────────────────────────────────────────────────

export function handleSummary(data) {
    return {
        stdout: textSummary(data),
        "frontdesk-summary-ollama.json": JSON.stringify(data, null, 2),
    };
}

function textSummary(data) {
    const m = data.metrics;
    function pct(metric, key) {
        return ((metric?.values?.[key]) || 0).toFixed(1);
    }
    const lines = [];
    lines.push("");
    lines.push("════ Cullis Frontdesk multi-user OLLAMA summary ════");
    lines.push("");
    lines.push(`  Users loaded:        ${MANIFEST.length}`);
    lines.push(`  Model:               ${MODEL}`);
    lines.push(`  Total requests:      ${m.http_reqs?.values?.count ?? 0}`);
    lines.push(`  Requests per sec:    ${(m.http_reqs?.values?.rate ?? 0).toFixed(1)} RPS`);
    lines.push(`  Logins:              ${m.cullis_fd_login_count?.values?.count ?? 0}`);
    lines.push(`  Chat calls:          ${m.cullis_fd_chat_count?.values?.count ?? 0}`);
    lines.push(`  Chat timeouts (0):   ${m.cullis_fd_chat_timeouts?.values?.count ?? 0}`);
    lines.push("");
    lines.push("  POST /api/auth/login:");
    lines.push(`    error rate   ${((m.cullis_fd_login_error_rate?.values?.rate ?? 0) * 100).toFixed(2)} %`);
    lines.push(`    avg / p50    ${pct(m.cullis_fd_login_latency_ms, "avg")} / ${pct(m.cullis_fd_login_latency_ms, "med")} ms`);
    lines.push(`    p95 / p99    ${pct(m.cullis_fd_login_latency_ms, "p(95)")} / ${pct(m.cullis_fd_login_latency_ms, "p(99)")} ms`);
    lines.push(`    max          ${pct(m.cullis_fd_login_latency_ms, "max")} ms`);
    lines.push("");
    lines.push("  POST /v1/chat/completions:");
    lines.push(`    error rate   ${((m.cullis_fd_chat_error_rate?.values?.rate ?? 0) * 100).toFixed(2)} %`);
    lines.push(`    avg / p50    ${pct(m.cullis_fd_chat_latency_ms, "avg")} / ${pct(m.cullis_fd_chat_latency_ms, "med")} ms`);
    lines.push(`    p95 / p99    ${pct(m.cullis_fd_chat_latency_ms, "p(95)")} / ${pct(m.cullis_fd_chat_latency_ms, "p(99)")} ms`);
    lines.push(`    max          ${pct(m.cullis_fd_chat_latency_ms, "max")} ms`);
    lines.push("");
    return lines.join("\n");
}
