// Cullis Mastio intra-org enterprise burst (C2.A.1 baseline).
//
// Each VU = one pre-enrolled "stress-NNNNN" agent. VU cycle is:
//   1. POST /v1/auth/token   — client_assertion (ES256, x5c) + DPoP proof.
//      Issued LOCAL_TOKEN is cached for the rest of its lifetime so a VU
//      does not pay mint cost per iteration; the lifecycle still produces
//      a fresh DPoP proof every call so the JTI replay store sees real
//      traffic.
//   2. POST /v1/ingress/execute — fires a deliberately-unknown tool name
//      so the executor goes through the auth dep + DPoP verify + JTI
//      replay + log_audit path without invoking a real handler. That
//      exercises the same hot path real tool calls do for everything
//      we want to measure (auth, DPoP, audit chain) while keeping
//      handler cost effectively zero.
//
// Pre-conditions:
//   - ``scripts/stress/bulk_enroll_agents.py --n N --wipe`` has been run
//     against the target Mastio so ``stress_agents.json`` is present and
//     N matches the peak VU count below.
//   - The Mastio's external URL is reachable on BASE_URL (default
//     ``https://192.168.122.170:9443``).
//
// Run:
//   nix-shell -p k6 --run "k6 run --insecure-skip-tls-verify \\
//       --out json=intra-org-results.ndjson \\
//       scripts/stress/intra-org-mastio-burst.js"
//
// Output:
//   - stdout summary (per-stage tag breakdown when using k6's k6/x/output
//     parsing on the ndjson)
//   - ``intra-org-summary.json`` next to the script via ``handleSummary``
//
// Tuning hooks (env-driven):
//   - BASE_URL       — Mastio public URL (default
//                      ``https://192.168.122.170:9443``)
//   - HTU_OVERRIDE   — explicit htu the DPoP proof signs into (default
//                      derives from BASE_URL with the port stripped, see
//                      the smoke note in _auth_smoke.py)
//   - AGENT_FILE     — path to stress_agents.json (default sibling of
//                      this script)
//   - STAGE_OVERRIDE — JSON-encoded ramp override for triage runs:
//                      ``[{"duration":"60s","target":500},...]``
//   - THINK_MS       — optional fixed inter-cycle sleep (default 0)
//   - REQ_TIMEOUT_S  — http timeout (default 30)

import http from "k6/http";
import encoding from "k6/encoding";
import { check, sleep, fail } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";
import { SharedArray } from "k6/data";


// ── Tunables ──────────────────────────────────────────────────────────

const BASE_URL = __ENV.BASE_URL || "https://192.168.122.170:9443";
const AGENT_FILE = __ENV.AGENT_FILE || "./stress_agents.json";
const THINK_MS = parseInt(__ENV.THINK_MS || "0", 10);
const REQ_TIMEOUT = `${parseInt(__ENV.REQ_TIMEOUT_S || "30", 10)}s`;
// Token re-mint margin: cull each LOCAL_TOKEN 60s before its true expiry.
const TOKEN_REUSE_MARGIN_MS = 60 * 1000;

// ``HTU_OVERRIDE`` lets the operator force a specific htu when nginx
// rewrites the Host header in non-obvious ways (audited gotcha:
// ``$host`` strips the port, so DPoP htu has to match the port-less
// form even when the client targets the :9443 sidecar).
const DEFAULT_HTU = (__ENV.HTU_OVERRIDE
    || BASE_URL.replace(/:(\d+)$/, "")) + "/v1/auth/token";
const INGRESS_HTU = (__ENV.HTU_OVERRIDE
    || BASE_URL.replace(/:(\d+)$/, "")) + "/v1/ingress/execute";


// ── Stages ────────────────────────────────────────────────────────────

const DEFAULT_STAGES = [
    { duration: "60s",  target: 50 },
    { duration: "300s", target: 50 },
    { duration: "60s",  target: 500 },
    { duration: "300s", target: 500 },
    { duration: "60s",  target: 2000 },
    { duration: "300s", target: 2000 },
    { duration: "60s",  target: 5000 },
    { duration: "600s", target: 5000 },
    { duration: "60s",  target: 0 },
];

const STAGES = __ENV.STAGE_OVERRIDE
    ? JSON.parse(__ENV.STAGE_OVERRIDE)
    : DEFAULT_STAGES;


// ── Shared data ───────────────────────────────────────────────────────

// SharedArray cost: load + JSON-parse once, then VMs share the same
// underlying memory. For 5000 agents the file is ~8 MB; without
// SharedArray every VU would deep-copy that into its own VM.
const AGENTS = new SharedArray("stress-agents", () => {
    const bundle = JSON.parse(open(AGENT_FILE));
    if (!bundle.agents || bundle.agents.length === 0) {
        fail(`AGENT_FILE ${AGENT_FILE} contains no agents`);
    }
    return bundle.agents;
});


// ── Metrics ───────────────────────────────────────────────────────────

const mintLatency = new Trend("cullis_mint_latency_ms");
const ingressLatency = new Trend("cullis_ingress_latency_ms");
const mintErrors = new Rate("cullis_mint_error_rate");
const ingressErrors = new Rate("cullis_ingress_error_rate");
const tokenReuse = new Counter("cullis_token_reuse");
const tokenMint = new Counter("cullis_token_mint");
const dpopNonceRetry = new Counter("cullis_dpop_nonce_retry");


// ── Options ───────────────────────────────────────────────────────────

export const options = {
    insecureSkipTLSVerify: true,
    discardResponseBodies: false,
    summaryTrendStats: ["avg", "min", "med", "p(95)", "p(99)", "max"],
    scenarios: {
        intra_org_burst: {
            executor: "ramping-vus",
            startVUs: 0,
            stages: STAGES,
            gracefulRampDown: "30s",
        },
    },
    thresholds: {
        // Stress test, not pre-release gate — keep thresholds loose so
        // k6 does not exit non-zero on the first plateau spike. We use
        // the values to flag where the curve goes off rather than to
        // block CI.
        "cullis_mint_error_rate": ["rate<0.50"],
        "cullis_ingress_error_rate": ["rate<0.50"],
    },
};


// ── Helpers ───────────────────────────────────────────────────────────

// 8-bit safe (ASCII) — k6 lacks WHATWG TextEncoder. JWT inputs
// (base64url JSON, RFC 3339 timestamps, hex jti) are always ASCII so
// this is sufficient. Multi-byte UTF-8 would need a proper polyfill.
const enc = {
    encode(str) {
        const buf = new Uint8Array(str.length);
        for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i) & 0xff;
        return buf.buffer;
    },
};

function b64urlEncodeBytes(bytes) {
    // k6's ``encoding.b64encode`` accepts ArrayBuffer directly. Passing
    // it through ``String.fromCharCode`` first would re-interpret bytes
    // >= 0x80 as UTF-16 codepoints, which encoding.b64encode then
    // UTF-8 encodes — the sig grows from 64 bytes to ~110 and the
    // server rejects the JWT with "Signature verification failed".
    const std = encoding.b64encode(bytes);
    return std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlEncodeStr(str) {
    const std = encoding.b64encode(str);
    return std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64stdToBuffer(b64) {
    // ``b64decode(s, "std")`` returns ArrayBuffer when no 3rd arg.
    // Required for binary input to crypto.subtle.importKey.
    return encoding.b64decode(b64, "std");
}

function pemBodyToBuffer(pem) {
    const body = pem.replace(/-----[^-]+-----|\s/g, "");
    return b64stdToBuffer(body);
}

function randomJti() {
    // Lightweight UUID-ish: 16 hex chars from Math.random — sufficient
    // for jti replay collision-avoidance in a single run (DPoP rejects
    // server-side anyway).
    let s = "";
    for (let i = 0; i < 16; i++) {
        s += Math.floor(Math.random() * 16).toString(16);
    }
    return s + "-" + Date.now();
}

async function importPkcs8(pem) {
    return await crypto.subtle.importKey(
        "pkcs8", pemBodyToBuffer(pem),
        { name: "ECDSA", namedCurve: "P-256" },
        false, ["sign"],
    );
}

async function signJwt(privKey, headerObj, payloadObj) {
    const headerB64 = b64urlEncodeStr(JSON.stringify(headerObj));
    const payloadB64 = b64urlEncodeStr(JSON.stringify(payloadObj));
    const signing = `${headerB64}.${payloadB64}`;
    const sigBuf = await crypto.subtle.sign(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        privKey, enc.encode(signing),
    );
    return `${signing}.${b64urlEncodeBytes(sigBuf)}`;
}

async function ath(token) {
    // base64url(SHA-256(access_token)). We use the WebCrypto digest
    // since k6/crypto only exposes the legacy ``sha256`` helper.
    const digest = await crypto.subtle.digest(
        "SHA-256", enc.encode(token),
    );
    return b64urlEncodeBytes(digest);
}


// ── Per-VU state cache ────────────────────────────────────────────────

const vuCache = new Map();  // keyed by __VU index

async function getAgentState() {
    let state = vuCache.get(__VU);
    if (state) return state;

    const agent = AGENTS[(__VU - 1) % AGENTS.length];
    const [leafKey, dpopKey] = await Promise.all([
        importPkcs8(agent.leaf_priv_pkcs8_pem),
        importPkcs8(agent.dpop_priv_pkcs8_pem),
    ]);

    // Pre-compute the cert DER (base64-std) for x5c — the PEM body is
    // already standard base64, so re-encoding is a no-op.
    const certB64 = agent.cert_pem
        .replace(/-----[^-]+-----|\s/g, "");
    state = {
        agent,
        leafKey,
        dpopKey,
        certB64,
        token: null,
        tokenExpiresAt: 0,
        dpopNonce: null,
    };
    vuCache.set(__VU, state);
    return state;
}


// ── Auth + tool call ──────────────────────────────────────────────────

async function dpopProof(state, method, htu, accessToken) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        jti: randomJti(),
        htm: method.toUpperCase(),
        htu,
        iat: now,
    };
    if (accessToken !== null && accessToken !== undefined) {
        payload.ath = await ath(accessToken);
    }
    if (state.dpopNonce) payload.nonce = state.dpopNonce;
    return await signJwt(
        state.dpopKey,
        { typ: "dpop+jwt", alg: "ES256", jwk: state.agent.dpop_jwk_pub },
        payload,
    );
}

async function clientAssertion(state) {
    const now = Math.floor(Date.now() / 1000);
    return await signJwt(
        state.leafKey,
        { alg: "ES256", typ: "JWT", x5c: [state.certB64] },
        {
            sub: state.agent.agent_id, iss: state.agent.agent_id,
            aud: "agent-trust-broker",
            iat: now, exp: now + 300, jti: randomJti(),
        },
    );
}

async function mintToken(state) {
    const assertion = await clientAssertion(state);
    let proof = await dpopProof(state, "POST", DEFAULT_HTU, null);
    let resp = http.post(
        `${BASE_URL}/v1/auth/token`,
        JSON.stringify({ client_assertion: assertion }),
        {
            headers: {
                "Content-Type": "application/json",
                "DPoP": proof,
            },
            timeout: REQ_TIMEOUT,
            tags: { endpoint: "auth_token" },
        },
    );

    // Handle the server-nonce dance once. Mastio rotates the nonce every
    // 5 min, accepts current+previous, and the proof signs the new
    // value back into a follow-up request.
    if (resp.status === 401
        && resp.body
        && resp.body.indexOf("use_dpop_nonce") >= 0) {
        const nonce = resp.headers["Dpop-Nonce"] || resp.headers["dpop-nonce"];
        if (nonce) state.dpopNonce = nonce;
        dpopNonceRetry.add(1);
        proof = await dpopProof(state, "POST", DEFAULT_HTU, null);
        resp = http.post(
            `${BASE_URL}/v1/auth/token`,
            JSON.stringify({ client_assertion: assertion }),
            {
                headers: {
                    "Content-Type": "application/json",
                    "DPoP": proof,
                },
                timeout: REQ_TIMEOUT,
                tags: { endpoint: "auth_token", nonce_retry: "1" },
            },
        );
    }

    mintLatency.add(resp.timings.duration);
    const ok = resp.status === 200;
    mintErrors.add(!ok);
    if (!ok) {
        return null;
    }
    tokenMint.add(1);
    const body = resp.json();
    state.token = body.access_token;
    state.tokenExpiresAt = Date.now() + (body.expires_in * 1000) - TOKEN_REUSE_MARGIN_MS;
    return state.token;
}

async function ensureToken(state) {
    if (state.token && Date.now() < state.tokenExpiresAt) {
        tokenReuse.add(1);
        return state.token;
    }
    return await mintToken(state);
}

async function callTool(state, token) {
    const proof = await dpopProof(
        state, "POST", INGRESS_HTU, token,
    );
    // Deliberately unknown tool name: the executor still walks the auth
    // dep + DPoP verify + JTI replay + log_audit path, but skips any
    // real handler work. Same hot path as a real tool call would take
    // for the parts we are measuring.
    const body = JSON.stringify({
        tool: "cullis_stress_probe",
        parameters: {},
        request_id: randomJti(),
    });
    const resp = http.post(
        `${BASE_URL}/v1/ingress/execute`,
        body,
        {
            headers: {
                "Content-Type": "application/json",
                "Authorization": `DPoP ${token}`,
                "DPoP": proof,
            },
            timeout: REQ_TIMEOUT,
            tags: { endpoint: "ingress_execute" },
        },
    );
    ingressLatency.add(resp.timings.duration);
    // 200-with-error-body (tool not found is a 2xx in the executor's
    // contract) and 4xx both count as "request handled" from the
    // stress perspective. We treat anything non-5xx as success.
    const ok = resp.status < 500 && resp.status !== 0;
    ingressErrors.add(!ok);
    return ok;
}


// ── VU body ───────────────────────────────────────────────────────────

export default async function () {
    const state = await getAgentState();
    const token = await ensureToken(state);
    if (!token) {
        // Mint failed: skip the tool call so we do not produce noise on
        // the ingress metrics. The error rate already captured it.
        return;
    }
    await callTool(state, token);
    if (THINK_MS > 0) sleep(THINK_MS / 1000);
}


// ── Summary ───────────────────────────────────────────────────────────

export function handleSummary(data) {
    return {
        stdout: textSummary(data),
        "intra-org-summary.json": JSON.stringify(data, null, 2),
    };
}

function textSummary(data) {
    const m = data.metrics;
    function pct(metric, key) {
        return ((metric?.values?.[key]) || 0).toFixed(1);
    }
    const lines = [];
    lines.push("");
    lines.push("════ Cullis Mastio intra-org burst summary ════");
    lines.push("");
    lines.push(`  Base URL:           ${BASE_URL}`);
    lines.push(`  Agents loaded:      ${AGENTS.length}`);
    lines.push(`  Auth-token mints:   ${m.cullis_token_mint?.values?.count ?? 0}`);
    lines.push(`  Auth-token reuse:   ${m.cullis_token_reuse?.values?.count ?? 0}`);
    lines.push(`  DPoP nonce retries: ${m.cullis_dpop_nonce_retry?.values?.count ?? 0}`);
    lines.push(`  Total requests:     ${m.http_reqs?.values?.count ?? 0}`);
    lines.push(`  Requests per sec:   ${(m.http_reqs?.values?.rate ?? 0).toFixed(1)} RPS`);
    lines.push("");
    lines.push("  Mint /v1/auth/token:");
    lines.push(`    error rate   ${((m.cullis_mint_error_rate?.values?.rate ?? 0) * 100).toFixed(2)} %`);
    lines.push(`    avg / p50    ${pct(m.cullis_mint_latency_ms, "avg")} / ${pct(m.cullis_mint_latency_ms, "med")} ms`);
    lines.push(`    p95 / p99    ${pct(m.cullis_mint_latency_ms, "p(95)")} / ${pct(m.cullis_mint_latency_ms, "p(99)")} ms`);
    lines.push(`    max          ${pct(m.cullis_mint_latency_ms, "max")} ms`);
    lines.push("");
    lines.push("  Ingress /v1/ingress/execute:");
    lines.push(`    error rate   ${((m.cullis_ingress_error_rate?.values?.rate ?? 0) * 100).toFixed(2)} %`);
    lines.push(`    avg / p50    ${pct(m.cullis_ingress_latency_ms, "avg")} / ${pct(m.cullis_ingress_latency_ms, "med")} ms`);
    lines.push(`    p95 / p99    ${pct(m.cullis_ingress_latency_ms, "p(95)")} / ${pct(m.cullis_ingress_latency_ms, "p(99)")} ms`);
    lines.push(`    max          ${pct(m.cullis_ingress_latency_ms, "max")} ms`);
    lines.push("");
    return lines.join("\n");
}
