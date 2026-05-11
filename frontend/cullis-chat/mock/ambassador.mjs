#!/usr/bin/env node
/**
 * Mock Connector Ambassador for Cullis Chat dev + Playwright CI.
 *
 * Stand-alone Node http server, zero npm dependencies, OpenAI-compatible
 * surface. Reproduces the contract of the real Ambassador (PR #406,
 * `cullis_connector/ambassador/`) for the routes the SPA actually uses:
 *
 *   GET  /v1/models                — model list
 *   GET  /v1/whoami                — ADR-020 principal shape
 *   POST /v1/chat/completions      — sync + SSE streaming, with optional
 *                                    server-side tool-use loop simulation
 *   POST /v1/mcp                   — JSON-RPC stub
 *   GET  /v1/ambassador/health     — for liveness probes
 *
 * Three answer fixtures drive the demo:
 *   1. plain chat        — no trigger words → simple markdown answer
 *   2. tool-use loop     — "gdpr" / "training" / "postgres" → sim. tool
 *                          call, custom SSE events, final answer
 *   3. streaming         — `stream: true` → SSE token-by-token
 *
 * Auth: any non-empty Bearer is accepted. The real Ambassador enforces
 * the local.token contract; the mock relaxes that so tests don't have
 * to manage on-disk state.
 */

import { createServer } from 'node:http';

const PORT = Number(process.env.PORT ?? 7777);
const HOST = process.env.HOST ?? '127.0.0.1';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function chunkify(text, size = 6) {
  const out = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out;
}

async function readJson(req) {
  return new Promise((resolve, reject) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      if (!buf) return resolve({});
      try {
        resolve(JSON.parse(buf));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function pickFixture(messages) {
  const last = messages?.at(-1)?.content ?? '';
  if (/__xss__/i.test(last)) return 'xss';
  if (/gdpr|training|postgres|compliance/i.test(last)) return 'tool';
  if (/sessions?|active/i.test(last)) return 'sessions';
  return 'plain';
}

const FIXTURES = {
  plain: {
    answer:
      "Hi. I'm **Cullis Chat**, the Cullis Frontdesk interface. " +
      "I can answer operational questions about your organisation's data " +
      "through the connected MCP tools. Try asking me about compliance, " +
      'active sessions, or GDPR training.',
    tools: [],
  },
  tool: {
    answer:
      "Yes. **Anna Bianchi** completed her GDPR training on *2025-09-12* (source: " +
      "the `gdpr_training_records` table in the compliance DB).\n\n" +
      "```sql\n" +
      "select employee, completion_date\n" +
      "  from gdpr_training_records\n" +
      "  where employee = 'Anna Bianchi';\n" +
      "```\n\n" +
      "A full scan across the Sales team shows **3 employees** past " +
      'the 12-month deadline. I can pull up the details if you want.',
    tools: [
      { name: 'postgres.query', latency_ms: 286 },
    ],
  },
  xss: {
    // Used by Playwright to verify DOMPurify strips dangerous tags from
    // assistant content. Triggered by the literal `__xss__` string.
    answer:
      '# XSS test heading\n\n' +
      'Inline script: <script>window.__cullis_xss = true; alert(1);</script>\n\n' +
      '![pwn](javascript:alert(2))\n\n' +
      '<img src=x onerror="window.__cullis_xss_img = true; alert(3)">\n\n' +
      '<a href="javascript:alert(4)">unsafe link</a>\n\n' +
      '<iframe src="javascript:alert(5)"></iframe>\n\n' +
      '<p onclick="alert(6)">click trap</p>\n\n' +
      'OK ' + 'final.',
    tools: [],
  },
  sessions: {
    answer:
      '**4 active sessions** in the last 24h:\n\n' +
      '| Agent | Org | Opened | State |\n' +
      '|---|---|---|---|\n' +
      '| `payments-bot` | acme | 2026-05-04 09:12 | live |\n' +
      '| `procurement-bot` | acme | 2026-05-04 10:48 | live |\n' +
      '| `risk-monitor` | acme | 2026-05-04 11:03 | live |\n' +
      '| `mario-laptop` | acme | 2026-05-04 12:21 | idle |\n\n' +
      'Each row is anchored to a trace_id verifiable in the audit chain.',
    tools: [
      { name: 'mastio.list_sessions', latency_ms: 142 },
    ],
  },
};

function newTraceId() {
  return 't_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

function jsonResponse(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...extraHeaders });
  res.end(JSON.stringify(body));
}

function unauthorized(res) {
  jsonResponse(res, 401, { error: { code: 'no_bearer', message: 'Bearer required' } });
}

// ─── Inbox in-memory store ──────────────────────────────────────────
// Seeded with one demo row so /inbox renders a real message in
// Playwright. send() appends, ack() flips delivery_state, archive()
// removes from the visible list. Mirrors the broker `InboxItem`
// shape (`app/inbox/router.py`).
const INBOX_MOCK = (() => {
  const nowIso = () => new Date().toISOString();
  const ttlIso = (h = 24) =>
    new Date(Date.now() + h * 3600 * 1000).toISOString();
  const seed = {
    msg_id: 'msg_seed_001',
    sender_org_id: 'mediterranean',
    sender_principal_type: 'agent',
    sender_name: 'night-reporter',
    subject: 'Cross-company-flagged claims · nightly summary',
    body:
      'Two claims flagged for cross-company review overnight:\n\n' +
      '  · CLM-2026-0412 (vehicle, asia-pacific)\n' +
      '  · CLM-2026-0419 (property, asia-pacific)\n\n' +
      'See the audit chain for full provenance.',
    delivery_state: 'pending',
    consent_id: null,
    enqueued_at: nowIso(),
    delivered_at: null,
    ttl_expires_at: ttlIso(72),
  };
  const rows = [seed];
  return {
    list() { return rows.filter((r) => r.delivery_state !== 'archived'); },
    send(body) {
      const msg_id = 'msg_' + Math.random().toString(36).slice(2, 10);
      rows.unshift({
        msg_id,
        sender_org_id: 'demo',
        sender_principal_type: 'user',
        sender_name: 'mario',
        subject: body?.subject ?? null,
        body: body?.body ?? '',
        delivery_state: 'pending',
        consent_id: null,
        enqueued_at: nowIso(),
        delivered_at: null,
        ttl_expires_at: ttlIso(24),
      });
      return { msg_id, inserted: true, quadrant: 'u2u' };
    },
    ack(msgId) {
      const row = rows.find((r) => r.msg_id === msgId);
      if (!row) return false;
      if (row.delivery_state === 'pending') {
        row.delivery_state = 'delivered';
        row.delivered_at = nowIso();
        return true;
      }
      return false;
    },
    archive(msgId) {
      const row = rows.find((r) => r.msg_id === msgId);
      if (!row) return false;
      row.delivery_state = 'archived';
      return true;
    },
  };
})();

// ─── Conversation history mock (Sprint 1 Step 6 PR-A backend) ────────
// In-memory map keyed by conversation id. Each conversation carries a
// title, timestamps, a soft-deleted flag, and a messages array. The
// Playwright SPA exercises every CRUD path; nothing here is persisted
// across mock restarts which matches the test expectations.
const CONV_MOCK = (() => {
  const nowIso = () => new Date().toISOString();
  const rows = new Map();
  function _summary(c) {
    return {
      id: c.id,
      title: c.title,
      created_at: c.created_at,
      updated_at: c.updated_at,
    };
  }
  return {
    list() {
      return Array.from(rows.values())
        .filter((c) => !c.deleted_at)
        .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
        .map(_summary);
    },
    create() {
      const id = 'c_' + Math.random().toString(36).slice(2, 12);
      const now = nowIso();
      const conv = {
        id,
        title: null,
        created_at: now,
        updated_at: now,
        deleted_at: null,
        messages: [],
      };
      rows.set(id, conv);
      return _summary(conv);
    },
    get(id) {
      const c = rows.get(id);
      if (!c || c.deleted_at) return null;
      return {
        ..._summary(c),
        messages: c.messages.map((m) => ({ ...m })),
      };
    },
    rename(id, title) {
      const c = rows.get(id);
      if (!c || c.deleted_at) return null;
      c.title = title ?? null;
      c.updated_at = nowIso();
      return _summary(c);
    },
    delete(id) {
      const c = rows.get(id);
      if (!c || c.deleted_at) return false;
      c.deleted_at = nowIso();
      return true;
    },
    append(id, msg) {
      const c = rows.get(id);
      if (!c || c.deleted_at) return null;
      const now = nowIso();
      const row = {
        role: msg.role,
        content: msg.content || '',
        tool_calls: msg.tool_calls ?? null,
        trace_id: msg.trace_id ?? null,
        created_at: now,
      };
      c.messages.push(row);
      c.updated_at = now;
      return row;
    },
    reset() {
      rows.clear();
    },
  };
})();

const server = createServer(async (req, res) => {
  // Loopback-only — same posture as the real Ambassador.
  if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress ?? '')) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('mock ambassador: loopback only');
    return;
  }

  const url = new URL(req.url ?? '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Health is unauthenticated (matches the real Ambassador convention).
  if (req.method === 'GET' && pathname === '/v1/ambassador/health') {
    jsonResponse(res, 200, { ok: true, mock: true });
    return;
  }

  // Mock-only test reset, sits ABOVE the bearer gate on purpose so the
  // Playwright beforeEach can wipe CONV_MOCK without juggling a fake
  // token. Not implemented by the real Ambassador.
  if (req.method === 'POST' && pathname === '/v1/conversations/_test/reset') {
    CONV_MOCK.reset();
    jsonResponse(res, 200, { ok: true });
    return;
  }

  // Session bootstrap is unauthenticated by design — it IS the path that
  // mints the cookie. ADR-019 Phase 8b-2b: the SPA static now calls
  // these directly (no Astro server in front).
  if (req.method === 'POST' && pathname === '/api/session/init') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie':
        'cullis_session=mock-token; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800',
    });
    res.end(JSON.stringify({ ok: true, ttl: 1800 }));
    return;
  }
  if (req.method === 'POST' && pathname === '/api/session/logout') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': 'cullis_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // Everything else needs Bearer or the `cullis_session` cookie
  // (ADR-019 Phase 8a: ``require_bearer`` on the real Ambassador
  // accepts either path; the mock now mirrors that). Any non-empty
  // value passes — the mock does not validate the token, the real
  // Ambassador's secrets.compare_digest is what matters in production.
  const auth = req.headers['authorization'];
  const hasBearer = auth && auth.toString().toLowerCase().startsWith('bearer ');
  const cookieHeader = req.headers['cookie'] || '';
  const hasSessionCookie = /(?:^|;\s*)cullis_session=[^;]+/.test(cookieHeader);
  if (!hasBearer && !hasSessionCookie) {
    return unauthorized(res);
  }

  if (req.method === 'GET' && pathname === '/v1/whoami') {
    // Single mode legacy shape — kept for back-compat. Shared mode
    // uses /api/session/whoami (below) with the cookie-payload shape.
    jsonResponse(res, 200, {
      spiffe_id: 'spiffe://demo.test/demo/user/mario',
      principal_type: 'user',
      name: 'mario',
      org: 'demo',
      trust_domain: 'demo.test',
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/session/whoami') {
    // ADR-019 Phase 8b-2a unified shape: both single and shared modes
    // now emit the wrapped ADR-020 ``principal`` subobject alongside
    // the legacy top-level fields. The SPA's IdentityBadge consumes
    // the wrapped shape directly with no client-side translation.
    jsonResponse(res, 200, {
      ok: true,
      principal: {
        spiffe_id: 'spiffe://demo.test/demo/user/mario',
        principal_type: 'user',
        name: 'mario',
        org: 'demo',
        trust_domain: 'demo.test',
        sub: 'mario@demo.test',
        source: 'shared',
      },
      principal_id: 'demo.test/demo/user/mario',
      sub: 'mario@demo.test',
      org: 'demo',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/v1/models') {
    jsonResponse(res, 200, {
      object: 'list',
      data: [
        { id: 'claude-haiku-4-5', object: 'model', owned_by: 'cullis-routed' },
        { id: 'claude-sonnet-4-6', object: 'model', owned_by: 'cullis-routed' },
        { id: 'claude-opus-4-7', object: 'model', owned_by: 'cullis-routed' },
      ],
    });
    return;
  }

  // ─── Inbox surface (ADR-020 Phase 4) ────────────────────────────
  // The mock keeps an in-memory list seeded with one demo message so
  // /inbox renders a real row in Playwright. POST /send appends a
  // synthetic msg_id and refreshes the list. Ack/archive are wired
  // for end-to-end coverage of the read/dismiss UI flows.
  if (req.method === 'GET' && pathname === '/v1/inbox') {
    jsonResponse(res, 200, INBOX_MOCK.list());
    return;
  }
  if (req.method === 'POST' && pathname === '/v1/inbox/send') {
    let body;
    try { body = await readJson(req); } catch {
      jsonResponse(res, 400, { error: { code: 'bad_json' } });
      return;
    }
    const result = INBOX_MOCK.send(body);
    jsonResponse(res, 201, result);
    return;
  }
  {
    const m = pathname.match(/^\/v1\/inbox\/([^/]+)\/(ack|archive)$/);
    if (m && req.method === 'POST') {
      const [, msgId, action] = m;
      if (action === 'ack') {
        const flipped = INBOX_MOCK.ack(msgId);
        jsonResponse(res, 200, { acked: flipped, msg_id: msgId });
      } else {
        const archived = INBOX_MOCK.archive(msgId);
        jsonResponse(res, 200, { archived, msg_id: msgId });
      }
      return;
    }
  }

  // ─── Conversation history surface (Sprint 1 Step 6) ────────────
  // Note: /v1/conversations/_test/reset is handled higher up, above the
  // bearer gate, so the Playwright beforeEach can call it without auth.
  if (pathname === '/v1/conversations') {
    if (req.method === 'GET') {
      jsonResponse(res, 200, CONV_MOCK.list());
      return;
    }
    if (req.method === 'POST') {
      jsonResponse(res, 201, CONV_MOCK.create());
      return;
    }
  }
  {
    const m = pathname.match(/^\/v1\/conversations\/([^/]+)(?:\/(messages))?$/);
    if (m) {
      const convId = m[1];
      const sub = m[2];
      if (!sub && req.method === 'GET') {
        const detail = CONV_MOCK.get(convId);
        if (detail) jsonResponse(res, 200, detail);
        else jsonResponse(res, 404, { error: { code: 'not_found' } });
        return;
      }
      if (!sub && req.method === 'PATCH') {
        let body;
        try { body = await readJson(req); } catch {
          jsonResponse(res, 400, { error: { code: 'bad_json' } });
          return;
        }
        const summary = CONV_MOCK.rename(convId, body?.title ?? null);
        if (summary) jsonResponse(res, 200, summary);
        else jsonResponse(res, 404, { error: { code: 'not_found' } });
        return;
      }
      if (!sub && req.method === 'DELETE') {
        const ok = CONV_MOCK.delete(convId);
        if (ok) {
          res.writeHead(204);
          res.end();
        } else {
          jsonResponse(res, 404, { error: { code: 'not_found' } });
        }
        return;
      }
      if (sub === 'messages' && req.method === 'POST') {
        let body;
        try { body = await readJson(req); } catch {
          jsonResponse(res, 400, { error: { code: 'bad_json' } });
          return;
        }
        const stored = CONV_MOCK.append(convId, body);
        if (stored) jsonResponse(res, 201, stored);
        else jsonResponse(res, 404, { error: { code: 'not_found' } });
        return;
      }
    }
  }

  if (req.method === 'POST' && pathname === '/v1/chat/completions') {
    let body;
    try {
      body = await readJson(req);
    } catch {
      jsonResponse(res, 400, { error: { code: 'bad_json' } });
      return;
    }

    const fixtureKey = pickFixture(body.messages);
    const fx = FIXTURES[fixtureKey];
    const traceId = newTraceId();
    const model = body.model ?? 'claude-haiku-4-5';
    const startedAt = Date.now();

    const toolHeader = fx.tools.map((t) => t.name).join(',');

    if (body.stream === true) {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'X-Cullis-Trace-Id': traceId,
        'X-Cullis-Tools-Used': toolHeader,
      });

      // Custom Cullis SSE events for tool-use indicators.
      for (const tool of fx.tools) {
        res.write(`event: tool_call_start\n`);
        res.write(`data: ${JSON.stringify({ tool: tool.name })}\n\n`);
        await sleep(180);
        res.write(`event: tool_call_end\n`);
        res.write(`data: ${JSON.stringify({ tool: tool.name, latency_ms: tool.latency_ms })}\n\n`);
        await sleep(60);
      }

      // Token chunks.
      const chunks = chunkify(fx.answer, 6);
      for (const chunk of chunks) {
        const piece = {
          id: traceId,
          object: 'chat.completion.chunk',
          model,
          choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }],
        };
        res.write(`data: ${JSON.stringify(piece)}\n\n`);
        await sleep(28);
      }

      // Final chunk + audit anchor.
      const audit = {
        id: traceId,
        object: 'chat.completion.chunk',
        model,
        choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
        cullis_audit: {
          trace_id: traceId,
          latency_ms: Date.now() - startedAt,
          tools: fx.tools,
          principal: {
            spiffe_id: 'spiffe://demo.test/demo/user/mario',
            principal_type: 'user',
          },
        },
      };
      res.write(`event: cullis_audit\n`);
      res.write(`data: ${JSON.stringify(audit.cullis_audit)}\n\n`);
      res.write(`data: ${JSON.stringify(audit)}\n\n`);
      res.write(`data: [DONE]\n\n`);
      res.end();
      return;
    }

    // Non-streaming
    jsonResponse(
      res,
      200,
      {
        id: traceId,
        object: 'chat.completion',
        model,
        choices: [
          {
            index: 0,
            message: { role: 'assistant', content: fx.answer },
            finish_reason: 'stop',
          },
        ],
        cullis_audit: {
          trace_id: traceId,
          latency_ms: Date.now() - startedAt,
          tools: fx.tools,
          principal: {
            spiffe_id: 'spiffe://demo.test/demo/user/mario',
            principal_type: 'user',
          },
        },
      },
      {
        'X-Cullis-Trace-Id': traceId,
        'X-Cullis-Tools-Used': toolHeader,
      },
    );
    return;
  }

  if (req.method === 'POST' && pathname === '/v1/mcp') {
    let body;
    try {
      body = await readJson(req);
    } catch {
      jsonResponse(res, 400, { error: { code: 'bad_json' } });
      return;
    }
    jsonResponse(res, 200, {
      jsonrpc: '2.0',
      id: body.id ?? 1,
      result: {
        mock: true,
        echo: body.method ?? null,
      },
    });
    return;
  }

  jsonResponse(res, 404, { error: { code: 'not_found', path: pathname } });
});

server.listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.log(`mock Cullis Ambassador (cullis-chat) on http://${HOST}:${PORT}`);
});

// Be tidy on Ctrl+C — useful in CI.
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.close(() => process.exit(0));
  });
}
