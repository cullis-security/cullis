# Cullis Chat

Identity-aware chat SPA for Cullis Frontdesk. Implements **ADR-019 Step 2**.

The browser talks Bearer (HttpOnly cookie) to this Astro server. The Astro
server forwards each call to the **Connector Ambassador** (ADR-019 Step 1,
PR #406, code in `cullis_connector/ambassador/`), which re-signs the request
as DPoP+mTLS and emits it to the Cullis cloud (proxy + Mastio).

```
[browser]──cookie──[cullis-chat (Astro :4321)]──Bearer──[Ambassador :7777]──DPoP+mTLS──[Cullis cloud]
```

## v0.1 surface

- 3-pane layout: empty sidebar (history lands in v0.5), chat main, optional dev audit panel
- Streaming SSE chat over `/v1/chat/completions` (OpenAI-compatible)
- Tool-use indicators inline ("calling postgres.query...")
- Identity badge with `principal_type` per ADR-020 (`user · mario`)
- Model picker fed by `/v1/models`
- Dev-only audit panel (right rail) gated by `PUBLIC_DEV_AUDIT_PANEL=1`. In
  production the audit chain belongs to the CISO/admin dashboard (Mastio),
  not to the end-user surface. Default off.
- No login (topology L: security boundary is the OS process; topology S adds
  reverse-proxy SSO upstream, see ADR-019 §2)

## Security (ADR-019 §6, hard requirements)

- Cookie `HttpOnly + Secure + SameSite=Strict`
- Strict CSP with per-request nonce, no `unsafe-inline`, no inline scripts
- All markdown rendered through DOMPurify with strict allowlist
- Code blocks via Shiki precomputed HTML (no runtime HTML interpolation)
- Origin / Referer / Sec-Fetch-Site enforced server-side on every POST
- `Authorization`, `Cookie`, `Set-Cookie` filtered from logs

## Dev

```bash
npm install

# Two terminals:
npm run dev:mock        # mock Ambassador on :7777 (Node, zero deps)
npm run dev             # Astro dev on :4321

# Open http://localhost:4321
```

To exercise the dev audit panel locally:

```bash
PUBLIC_DEV_AUDIT_PANEL=1 npm run dev
```

The Playwright config sets this automatically for the e2e suite.

## Build

```bash
npm run build           # produces dist/server/entry.mjs and dist/client/*
npm start               # serves on :4321 (override via HOST/PORT env)
```

## Container

```bash
docker build -t cullis/cullis-chat:dev .
docker run --rm -p 4321:4321 \
  -e CULLIS_AMBASSADOR_URL=http://host.docker.internal:7777 \
  -e CULLIS_LOCAL_TOKEN=dev-token \
  cullis/cullis-chat:dev
```

Two-stage build: a Node 22 alpine builder produces the standalone
Node bundle, the runtime stage drops to non-root (`cullis:cullis`)
and serves `dist/server/entry.mjs` directly. The Frontdesk
deployment image (future ADR-019 Step 4) will bundle this with the
Connector daemon under a supervisor.

## Test

```bash
npm run test:e2e:install   # one-time chromium download
npm run test:e2e           # Playwright e2e suite
```

The Playwright config spawns the mock Ambassador on `:7777` and the
Astro dev server on `:4321` automatically (`webServer:`). The dev
server is fed `CULLIS_LOCAL_TOKEN=test-token` so `/api/session/init`
can mint a cookie without a real Connector profile on disk.

Six specs (8 tests):
- `chat-happy-path.spec.ts`: empty state → send → streamed answer
- `tool-indicator.spec.ts`: pending → resolved chip with latency
- `audit-panel.spec.ts`: trace_id + latency + ADR-020 principal,
  cross-highlight on click
- `markdown-xss.spec.ts`: `__xss__` fixture, asserts DOMPurify strips
  every dangerous tag and no `dialog` event fires
- `model-picker.spec.ts`: 3 routed models, selection persists across
  reload via localStorage
- `csp-strict.spec.ts`: response headers on `/`, CSRF 403 on
  cross-origin `/api/session/init`, 401 on `/api/session/whoami`
  without cookie

NixOS / non-Ubuntu hosts: Chromium needs shared libraries that
`playwright install --with-deps` requires sudo to fetch. On NixOS
those libs aren't on the standard path, so the browser-driven tests
fail to launch locally. CI (Ubuntu in GitHub Actions) runs the full
suite. The 2 pure HTTP-request specs (`csp-strict` minus its first
test) pass on NixOS too.

## Deployment notes

The `output: 'server'` mode of Astro is required: the cookie-issuance and
Bearer-stripping forward endpoints under `/api/*` are server-side. This is a
**deviation from the original plan** (which suggested `dist/` would be served
as static files by `cullis_connector`); the rationale lives in the README and
the PR description: implementing `/api/*` in Python would require touching
`cullis_connector/`, which is out of scope for this PR. Future option: collapse
the Astro server into the Connector daemon (ADR-019 Step 4-ish), but not now.

In production the Frontdesk container runs two processes (Astro server +
Connector) under a small supervisor. Both bind to the same network namespace,
the Astro server forwards via `127.0.0.1:7777`.

## Files

- `src/pages/index.astro` — chat shell
- `src/pages/api/session/init.ts` — issues the HttpOnly cookie from `local.token`
- `src/pages/api/proxy/[...path].ts` — Bearer-stripping forward to Ambassador
- `src/middleware.ts` — CSP nonce + Origin/Referer enforcement
- `src/components/` — React islands
- `src/lib/` — markdown, sse, principal, api, types
- `src/styles/tokens.css` — palette + fonts (mirrors `site/src/styles/global.css`)
- `mock/ambassador.mjs` — Node mock backend for dev + CI Playwright
- `tests/e2e/` — Playwright specs

## Accepted advisories

`npm audit` flags 2 moderate advisories that are accepted for v0.1:

- **GHSA-j687-52p2-xcff** — Astro `define:vars` XSS. Not used in this codebase
  (grep `define:vars` to verify). Fixed in Astro 6.x; we cannot adopt 6 yet
  because it requires Node 22.12+ and our toolchain pins Node 20.
- **GHSA-3rmj-9m5h-8fpv / GHSA-c57f-mm3j-27q9** — `@astrojs/node` Server Islands
  DoS + `if-match` cache poisoning. Server Islands are disabled (no
  `server:defer` directive in this codebase). Header normalisation happens
  upstream of the Astro server in production (reverse proxy in topology S,
  Connector loopback in topology L).

When the Node 22.12+ toolchain becomes available across the project, bump to
Astro 6 + `@astrojs/node` 10 in a dedicated PR.

## Related ADRs

- `imp/adr-019-cullis-frontdesk.md` — overall decision
- `imp/adr-019-cullis-frontdesk-plan.md` — Step 2 detail
- `imp/adr-020-user-principal-and-quadrants.md` — `principal_type` taxonomy
