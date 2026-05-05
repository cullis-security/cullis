import { defineConfig } from 'astro/config';
import react from '@astrojs/react';

// Cullis Chat SPA — ADR-019 Phase 8b-2b: pure static.
//
// All API routes were moved to the Connector (Phase 8a + 8b-2a) and the
// SPA's /api/proxy/* translator is gone (Phase 8b-1). With nothing
// dynamic left to render server-side, the SPA ships as static HTML + JS
// and is served by:
//
//   - Vite dev: ``npm run dev``, with /v1 + /api proxied to the mock
//     Ambassador (or a real Connector) on 7777.
//   - Frontdesk container: nginx serves dist/ + proxies /v1/* /api/* to
//     the Connector container (packaging/frontdesk-bundle/).
//   - Desktop installer (Phase 8c): FastAPI mounts dist/ at /chat and
//     serves the same /v1/* /api/* on the same origin.
// ``ASTRO_BASE`` env var lets the same source build for two topologies:
//
//   - Frontdesk container (packaging/frontdesk-bundle/): nginx serves
//     the SPA at ``/`` so the default ``base: '/'`` produces asset
//     URLs like ``/_astro/app.js`` that resolve against the bundle's
//     root.
//   - Desktop installer (Phase 8c): FastAPI mounts the SPA under
//     ``/chat/`` (the ``/`` route is the Connector dashboard). Asset
//     URLs need to live under ``/chat/_astro/...`` or the browser 404s
//     the entire CSS+JS payload and renders an unstyled page.
//
// scripts/build-spa.sh sets ``ASTRO_BASE=/chat`` before invoking npm
// run build for the Connector-staged copy. The Frontdesk Dockerfile
// keeps the default. API fetches in lib/api.ts use absolute paths
// (``/api/session/init`` etc) so they always hit the origin root,
// regardless of base.
const ASTRO_BASE = process.env.ASTRO_BASE || '/';

export default defineConfig({
  output: 'static',
  base: ASTRO_BASE,
  integrations: [react()],
  server: {
    port: 4321,
    host: '127.0.0.1',
  },
  vite: {
    server: {
      // Dev: forward both /v1/* and /api/* to the mock Ambassador.
      // The SPA's session bootstrap (POST /api/session/init), the
      // whoami badge (GET /api/session/whoami), and every chat /
      // model / tool call (/v1/*) all land on the Connector now.
      proxy: {
        '/v1': {
          target: process.env.CULLIS_AMBASSADOR_URL || 'http://127.0.0.1:7777',
          changeOrigin: true,
        },
        '/api': {
          target: process.env.CULLIS_AMBASSADOR_URL || 'http://127.0.0.1:7777',
          changeOrigin: true,
        },
      },
    },
    build: {
      // Shiki ships one chunk per language grammar. Each is lazy-loaded
      // at runtime, only when a code block of that language appears, so
      // the warning is a build-output cosmetic, not a transfer-size hit.
      chunkSizeWarningLimit: 1500,
    },
  },
});
