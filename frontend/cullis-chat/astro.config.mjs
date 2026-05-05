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
export default defineConfig({
  output: 'static',
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
