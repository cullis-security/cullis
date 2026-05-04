import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import node from '@astrojs/node';

// Cullis Chat SPA — ADR-019 Step 2.
// output: 'server' is required because /api/session/init and /api/proxy/* are
// dynamic endpoints (cookie issuance + Bearer-stripping forward to Ambassador).
// Static-only would push those into Python land, which the boundary forbids
// for this PR (cullis_connector/ is owned by ADR-019 Step 1, already merged).
export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  integrations: [react()],
  server: {
    port: 4321,
    host: '127.0.0.1',
  },
  vite: {
    server: {
      // Dev: forward any /v1/* miss to the local mock Ambassador so curl-style
      // probes work too. The SPA itself never calls /v1/* directly — it uses
      // /api/proxy/* — but this keeps the dev surface complete.
      proxy: {
        '/v1': {
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
