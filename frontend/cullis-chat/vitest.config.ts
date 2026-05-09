import { defineConfig } from 'vitest/config';

/**
 * Vitest config — ADR-025 Phase 5.
 *
 * Pure unit tests for ``src/lib`` (auth client, fetch wrappers).
 * React component tests live separately under tests/e2e via
 * Playwright; Vitest stays node-environment to keep the bar low
 * (no jsdom, no testing-library) and the test runtime fast.
 */
export default defineConfig({
  test: {
    include: ['tests/unit/**/*.test.ts'],
    environment: 'node',
    globals: false,
    reporters: 'default',
    pool: 'forks',
    isolate: true,
  },
});
