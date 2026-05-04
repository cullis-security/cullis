/**
 * Server-side configuration. Reads env vars once at module load.
 *
 * Used by API endpoints under `src/pages/api/*` and by the middleware.
 * Never imported from React islands or client code.
 */

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const env = (key: string, fallback?: string): string | undefined => {
  const value = process.env[key];
  if (value === undefined || value === '') return fallback;
  return value;
};

/** Upstream Connector Ambassador. Always loopback in v0.1. */
export const AMBASSADOR_URL = env('CULLIS_AMBASSADOR_URL', 'http://127.0.0.1:7777')!;

/**
 * Active Connector profile name. The Ambassador stores its local Bearer
 * token at `~/.cullis-connector/profiles/<profile>/local.token` (mode 0600).
 */
export const CONNECTOR_PROFILE = env('CULLIS_CONNECTOR_PROFILE', 'default')!;

/**
 * Optional: explicit token-file path. Wins over the profile-based path.
 */
export const LOCAL_TOKEN_PATH = env('CULLIS_LOCAL_TOKEN_PATH');

/**
 * Optional: literal Bearer token (mostly for tests / mock scenarios).
 * If set, neither the file path nor the profile is consulted.
 */
export const LOCAL_TOKEN = env('CULLIS_LOCAL_TOKEN');

/** Cookie name for the Bearer-bound session. */
export const SESSION_COOKIE = 'cullis_session';

/** Cookie max-age — 30 minutes per ADR-019 §6 axis 1. */
export const SESSION_TTL_SECONDS = 30 * 60;

/**
 * Read the Connector's local Bearer token. Lookup order:
 *   1. CULLIS_LOCAL_TOKEN env (literal)
 *   2. CULLIS_LOCAL_TOKEN_PATH env (file path)
 *   3. ~/.cullis-connector/profiles/<profile>/local.token
 */
export function readLocalToken(): string {
  if (LOCAL_TOKEN) return LOCAL_TOKEN.trim();

  const path =
    LOCAL_TOKEN_PATH ??
    join(homedir(), '.cullis-connector', 'profiles', CONNECTOR_PROFILE, 'local.token');

  try {
    return readFileSync(path, 'utf8').trim();
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Cullis Chat: cannot read local Bearer token at "${path}". ` +
        'Either run `cullis-connector dashboard --profile <name>` first ' +
        'or set CULLIS_LOCAL_TOKEN / CULLIS_LOCAL_TOKEN_PATH. ' +
        `Underlying error: ${reason}`,
    );
  }
}

/** True in `astro dev`. False in build / `node ./dist/server/entry.mjs`. */
export const IS_DEV = import.meta.env.DEV === true;
