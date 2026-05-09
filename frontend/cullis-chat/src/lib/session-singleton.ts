import { ApiError, initSession } from './api';
import { fetchRuntimeInfo } from './auth';

/**
 * Idempotent session bootstrap. Three islands need the cookie before
 * their first call to `/v1/*` or `/api/session/whoami`: ChatApp (chat
 * completions), IdentityBadge (whoami), ModelPicker (list models).
 * Every island calls `ensureSession()`; only the first call hits
 * `/api/session/init`, the rest piggyback on the cached promise.
 *
 * ADR-025 Phase 5 — when the Connector is in local mode and
 * ``/api/session/init`` reports the caller is not signed in (401), we
 * redirect to ``/login`` so the user can authenticate. The redirect is
 * a one-shot side effect: the promise rejects so callers fail fast,
 * but the user does not see a transient error UI.
 */
let pending: Promise<void> | null = null;

const LOGIN_PATH = '/login';
const CHANGE_PASSWORD_PATH = '/change-password';

function pathIsAuthFlow(): boolean {
  if (typeof window === 'undefined') return false;
  const p = window.location.pathname;
  return p === LOGIN_PATH || p === CHANGE_PASSWORD_PATH;
}

/**
 * Best-effort redirect to ``/login``. Silently swallows redirect when
 * we are already on an auth-flow page, so the bootstrap on
 * ``/login`` itself does not loop.
 */
export function redirectToLogin(): void {
  if (typeof window === 'undefined') return;
  if (pathIsAuthFlow()) return;
  window.location.assign(LOGIN_PATH);
}

async function bootstrap(): Promise<void> {
  // ADR-025 Phase 5 follow-up (bug N20, 2026-05-09 VM dogfood):
  // ``/api/session/init`` is only mounted when the Connector runs in
  // shared mode (AMBASSADOR_MODE=shared). In local mode the SPA
  // already has its session cookie minted by /api/auth/login, so
  // calling /api/session/init returns 403 and clutters the UI with a
  // misleading error banner. Probe runtime-info first and skip the
  // legacy bootstrap when ``auth_mode === 'local'``.
  const info = await fetchRuntimeInfo();
  if (info && info.auth_mode === 'local') {
    // The local-mode session cookie was issued by /api/auth/login.
    // If the user is on a chat page without a valid cookie (cookie
    // expired, never logged in), the IdentityBadge whoami probe will
    // catch the 401 and redirect to /login — that's the right entry
    // point in local mode, NOT /api/session/init.
    return;
  }
  try {
    await initSession();
    return;
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      // Defensive: runtime-info absent (older Connector image) but
      // session/init says we are not signed in — assume local-mode
      // semantics and redirect to /login.
      if (!info) {
        redirectToLogin();
      }
    }
    throw err;
  }
}

export function ensureSession(): Promise<void> {
  if (!pending) {
    pending = bootstrap().catch((err) => {
      // Reset the cache on failure so a retry can happen, but propagate
      // the rejection to the caller so it can surface the error.
      pending = null;
      throw err;
    });
  }
  return pending;
}
