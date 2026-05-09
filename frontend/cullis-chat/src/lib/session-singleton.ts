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
  try {
    await initSession();
    return;
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      // Only chase the local-mode redirect when the Connector says
      // it is in local mode. In OIDC mode we let the caller surface
      // the error so the UI can render an SSO bootstrap link.
      const info = await fetchRuntimeInfo();
      if (info && info.auth_mode === 'local') {
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
