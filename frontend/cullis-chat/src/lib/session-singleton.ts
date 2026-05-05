import { initSession } from './api';

/**
 * Idempotent session bootstrap. Three islands need the cookie before
 * their first call to `/v1/*` or `/api/session/whoami`: ChatApp (chat
 * completions), IdentityBadge (whoami), ModelPicker (list models).
 * Every island calls `ensureSession()`; only the first call hits
 * `/api/session/init`, the rest piggyback on the cached promise.
 */
let pending: Promise<void> | null = null;

export function ensureSession(): Promise<void> {
  if (!pending) {
    pending = initSession()
      .then(() => undefined)
      .catch((err) => {
        // Reset the cache on failure so a retry can happen, but propagate
        // the rejection to the caller so it can surface the error.
        pending = null;
        throw err;
      });
  }
  return pending;
}
