import type { APIRoute } from 'astro';
import { IS_DEV, SESSION_COOKIE, SESSION_TTL_SECONDS, readLocalToken } from '../../../lib/server/config';
import { logEvent } from '../../../lib/server/logger';

export const prerender = false;

/**
 * POST /api/session/init
 *
 * Reads the Connector's local Bearer token and stores it in an HttpOnly
 * cookie scoped to this origin. The browser never sees the token value;
 * it can only ride along on subsequent same-origin requests, which the
 * `/api/proxy/*` route translates back into an `Authorization: Bearer`
 * header to the Ambassador on `127.0.0.1:7777`.
 *
 * ADR-019 §6 axis 1 + 2 + 4:
 *   - Cookie is HttpOnly + Secure + SameSite=Strict
 *   - 30-min TTL, refreshed on each /api/session/init call
 *   - Token never leaves the server-side
 */
export const POST: APIRoute = async ({ cookies, request }) => {
  let token: string;
  try {
    token = readLocalToken();
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    logEvent('session_init_failed', { reason });
    return new Response(
      JSON.stringify({
        ok: false,
        error: 'connector_token_unavailable',
        message: IS_DEV ? reason : 'Run cullis-connector dashboard first.',
      }),
      { status: 503, headers: { 'Content-Type': 'application/json' } },
    );
  }

  cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: !IS_DEV,
    sameSite: 'strict',
    path: '/',
    maxAge: SESSION_TTL_SECONDS,
  });

  logEvent('session_init', {
    ip: request.headers.get('x-forwarded-for') ?? 'loopback',
    ttl: SESSION_TTL_SECONDS,
  });

  return new Response(JSON.stringify({ ok: true, ttl: SESSION_TTL_SECONDS }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};

/**
 * DELETE /api/session/init — explicit logout. Clears the cookie. Useful
 * for the future "switch profile" flow; not surfaced in the v0.1 UI yet.
 */
export const DELETE: APIRoute = async ({ cookies }) => {
  cookies.delete(SESSION_COOKIE, { path: '/' });
  logEvent('session_revoke', {});
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};
