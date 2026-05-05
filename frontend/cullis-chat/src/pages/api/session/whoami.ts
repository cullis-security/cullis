import type { APIRoute } from 'astro';
import { AMBASSADOR_URL, SESSION_COOKIE } from '../../../lib/server/config';
import { logEvent } from '../../../lib/server/logger';

export const prerender = false;

/**
 * GET /api/session/whoami
 *
 * Cookie-forward to the Ambassador. After ADR-019 Phase 8b-2a both
 * single mode (cullis_connector/ambassador/session_routes.py) and
 * shared mode (cullis_connector/ambassador/shared/router.py) return
 * the same ADR-020 wrapped shape:
 *
 *   { ok, principal: { spiffe_id, principal_type, name, org,
 *                      trust_domain, sub, source },
 *     principal_id, sub, org, exp }
 *
 * No payload translation here — the SPA's ``lib/api.ts:whoami()``
 * consumes the wrapped shape directly. The "no cookie" early-return
 * stays so unauth callers see a stable ``{ok:false, error:"no_session"}``
 * 401 instead of whatever the upstream's missing-auth response happens
 * to look like (single mode returns 200+placeholder, shared mode 401
 * with a different body). Phase 8b-2 will remove this Astro route
 * entirely along with switching Astro to static; the contract then
 * lives on the Ambassador only.
 */
export const GET: APIRoute = async ({ cookies, request }) => {
  if (!cookies.get(SESSION_COOKIE)?.value) {
    return new Response(JSON.stringify({ ok: false, error: 'no_session' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const fwdHeaders: Record<string, string> = {};
  const fwdCookie = request.headers.get('cookie');
  if (fwdCookie) {
    fwdHeaders.Cookie = fwdCookie;
  }

  try {
    const upstream = await fetch(`${AMBASSADOR_URL}/api/session/whoami`, {
      method: 'GET',
      headers: fwdHeaders,
    });
    const body = await upstream.text();
    return new Response(body, {
      status: upstream.status,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    logEvent('whoami_upstream_error', { reason });
    return new Response(
      JSON.stringify({ ok: false, error: 'upstream_unreachable' }),
      { status: 502, headers: { 'Content-Type': 'application/json' } },
    );
  }
};
