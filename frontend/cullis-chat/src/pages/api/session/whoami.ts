import type { APIRoute } from 'astro';
import { AMBASSADOR_URL, SESSION_COOKIE } from '../../../lib/server/config';
import { logEvent } from '../../../lib/server/logger';

export const prerender = false;

/**
 * GET /api/session/whoami
 *
 * Returns the current principal as resolved by the Ambassador. The SPA
 * uses this to populate the IdentityBadge in the TopBar.
 *
 * Implementation: read the Bearer cookie, forward to `/v1/whoami` on
 * the Ambassador, return the result verbatim. No token leaves the server.
 *
 * Shape (ADR-020):
 *   {
 *     spiffe_id: "spiffe://acme.test/acme/user/mario",
 *     principal_type: "user" | "agent" | "workload",
 *     name: "mario",
 *     org: "acme",
 *     trust_domain: "acme.test"
 *   }
 *
 * If the Ambassador does not yet expose /v1/whoami (Step 1 PR #406 is
 * principal-type-agnostic), we fall back to a minimal local-mode shape
 * inferred from the configured profile name.
 */
export const GET: APIRoute = async ({ cookies }) => {
  const token = cookies.get(SESSION_COOKIE)?.value;
  if (!token) {
    return new Response(JSON.stringify({ ok: false, error: 'no_session' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const upstream = await fetch(`${AMBASSADOR_URL}/v1/whoami`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (upstream.status === 404) {
      // Ambassador does not expose /v1/whoami yet — return a local shape
      // so the badge can still render something useful.
      return new Response(
        JSON.stringify({
          ok: true,
          principal: {
            spiffe_id: null,
            principal_type: 'user',
            name: 'local',
            org: 'local',
            trust_domain: null,
            source: 'fallback',
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

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
