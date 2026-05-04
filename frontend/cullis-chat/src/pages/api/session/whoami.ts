import type { APIRoute } from 'astro';
import { AMBASSADOR_URL, SESSION_COOKIE } from '../../../lib/server/config';
import { logEvent } from '../../../lib/server/logger';

export const prerender = false;

/**
 * GET /api/session/whoami
 *
 * Returns the current principal for the IdentityBadge in the TopBar.
 *
 * In **shared mode** (ADR-021) the Ambassador exposes
 * `/api/session/whoami` with the cookie payload shape
 * `{ principal_id, sub, org, exp }`. We translate it to the ADR-020
 * shape the IdentityBadge consumes:
 *
 *   {
 *     spiffe_id: "spiffe://acme.test/acme/user/mario",
 *     principal_type: "user" | "agent" | "workload",
 *     name: "mario",
 *     org: "acme",
 *     trust_domain: "acme.test"
 *   }
 *
 * In **single mode** the Ambassador has no whoami endpoint (it's a
 * one-user dashboard, identity is the Connector profile). We return
 * a local-shaped payload so the badge still renders.
 */
type SharedWhoami = {
  principal_id: string;
  sub: string;
  org: string;
  exp: number;
};

function principalFromSharedPayload(body: SharedWhoami) {
  // principal_id is `<trust-domain>/<org>/<principal-type>/<name>`
  const parts = body.principal_id.split('/');
  if (parts.length === 4) {
    const [trust_domain, org, principal_type, name] = parts;
    return {
      spiffe_id: `spiffe://${body.principal_id}`,
      principal_type,
      name,
      org,
      trust_domain,
      sub: body.sub,
      source: 'shared',
    };
  }
  // Malformed principal_id — surface what we have rather than crash.
  return {
    spiffe_id: null,
    principal_type: 'user',
    name: body.sub,
    org: body.org,
    trust_domain: null,
    sub: body.sub,
    source: 'shared-fallback',
  };
}

export const GET: APIRoute = async ({ cookies, request }) => {
  const token = cookies.get(SESSION_COOKIE)?.value;
  if (!token) {
    return new Response(JSON.stringify({ ok: false, error: 'no_session' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Forward the browser's cookies to the Ambassador so the
  // shared-mode `cullis_session` cookie reaches the server. The
  // Bearer is the local-token for single mode (kept for back-compat).
  const fwdHeaders: Record<string, string> = {
    Authorization: `Bearer ${token}`,
  };
  const fwdCookie = request.headers.get('cookie');
  if (fwdCookie) {
    fwdHeaders.Cookie = fwdCookie;
  }

  try {
    const upstream = await fetch(`${AMBASSADOR_URL}/api/session/whoami`, {
      method: 'GET',
      headers: fwdHeaders,
    });

    if (upstream.ok) {
      const body = (await upstream.json()) as SharedWhoami;
      return new Response(
        JSON.stringify({ ok: true, principal: principalFromSharedPayload(body) }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    if (upstream.status === 401 || upstream.status === 404) {
      // Single mode (no /api/session/whoami) or no shared cookie set.
      // Fall back to a local shape so the badge still renders.
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
