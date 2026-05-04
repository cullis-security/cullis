import type { APIRoute } from 'astro';
import { AMBASSADOR_URL, SESSION_COOKIE } from '../../../lib/server/config';
import { logEvent } from '../../../lib/server/logger';

export const prerender = false;

/**
 * /api/proxy/<...rest>
 *
 * Bearer-stripping reverse proxy from the SPA to the Ambassador.
 *
 *   browser ──cookie──> /api/proxy/v1/chat/completions
 *                         │ swap cookie for `Authorization: Bearer <token>`
 *                         ▼
 *                 http://127.0.0.1:7777/v1/chat/completions
 *                         │ Ambassador re-signs DPoP+mTLS upstream
 *                         ▼
 *                       Cullis cloud
 *
 * Streaming: the upstream may return `text/event-stream`. We pipe the
 * raw body straight back as a ReadableStream, preserving SSE chunk
 * boundaries, so the SPA's EventSource-equivalent reader works.
 *
 * ADR-019 §6 axis 4: Authorization / Cookie / Set-Cookie are never
 * surfaced in error pages. CSRF (axis 3) is enforced by middleware.
 */
const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);

const handler: APIRoute = async ({ params, request, cookies }) => {
  if (!ALLOWED_METHODS.has(request.method)) {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const token = cookies.get(SESSION_COOKIE)?.value;
  if (!token) {
    return new Response(
      JSON.stringify({ ok: false, error: 'no_session', hint: 'POST /api/session/init first' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    );
  }

  // Reconstruct the upstream path. `params.path` is the part after /api/proxy/
  // — Astro presents it either as a string or string[] depending on the route.
  const subpath = Array.isArray(params.path) ? params.path.join('/') : (params.path ?? '');
  const incomingUrl = new URL(request.url);
  const upstreamUrl = `${AMBASSADOR_URL}/${subpath}${incomingUrl.search}`;

  // Build forward headers. We do NOT mirror cookies (each call is fresh
  // server-to-server) and we strip any client-supplied Authorization
  // (only our injected one is honoured).
  const fwdHeaders = new Headers();
  for (const [k, v] of request.headers.entries()) {
    const key = k.toLowerCase();
    if (key === 'cookie' || key === 'authorization' || key === 'host') continue;
    if (key === 'content-length') continue; // recomputed by fetch
    fwdHeaders.set(k, v);
  }
  fwdHeaders.set('Authorization', `Bearer ${token}`);
  fwdHeaders.set('X-Cullis-Source', 'cullis-chat-spa');

  let body: BodyInit | undefined;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    body = request.body ?? undefined;
  }

  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl, {
      method: request.method,
      headers: fwdHeaders,
      body,
      // @ts-expect-error — `duplex: 'half'` is required by the Node fetch
      // implementation when `body` is a streaming request body. Not yet in
      // the standard RequestInit type.
      duplex: 'half',
      redirect: 'manual',
    });
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    logEvent('proxy_upstream_error', {
      method: request.method,
      path: subpath,
      reason,
    });
    return new Response(
      JSON.stringify({ ok: false, error: 'upstream_unreachable' }),
      { status: 502, headers: { 'Content-Type': 'application/json' } },
    );
  }

  // Mirror upstream headers back to the client, except hop-by-hop and
  // anything that could leak our Bearer or rewrite cookies.
  const respHeaders = new Headers();
  upstream.headers.forEach((v, k) => {
    const key = k.toLowerCase();
    if (
      key === 'set-cookie' ||
      key === 'authorization' ||
      key === 'connection' ||
      key === 'transfer-encoding' ||
      key === 'keep-alive'
    ) {
      return;
    }
    respHeaders.set(k, v);
  });

  logEvent('proxy_call', {
    method: request.method,
    path: subpath,
    status: upstream.status,
    streaming: respHeaders.get('content-type')?.includes('event-stream') ?? false,
  });

  return new Response(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
};

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const PATCH = handler;
export const DELETE = handler;
