import { defineMiddleware } from 'astro:middleware';
import { randomBytes } from 'node:crypto';
import { IS_DEV } from './lib/server/config';
import { logEvent } from './lib/server/logger';

/**
 * Cullis Chat global middleware.
 *
 * Responsibilities (ADR-019 §6):
 *   - Generate a per-request CSP nonce, expose it as `Astro.locals.cspNonce`.
 *   - Enforce Origin / Referer / Sec-Fetch-Site on state-mutating /api/*
 *     requests (CSRF defence).
 *   - Set strict CSP + the standard hardening headers on every response.
 *
 * Notes:
 *   - In dev, Vite injects inline <style>/<script> blocks; we relax
 *     style-src + script-src with 'unsafe-inline' / 'unsafe-eval' so the
 *     dev surface still works. Production builds produce external assets
 *     and run with strict 'self' + nonce only.
 *   - Origin === expected is preferred. Referer is a fallback when Origin
 *     is missing (some browsers omit it on same-origin GETs, but on POSTs
 *     it is mandated by Fetch spec).
 */
export const onRequest = defineMiddleware(async (context, next) => {
  const nonce = randomBytes(16).toString('base64');
  context.locals.cspNonce = nonce;

  const url = new URL(context.request.url);
  const method = context.request.method;
  const isApi = url.pathname.startsWith('/api/');
  const isMutating = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';

  if (isApi && isMutating) {
    const origin = context.request.headers.get('origin');
    const referer = context.request.headers.get('referer');
    const fetchSite = context.request.headers.get('sec-fetch-site');
    const expectedOrigin = url.origin;

    const originOk = origin === expectedOrigin;
    let refererOk = false;
    if (!originOk && referer) {
      try {
        refererOk = new URL(referer).origin === expectedOrigin;
      } catch {
        refererOk = false;
      }
    }

    // Sec-Fetch-Site: 'same-origin' OK; 'none' (typed-in URL) only valid for
    // GETs we don't reach here. Anything else (cross-site/same-site) blocked.
    const fetchSiteOk = fetchSite === null || fetchSite === 'same-origin';

    if (!(originOk || refererOk) || !fetchSiteOk) {
      logEvent('csrf_reject', {
        path: url.pathname,
        origin,
        referer,
        fetchSite,
      });
      return new Response('Forbidden: cross-origin request rejected', {
        status: 403,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }
  }

  const response = await next();

  // CSP — built once per response, varies dev vs prod.
  //
  // CSP Level 3 quirk: when a nonce/hash source is present, `'unsafe-inline'`
  // is ignored. Vite's HMR injects `<style>` and `<script>` tags without our
  // nonce, so in dev we must drop the nonce sources and keep `'unsafe-inline'`
  // for the Vite-injected blocks. In prod, Astro emits external assets and
  // any deliberate inline carries the nonce — strict policy applies.
  const scriptSrc = ["'self'"];
  const styleSrc = ["'self'", 'https://fonts.googleapis.com', 'https://api.fontshare.com'];
  if (IS_DEV) {
    scriptSrc.push("'unsafe-eval'", "'unsafe-inline'");
    styleSrc.push("'unsafe-inline'");
  } else {
    scriptSrc.push(`'nonce-${nonce}'`);
    styleSrc.push(`'nonce-${nonce}'`);
  }

  const csp = [
    "default-src 'self'",
    `script-src ${scriptSrc.join(' ')}`,
    `style-src ${styleSrc.join(' ')}`,
    "font-src 'self' https://fonts.gstatic.com https://api.fontshare.com https://cdn.fontshare.com data:",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; ');

  response.headers.set('Content-Security-Policy', csp);
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'same-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  return response;
});
