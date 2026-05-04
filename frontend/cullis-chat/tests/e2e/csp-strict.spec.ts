import { expect, test } from '@playwright/test';

test('CSP + hardening headers are present on every response', async ({ page }) => {
  const response = await page.goto('/');
  expect(response).not.toBeNull();

  const headers = response!.headers();

  // CSP carries a per-request nonce + the strict directives we care about.
  const csp = headers['content-security-policy'];
  expect(csp).toBeTruthy();
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("base-uri 'self'");
  expect(csp).toContain("form-action 'self'");

  // In dev (Vite HMR injects un-nonced inline tags) the policy carries
  // 'unsafe-inline' instead of a nonce. Production builds emit external
  // assets and the policy is nonce-strict. Either path is acceptable
  // here — what we verify is that one of the two safe modes is in force.
  const scriptSrc = csp.match(/script-src ([^;]+)/)?.[1] ?? '';
  const styleSrc = csp.match(/style-src ([^;]+)/)?.[1] ?? '';
  expect(scriptSrc).toMatch(/'nonce-[A-Za-z0-9+/=]+'|'unsafe-inline'/);
  expect(styleSrc).toMatch(/'nonce-[A-Za-z0-9+/=]+'|'unsafe-inline'/);

  // Hardening trio
  expect(headers['x-content-type-options']).toBe('nosniff');
  expect(headers['x-frame-options']).toBe('DENY');
  expect(headers['referrer-policy']).toBe('same-origin');
  expect(headers['permissions-policy']).toContain('camera=()');
});

test('CSRF: cross-origin POST to /api/session/init is rejected', async ({ request }) => {
  const res = await request.post('http://127.0.0.1:4321/api/session/init', {
    headers: {
      Origin: 'http://evil.example.com',
      'Sec-Fetch-Site': 'cross-site',
      'Content-Type': 'application/json',
    },
    data: '{}',
    failOnStatusCode: false,
  });
  expect(res.status()).toBe(403);
});

test('whoami without cookie returns 401', async ({ request }) => {
  const res = await request.get('http://127.0.0.1:4321/api/session/whoami', {
    failOnStatusCode: false,
  });
  expect(res.status()).toBe(401);
  const body = await res.json();
  expect(body.ok).toBe(false);
  expect(body.error).toBe('no_session');
});
