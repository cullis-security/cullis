/**
 * Vitest — auth client (ADR-025 Phase 5).
 *
 * Mocks global ``fetch`` to assert the request shape and the way the
 * client surfaces server responses (status, headers, error class).
 *
 * No DOM, no React. The auth React components are exercised by
 * Playwright e2e specs; this suite focuses on the wrapper contract
 * so a typo in a URL or a missing ``X-Admin-Secret`` header is
 * caught at the lib boundary.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ADMIN_SECRET_STORAGE_KEY,
  LoginError,
  adminCreateUser,
  adminDeleteUser,
  adminListUsers,
  adminResetPassword,
  changePassword,
  clearAdminSecret,
  fetchRuntimeInfo,
  loginLocal,
  logoutLocal,
  readAdminSecret,
  whoamiAuto,
  whoamiLocal,
  writeAdminSecret,
} from '../../src/lib/auth';

interface FakeFetchInit extends RequestInit {}

interface MockResponseInit {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

function mockResponse({ status = 200, body, headers = {} }: MockResponseInit = {}) {
  const text = body === undefined ? '' : JSON.stringify(body);
  const h = new Headers({ 'content-type': 'application/json', ...headers });
  return new Response(text, { status, headers: h });
}

const calls: { url: string; init: FakeFetchInit }[] = [];

beforeEach(() => {
  calls.length = 0;
  // Default — every test installs its own mock with .mockImplementation.
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: FakeFetchInit) => {
    calls.push({ url: String(input), init: init ?? {} });
    return mockResponse();
  }) as unknown as typeof fetch;

  // sessionStorage shim for node-environment runs.
  const store = new Map<string, string>();
  // vitest node env has no sessionStorage by default; install a minimal
  // Storage-shaped object on the global so the `auth.ts` helpers work.
  (globalThis as unknown as { sessionStorage: Storage }).sessionStorage = {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => { store.set(k, v); },
    removeItem: (k: string) => { store.delete(k); },
    clear: () => { store.clear(); },
    key: (i: number) => Array.from(store.keys())[i] ?? null,
    get length() { return store.size; },
  };
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ── loginLocal ────────────────────────────────────────────────────────

describe('loginLocal', () => {
  it('posts JSON body and returns the parsed payload on success', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async (input: RequestInfo | URL, init?: FakeFetchInit) => {
        calls.push({ url: String(input), init: init ?? {} });
        return mockResponse({
          status: 200,
          body: {
            ok: true,
            must_change_password: false,
            principal_name: 'mario',
            exp: 1234567890,
          },
        });
      },
    );
    const res = await loginLocal('mario', 'hunter2hunter2');
    expect(res.ok).toBe(true);
    expect(res.principal_name).toBe('mario');
    expect(calls[0].url).toBe('/api/auth/login');
    expect(calls[0].init.method).toBe('POST');
    const body = JSON.parse(String(calls[0].init.body ?? ''));
    expect(body).toEqual({ user_name: 'mario', password: 'hunter2hunter2' });
  });

  it('throws LoginError with status=401 on invalid credentials', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async () => mockResponse({ status: 401, body: { detail: 'invalid credentials' } }),
    );
    await expect(loginLocal('mario', 'wrong')).rejects.toMatchObject({
      details: { status: 401, detail: 'invalid credentials' },
    });
  });

  it('reads Retry-After on 429 and surfaces it in LoginError', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async () => mockResponse({
        status: 429,
        body: { detail: 'too many login attempts' },
        headers: { 'retry-after': '42' },
      }),
    );
    let caught: unknown = null;
    try {
      await loginLocal('mario', 'wrong');
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(LoginError);
    const e = caught as LoginError;
    expect(e.details.status).toBe(429);
    expect(e.details.retryAfter).toBe(42);
    expect(e.details.detail).toBe('too many login attempts');
  });

  it('marks provisioning=deferred when the X-Cullis-Provisioning-Failed header is present', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async () => mockResponse({
        status: 200,
        body: {
          ok: true,
          must_change_password: false,
          principal_name: 'mario',
          exp: 1234567890,
        },
        headers: { 'x-cullis-provisioning-failed': 'true' },
      }),
    );
    const res = await loginLocal('mario', 'pw');
    expect(res.provisioning).toBe('deferred');
  });
});

// ── logoutLocal / changePassword / whoamiLocal ────────────────────────

describe('logoutLocal', () => {
  it('POSTs /api/auth/logout', async () => {
    await logoutLocal();
    expect(calls[0].url).toBe('/api/auth/logout');
    expect(calls[0].init.method).toBe('POST');
  });
});

describe('changePassword', () => {
  it('posts old/new password and parses the response', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async (input: RequestInfo | URL, init?: FakeFetchInit) => {
        calls.push({ url: String(input), init: init ?? {} });
        return mockResponse({
          status: 200,
          body: {
            ok: true,
            must_change_password: false,
            principal_name: 'mario',
            exp: 1234567890,
          },
        });
      },
    );
    const res = await changePassword('old', 'newpassword1');
    expect(res.ok).toBe(true);
    expect(calls[0].url).toBe('/api/auth/change-password');
    const body = JSON.parse(String(calls[0].init.body ?? ''));
    expect(body).toEqual({ old_password: 'old', new_password: 'newpassword1' });
  });
});

describe('whoamiLocal', () => {
  it('returns the parsed cookie echo', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async () => mockResponse({
        status: 200,
        body: { user_name: 'mario', principal_name: 'mario', must_change_password: false, exp: 1 },
      }),
    );
    const res = await whoamiLocal();
    expect(res.user_name).toBe('mario');
  });
});

// ── whoamiAuto fallback ───────────────────────────────────────────────

describe('whoamiAuto', () => {
  it('returns ADR-020 principal when /api/session/whoami succeeds', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === '/api/session/whoami') {
          return mockResponse({
            status: 200,
            body: {
              ok: true,
              principal: {
                spiffe_id: 'spiffe://demo/agent/x',
                principal_type: 'agent',
                name: 'agent-x',
                org: 'demo',
                trust_domain: 'demo',
              },
            },
          });
        }
        throw new Error(`unexpected url ${url}`);
      },
    );
    const res = await whoamiAuto();
    expect(res.source).toBe('session');
    expect(res.principal.principal_type).toBe('agent');
    expect(res.principal.name).toBe('agent-x');
  });

  it('falls back to /api/auth/whoami-local on 401 and synthesises a user principal', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === '/api/session/whoami') {
          return mockResponse({ status: 401, body: { detail: 'unauthenticated' } });
        }
        if (url === '/api/auth/whoami-local') {
          return mockResponse({
            status: 200,
            body: {
              user_name: 'mario',
              principal_name: 'mario',
              must_change_password: false,
              exp: 1,
            },
          });
        }
        throw new Error(`unexpected url ${url}`);
      },
    );
    const res = await whoamiAuto();
    expect(res.source).toBe('local');
    expect(res.principal.principal_type).toBe('user');
    expect(res.principal.name).toBe('mario');
    expect(res.principal.spiffe_id).toBeNull();
  });

  it('re-throws on 5xx from /api/session/whoami', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async () => mockResponse({ status: 500, body: { detail: 'boom' } }),
    );
    await expect(whoamiAuto()).rejects.toMatchObject({ status: 500 });
  });
});

// ── runtime-info ──────────────────────────────────────────────────────

describe('fetchRuntimeInfo', () => {
  it('returns null on 404 (route unmounted = OIDC mode)', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async () => new Response('', { status: 404 }),
    );
    const info = await fetchRuntimeInfo();
    expect(info).toBeNull();
  });

  it('returns the parsed payload when local mode is active', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async () => mockResponse({
        status: 200,
        body: {
          auth_mode: 'local',
          login_url: '/login',
          require_change_password_url: '/change-password',
        },
      }),
    );
    const info = await fetchRuntimeInfo();
    expect(info?.auth_mode).toBe('local');
  });

  it('exposes support_email when the Connector reports it (P3 MAJOR-1-rest)', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async () => mockResponse({
        status: 200,
        body: {
          auth_mode: 'local',
          login_url: '/login',
          require_change_password_url: '/change-password',
          support_email: 'it-support@acme.com',
        },
      }),
    );
    const info = await fetchRuntimeInfo();
    expect(info?.support_email).toBe('it-support@acme.com');
  });
});

// ── admin endpoints ───────────────────────────────────────────────────

describe('admin: create / list / delete / reset', () => {
  const SECRET = 'admin-secret-test';

  it('adminCreateUser sends X-Admin-Secret and JSON body', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async (input: RequestInfo | URL, init?: FakeFetchInit) => {
        calls.push({ url: String(input), init: init ?? {} });
        return mockResponse({
          status: 201,
          body: {
            user_name: 'mario',
            display_name: '',
            must_change_password: true,
            created_at: '2026-05-08T00:00:00Z',
          },
        });
      },
    );
    const res = await adminCreateUser(SECRET, {
      user_name: 'mario',
      password: 'temp1234',
    });
    expect(res.user_name).toBe('mario');
    expect(calls[0].url).toBe('/admin/users');
    expect(calls[0].init.method).toBe('POST');
    const headers = new Headers(calls[0].init.headers as HeadersInit);
    expect(headers.get('X-Admin-Secret')).toBe(SECRET);
    const body = JSON.parse(String(calls[0].init.body ?? ''));
    expect(body.user_name).toBe('mario');
    expect(body.password).toBe('temp1234');
    // Defaults applied.
    expect(body.must_change_password).toBe(true);
    expect(body.display_name).toBe('');
  });

  it('adminListUsers builds the q= query string and unwraps the list', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async (input: RequestInfo | URL, init?: FakeFetchInit) => {
        calls.push({ url: String(input), init: init ?? {} });
        return mockResponse({
          status: 200,
          body: { users: [{ user_name: 'mario', display_name: '', must_change_password: false, created_at: 'x' }], total: 1 },
        });
      },
    );
    const res = await adminListUsers(SECRET, 'mar');
    expect(res).toHaveLength(1);
    expect(res[0].user_name).toBe('mario');
    expect(calls[0].url).toBe('/admin/users?q=mar');
    const headers = new Headers(calls[0].init.headers as HeadersInit);
    expect(headers.get('X-Admin-Secret')).toBe(SECRET);
  });

  it('adminDeleteUser DELETEs the username-encoded path', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async (input: RequestInfo | URL, init?: FakeFetchInit) => {
        calls.push({ url: String(input), init: init ?? {} });
        return new Response(null, { status: 204 });
      },
    );
    await adminDeleteUser(SECRET, 'mario.rossi');
    expect(calls[0].url).toBe('/admin/users/mario.rossi');
    expect(calls[0].init.method).toBe('DELETE');
  });

  it('adminResetPassword POSTs to /reset-password and returns the response', async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async (input: RequestInfo | URL, init?: FakeFetchInit) => {
        calls.push({ url: String(input), init: init ?? {} });
        return mockResponse({
          status: 200,
          body: { user_name: 'mario', must_change_password: true },
        });
      },
    );
    const res = await adminResetPassword(SECRET, 'mario', 'new12345');
    expect(res.must_change_password).toBe(true);
    expect(calls[0].url).toBe('/admin/users/mario/reset-password');
    const body = JSON.parse(String(calls[0].init.body ?? ''));
    expect(body).toEqual({ new_password: 'new12345' });
  });
});

// ── sessionStorage helpers ────────────────────────────────────────────

describe('admin secret session storage', () => {
  it('round-trips via writeAdminSecret/readAdminSecret/clearAdminSecret', () => {
    expect(readAdminSecret()).toBeNull();
    writeAdminSecret('abc123');
    expect(readAdminSecret()).toBe('abc123');
    expect(sessionStorage.getItem(ADMIN_SECRET_STORAGE_KEY)).toBe('abc123');
    clearAdminSecret();
    expect(readAdminSecret()).toBeNull();
  });
});
