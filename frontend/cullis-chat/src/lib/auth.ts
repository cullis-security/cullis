/**
 * Local-mode auth client — ADR-025 Phase 5.
 *
 * Wraps the Connector's ``/api/auth/*`` and ``/admin/users`` endpoints
 * with typed request/response shapes. The SPA uses these from three
 * surfaces:
 *
 *   - LoginForm           POST /api/auth/login
 *   - ChangePasswordForm  POST /api/auth/change-password
 *   - AdminUsers          GET/POST/DELETE /admin/users
 *
 * Endpoints live on the Connector (same-origin, cookie auth). The
 * admin surface is gated by the ``X-Admin-Secret`` header which the
 * SPA reads from sessionStorage — see AdminUsers.tsx.
 *
 * ``whoamiAuto`` papers over the two whoami shapes (Ambassador's
 * ADR-020 wrapped principal vs the local-mode echo of the cookie
 * payload) so the IdentityBadge call site can stay simple.
 */
import { ApiError } from './api';
import type { Principal } from './types';

export const ADMIN_SECRET_STORAGE_KEY = 'cullis-chat:admin-secret';

// ── shared low-level fetch ────────────────────────────────────────────

interface FetchOpts extends RequestInit {
  /** Throw on non-2xx (default). Set false to inspect status manually. */
  throwOnError?: boolean;
}

async function jsonRequest<T>(
  url: string,
  opts: FetchOpts = {},
): Promise<{ status: number; headers: Headers; data: T | null; error: ApiError | null }> {
  const { throwOnError = true, headers: hdr, ...rest } = opts;
  const res = await fetch(url, {
    credentials: 'same-origin',
    ...rest,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(hdr ?? {}),
    },
  });
  let data: T | null = null;
  if (res.status !== 204) {
    const text = await res.text();
    if (text) {
      try {
        data = JSON.parse(text) as T;
      } catch {
        data = (text as unknown) as T;
      }
    }
  }
  if (!res.ok) {
    const err = new ApiError(res.status, data);
    if (throwOnError) throw err;
    return { status: res.status, headers: res.headers, data, error: err };
  }
  return { status: res.status, headers: res.headers, data, error: null };
}

// ── runtime info / mode detection ──────────────────────────────────────

export interface RuntimeInfo {
  auth_mode: 'local' | 'oidc' | string;
  login_url: string;
  require_change_password_url: string;
  /**
   * Optional setup-state hint used by the SPA bootstrap. Defaults to
   * ``false`` on responses from older Connectors that did not return
   * the field.
   */
  setup_required?: boolean;
  setup_url?: string;
  /**
   * P3 MAJOR-1-rest — IT-support email behind the "Forgot password?"
   * affordance. Empty string when the bundle operator has not set
   * ``CULLIS_FRONTDESK_SUPPORT_EMAIL``; the LoginForm then renders a
   * CLI-hint fallback instead of a mailto link.
   */
  support_email?: string;
}

/**
 * Probe ``/api/auth/runtime-info``. Returns ``null`` when the route
 * is unmounted (404) — that means the Connector is not in local mode
 * and the SPA should fall back to the Ambassador session bootstrap.
 */
export async function fetchRuntimeInfo(): Promise<RuntimeInfo | null> {
  const res = await fetch('/api/auth/runtime-info', {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  });
  if (res.status === 404) return null;
  if (!res.ok) return null;
  try {
    return (await res.json()) as RuntimeInfo;
  } catch {
    return null;
  }
}

// ── login / logout / change-password ──────────────────────────────────

export interface LoginResponse {
  ok: boolean;
  must_change_password: boolean;
  principal_name: string;
  exp: number;
  /** Phase 3 — present when Mastio CSR enrollment is deferred. */
  provisioning?: 'ok' | 'deferred';
}

export interface LoginErrorDetails {
  status: number;
  /** Seconds the caller must wait before retrying (429 only). */
  retryAfter?: number;
  detail?: string;
}

export class LoginError extends Error {
  constructor(public details: LoginErrorDetails) {
    super(`login error: ${details.status}`);
  }
}

export async function loginLocal(
  user_name: string,
  password: string,
): Promise<LoginResponse> {
  const res = await jsonRequest<LoginResponse | { detail?: string }>(
    '/api/auth/login',
    {
      method: 'POST',
      body: JSON.stringify({ user_name, password }),
      throwOnError: false,
    },
  );
  if (res.error) {
    let retryAfter: number | undefined;
    const ra = res.headers.get('Retry-After');
    if (ra) {
      const n = Number.parseInt(ra, 10);
      if (Number.isFinite(n) && n > 0) retryAfter = n;
    }
    const detail =
      res.data && typeof res.data === 'object' && 'detail' in res.data
        ? String((res.data as { detail?: unknown }).detail ?? '')
        : undefined;
    throw new LoginError({ status: res.status, retryAfter, detail });
  }
  // Phase 3 may surface provisioning state via a response header so
  // the SPA can render a non-blocking banner. Read both shapes.
  const data = res.data as LoginResponse;
  if (!data.provisioning) {
    const flag = res.headers.get('X-Cullis-Provisioning-Failed');
    if (flag && flag.toLowerCase() === 'true') {
      data.provisioning = 'deferred';
    }
  }
  return data;
}

export async function logoutLocal(): Promise<void> {
  await jsonRequest('/api/auth/logout', { method: 'POST', body: '{}' });
}

export interface ChangePasswordResponse {
  ok: boolean;
  must_change_password: boolean;
  principal_name: string;
  exp: number;
}

export async function changePassword(
  oldPassword: string,
  newPassword: string,
): Promise<ChangePasswordResponse> {
  const res = await jsonRequest<ChangePasswordResponse>(
    '/api/auth/change-password',
    {
      method: 'POST',
      body: JSON.stringify({
        old_password: oldPassword,
        new_password: newPassword,
      }),
    },
  );
  return res.data as ChangePasswordResponse;
}

export interface WhoamiLocal {
  user_name: string;
  principal_name: string;
  must_change_password: boolean;
  exp: number;
}

export async function whoamiLocal(): Promise<WhoamiLocal> {
  const res = await jsonRequest<WhoamiLocal>('/api/auth/whoami-local');
  return res.data as WhoamiLocal;
}

/**
 * Best-effort principal probe with a graceful fallback.
 *
 * - Try the Ambassador's ``/api/session/whoami`` (ADR-020 shape).
 * - On 401/404, fall back to ``/api/auth/whoami-local`` and synthesise
 *   an ADR-020 principal so the IdentityBadge can render uniformly.
 * - Re-throw on anything that is not a 401/404 so the caller can
 *   distinguish "user is not signed in" from "transport broke".
 */
export async function whoamiAuto(): Promise<{
  source: 'session' | 'local';
  principal: Principal;
}> {
  try {
    const res = await jsonRequest<{ ok: boolean; principal: Principal } | Principal>(
      '/api/session/whoami',
    );
    const data = res.data;
    if (data && typeof data === 'object' && 'principal' in data) {
      return { source: 'session', principal: (data as { principal: Principal }).principal };
    }
    return { source: 'session', principal: data as Principal };
  } catch (err) {
    if (!(err instanceof ApiError) || (err.status !== 401 && err.status !== 404)) {
      throw err;
    }
    const local = await whoamiLocal();
    return {
      source: 'local',
      principal: {
        spiffe_id: null,
        principal_type: 'user',
        name: local.user_name,
        org: '',
        trust_domain: null,
      },
    };
  }
}

// ── admin: users ──────────────────────────────────────────────────────

export interface AdminUser {
  user_name: string;
  display_name: string;
  must_change_password: boolean;
  created_at: string;
  password_changed_at?: string | null;
  disabled?: boolean;
}

export interface AdminUserList {
  users: AdminUser[];
  total: number;
}

export interface CreateUserPayload {
  user_name: string;
  password: string;
  must_change_password?: boolean;
  display_name?: string;
}

function adminHeaders(secret: string): Record<string, string> {
  return { 'X-Admin-Secret': secret };
}

export async function adminCreateUser(
  secret: string,
  payload: CreateUserPayload,
): Promise<AdminUser> {
  const res = await jsonRequest<AdminUser>('/admin/users', {
    method: 'POST',
    headers: adminHeaders(secret),
    body: JSON.stringify({
      must_change_password: true,
      display_name: '',
      ...payload,
    }),
  });
  return res.data as AdminUser;
}

export async function adminListUsers(
  secret: string,
  q?: string,
): Promise<AdminUser[]> {
  const qs = new URLSearchParams();
  if (q) qs.set('q', q);
  const url = qs.toString() ? `/admin/users?${qs}` : '/admin/users';
  const res = await jsonRequest<AdminUserList>(url, {
    method: 'GET',
    headers: adminHeaders(secret),
  });
  return (res.data as AdminUserList).users;
}

export async function adminDeleteUser(
  secret: string,
  user_name: string,
): Promise<void> {
  await jsonRequest(`/admin/users/${encodeURIComponent(user_name)}`, {
    method: 'DELETE',
    headers: adminHeaders(secret),
  });
}

export interface ResetPasswordResponse {
  user_name: string;
  must_change_password: boolean;
}

export async function adminResetPassword(
  secret: string,
  user_name: string,
  newPassword: string,
): Promise<ResetPasswordResponse> {
  const res = await jsonRequest<ResetPasswordResponse>(
    `/admin/users/${encodeURIComponent(user_name)}/reset-password`,
    {
      method: 'POST',
      headers: adminHeaders(secret),
      body: JSON.stringify({ new_password: newPassword }),
    },
  );
  return res.data as ResetPasswordResponse;
}

// ── sessionStorage helpers (admin secret) ──────────────────────────────

export function readAdminSecret(): string | null {
  if (typeof sessionStorage === 'undefined') return null;
  try {
    return sessionStorage.getItem(ADMIN_SECRET_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function writeAdminSecret(secret: string): void {
  if (typeof sessionStorage === 'undefined') return;
  try {
    sessionStorage.setItem(ADMIN_SECRET_STORAGE_KEY, secret);
  } catch {
    /* ignore — Safari private mode etc. */
  }
}

export function clearAdminSecret(): void {
  if (typeof sessionStorage === 'undefined') return;
  try {
    sessionStorage.removeItem(ADMIN_SECRET_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}
