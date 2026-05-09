import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError } from '../../lib/api';
import {
  type AdminUser,
  adminCreateUser,
  adminDeleteUser,
  adminListUsers,
  adminResetPassword,
  clearAdminSecret,
  readAdminSecret,
  writeAdminSecret,
} from '../../lib/auth';

/**
 * Admin Users tab — ADR-025 Phase 5.
 *
 * Surfaces ``/admin/users`` (Phase 1) so a Frontdesk operator can
 * provision local users without curl. Admin auth is the
 * ``X-Admin-Secret`` header; the SPA prompts for it on first load
 * and caches it in sessionStorage so it does not survive a tab
 * close (defence in depth — the secret never lives in localStorage).
 */
export default function AdminUsers() {
  const [secret, setSecret] = useState<string | null>(() => readAdminSecret());
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('');
  const [creating, setCreating] = useState(false);
  const [resetState, setResetState] = useState<{
    user_name: string;
    temp_password: string | null;
  } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AdminUser | null>(null);

  const refresh = useCallback(async () => {
    if (!secret) return;
    setLoading(true);
    setError(null);
    try {
      const list = await adminListUsers(secret);
      setUsers(list);
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setError('Admin secret rejected. Re-enter the X-Admin-Secret to continue.');
        clearAdminSecret();
        setSecret(null);
        setUsers(null);
      } else {
        setError(`Could not load users (${err instanceof ApiError ? err.status : 'network'}).`);
      }
    } finally {
      setLoading(false);
    }
  }, [secret]);

  useEffect(() => {
    if (secret) refresh();
  }, [secret, refresh]);

  const filtered = useMemo(() => {
    if (!users) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return users;
    return users.filter(
      (u) =>
        u.user_name.toLowerCase().includes(q) ||
        u.display_name.toLowerCase().includes(q),
    );
  }, [users, filter]);

  if (!secret) {
    return <AdminSecretPrompt onSubmit={(s) => { writeAdminSecret(s); setSecret(s); }} />;
  }

  return (
    <main className="auth-shell" style={{ alignItems: 'flex-start', paddingTop: '3rem' }}>
      <div className="auth-card auth-card-wide admin-page">
        <header className="admin-header">
          <div>
            <span className="folio">Local users · ADR-025</span>
            <h1>Users</h1>
          </div>
          <div className="admin-toolbar">
            <input
              type="search"
              className="admin-search"
              placeholder="Filter by username..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <button
              type="button"
              className="auth-button"
              style={{ marginTop: 0, padding: '0.55rem 1rem' }}
              onClick={() => setCreating(true)}
            >
              + New user
            </button>
            <button
              type="button"
              className="auth-button auth-button-ghost"
              style={{ marginTop: 0, padding: '0.55rem 1rem' }}
              onClick={() => { clearAdminSecret(); setSecret(null); setUsers(null); }}
              title="Clear admin secret"
            >
              Sign out admin
            </button>
          </div>
        </header>

        {error && (
          <div className="auth-error" role="alert">{error}</div>
        )}

        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Display name</th>
                <th>Status</th>
                <th>Created</th>
                <th>Password changed</th>
                <th aria-label="actions" />
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={6} className="admin-table-empty">Loading…</td>
                </tr>
              )}
              {!loading && filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="admin-table-empty">
                    {users === null ? 'No data.' : 'No users match the filter.'}
                  </td>
                </tr>
              )}
              {!loading &&
                filtered.map((u) => (
                  <tr key={u.user_name}>
                    <td className="admin-mono">{u.user_name}</td>
                    <td>{u.display_name || <span style={{ color: 'var(--text-tertiary)' }}>—</span>}</td>
                    <td>
                      <UserStatusPill user={u} />
                    </td>
                    <td className="admin-mono" title={u.created_at}>
                      {formatDate(u.created_at)}
                    </td>
                    <td className="admin-mono" title={u.password_changed_at ?? ''}>
                      {u.password_changed_at ? formatDate(u.password_changed_at) : '—'}
                    </td>
                    <td>
                      <div className="admin-actions">
                        <button
                          type="button"
                          className="admin-action"
                          onClick={() =>
                            setResetState({ user_name: u.user_name, temp_password: null })
                          }
                        >
                          Reset pw
                        </button>
                        <button
                          type="button"
                          className="admin-action admin-action-danger"
                          onClick={() => setConfirmDelete(u)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      {creating && (
        <CreateUserModal
          secret={secret}
          onClose={() => setCreating(false)}
          onCreated={() => { setCreating(false); refresh(); }}
        />
      )}

      {resetState && (
        <ResetPasswordModal
          secret={secret}
          state={resetState}
          setState={setResetState}
          onDone={() => { setResetState(null); refresh(); }}
        />
      )}

      {confirmDelete && (
        <DeleteUserModal
          secret={secret}
          user={confirmDelete}
          onClose={() => setConfirmDelete(null)}
          onDeleted={() => { setConfirmDelete(null); refresh(); }}
        />
      )}
    </main>
  );
}

// ── secret prompt ─────────────────────────────────────────────────────

function AdminSecretPrompt({ onSubmit }: { onSubmit: (s: string) => void }) {
  const [value, setValue] = useState('');
  return (
    <main className="auth-shell">
      <div className="auth-card">
        <h1 className="auth-title">Admin access</h1>
        <p className="auth-subtitle">Enter the Connector admin secret</p>
        <form
          className="auth-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (!value) return;
            onSubmit(value);
          }}
          noValidate
        >
          <div className="auth-field">
            <label className="auth-label" htmlFor="admin_secret">X-Admin-Secret</label>
            <input
              id="admin_secret"
              name="admin_secret"
              type="password"
              className="auth-input"
              autoComplete="off"
              required
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
            <span className="auth-help">
              Set on the Connector via <code>CULLIS_CONNECTOR_ADMIN_SECRET</code>.
              Stored only in this tab&apos;s sessionStorage.
            </span>
          </div>
          <button type="submit" className="auth-button" disabled={!value}>
            Continue
          </button>
        </form>
      </div>
    </main>
  );
}

// ── status pill ───────────────────────────────────────────────────────

function UserStatusPill({ user }: { user: AdminUser }) {
  if (user.disabled) {
    return <span className="admin-pill admin-pill-disabled">Disabled</span>;
  }
  if (user.must_change_password) {
    return <span className="admin-pill admin-pill-pending">Pending</span>;
  }
  return <span className="admin-pill admin-pill-active">Active</span>;
}

// ── create user modal ─────────────────────────────────────────────────

function CreateUserModal({
  secret,
  onClose,
  onCreated,
}: {
  secret: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [userName, setUserName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [pw, setPw] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setErr(null);
    try {
      await adminCreateUser(secret, {
        user_name: userName.trim(),
        password: pw,
        display_name: displayName.trim(),
        must_change_password: true,
      });
      onCreated();
    } catch (e2) {
      if (e2 instanceof ApiError) {
        if (e2.status === 409) {
          setErr('A user with that name already exists.');
        } else if (e2.status === 400) {
          const detail =
            e2.payload && typeof e2.payload === 'object' && 'detail' in e2.payload
              ? String((e2.payload as { detail?: unknown }).detail ?? '')
              : '';
          setErr(detail || 'Invalid username or password.');
        } else if (e2.status === 403) {
          setErr('Admin secret rejected.');
        } else {
          setErr(`Could not create user (${e2.status}).`);
        }
      } else {
        setErr('Could not create user. Check your connection.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="admin-modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="new-user-title"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="admin-modal">
        <h2 id="new-user-title">New user</h2>
        <p>The user will be required to change their password on first sign-in.</p>
        <form className="auth-form" onSubmit={onSubmit} noValidate>
          <div className="auth-field">
            <label className="auth-label" htmlFor="cu_user_name">Username</label>
            <input
              id="cu_user_name"
              type="text"
              className="auth-input"
              required
              autoFocus
              value={userName}
              onChange={(e) => setUserName(e.target.value)}
              pattern="[A-Za-z0-9._\-]{1,64}"
              title="Letters, digits, dot, underscore, hyphen. Up to 64 characters."
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
            />
          </div>
          <div className="auth-field">
            <label className="auth-label" htmlFor="cu_display_name">Display name (optional)</label>
            <input
              id="cu_display_name"
              type="text"
              className="auth-input"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              maxLength={256}
            />
          </div>
          <div className="auth-field">
            <label className="auth-label" htmlFor="cu_password">Temporary password</label>
            <input
              id="cu_password"
              type="text"
              className="auth-input"
              required
              minLength={8}
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              autoComplete="off"
            />
            <span className="auth-help">
              Minimum 8 characters. The user must change this on first sign-in.
            </span>
          </div>

          {err && <div className="auth-error" role="alert">{err}</div>}

          <div className="admin-modal-actions">
            <button
              type="button"
              className="auth-button auth-button-ghost"
              onClick={onClose}
              disabled={submitting}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="auth-button"
              style={{ marginTop: 0 }}
              disabled={submitting || !userName || pw.length < 8}
            >
              {submitting ? 'Creating...' : 'Create user'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── reset password modal ──────────────────────────────────────────────

function ResetPasswordModal({
  secret,
  state,
  setState,
  onDone,
}: {
  secret: string;
  state: { user_name: string; temp_password: string | null };
  setState: (s: { user_name: string; temp_password: string | null } | null) => void;
  onDone: () => void;
}) {
  const [pw, setPw] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setErr(null);
    try {
      await adminResetPassword(secret, state.user_name, pw);
      setState({ user_name: state.user_name, temp_password: pw });
    } catch (e2) {
      if (e2 instanceof ApiError) {
        if (e2.status === 404) {
          setErr('User no longer exists.');
        } else if (e2.status === 400) {
          const detail =
            e2.payload && typeof e2.payload === 'object' && 'detail' in e2.payload
              ? String((e2.payload as { detail?: unknown }).detail ?? '')
              : '';
          setErr(detail || 'Password did not meet requirements.');
        } else {
          setErr(`Could not reset password (${e2.status}).`);
        }
      } else {
        setErr('Could not reset password. Check your connection.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  const showResult = state.temp_password !== null;

  return (
    <div
      className="admin-modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="reset-pw-title"
      onClick={(e) => { if (e.target === e.currentTarget && !submitting) setState(null); }}
    >
      <div className="admin-modal">
        <h2 id="reset-pw-title">Reset password</h2>
        <p>
          Setting a new temporary password for <code>{state.user_name}</code>. They will be
          required to change it on next sign-in.
        </p>

        {!showResult && (
          <form className="auth-form" onSubmit={onSubmit} noValidate>
            <div className="auth-field">
              <label className="auth-label" htmlFor="rp_password">New temporary password</label>
              <input
                id="rp_password"
                type="text"
                className="auth-input"
                required
                minLength={8}
                value={pw}
                onChange={(e) => setPw(e.target.value)}
                autoFocus
                autoComplete="off"
              />
            </div>

            {err && <div className="auth-error" role="alert">{err}</div>}

            <div className="admin-modal-actions">
              <button
                type="button"
                className="auth-button auth-button-ghost"
                onClick={() => setState(null)}
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="auth-button"
                style={{ marginTop: 0 }}
                disabled={submitting || pw.length < 8}
              >
                {submitting ? 'Resetting...' : 'Reset password'}
              </button>
            </div>
          </form>
        )}

        {showResult && (
          <div>
            <p style={{ color: 'var(--accent-cyan)', marginBottom: '0.4rem' }}>
              Password reset. Share this temporary password securely — it will not be shown again.
            </p>
            <code className="admin-temp-pw">{state.temp_password}</code>
            <div className="admin-modal-actions">
              <button
                type="button"
                className="auth-button"
                style={{ marginTop: 0 }}
                onClick={onDone}
              >
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── delete user modal ─────────────────────────────────────────────────

function DeleteUserModal({
  secret,
  user,
  onClose,
  onDeleted,
}: {
  secret: string;
  user: AdminUser;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function onConfirm() {
    if (submitting) return;
    setSubmitting(true);
    setErr(null);
    try {
      await adminDeleteUser(secret, user.user_name);
      onDeleted();
    } catch (e2) {
      if (e2 instanceof ApiError) {
        if (e2.status === 404) {
          // Already gone — treat as success.
          onDeleted();
          return;
        }
        setErr(`Could not delete user (${e2.status}).`);
      } else {
        setErr('Could not delete user. Check your connection.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="admin-modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="del-user-title"
      onClick={(e) => { if (e.target === e.currentTarget && !submitting) onClose(); }}
    >
      <div className="admin-modal">
        <h2 id="del-user-title">Delete user</h2>
        <p>
          Permanently remove <code>{user.user_name}</code>? The user&apos;s sessions and audit
          history will remain in the audit log.
        </p>

        {err && <div className="auth-error" role="alert">{err}</div>}

        <div className="admin-modal-actions">
          <button
            type="button"
            className="auth-button auth-button-ghost"
            onClick={onClose}
            disabled={submitting}
          >
            Cancel
          </button>
          <button
            type="button"
            className="auth-button auth-button-danger"
            style={{ marginTop: 0 }}
            onClick={onConfirm}
            disabled={submitting}
          >
            {submitting ? 'Deleting...' : 'Delete user'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── helpers ───────────────────────────────────────────────────────────

function formatDate(iso: string): string {
  // Servers emit ISO-8601 strings. Render in the user's locale, falling
  // back to the raw string if Date.parse fails (e.g. server emits a
  // shape we have not seen).
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  });
}
