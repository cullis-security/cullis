import { useMemo, useState } from 'react';
import { ApiError } from '../../lib/api';
import { changePassword } from '../../lib/auth';

const MIN_LEN = 8;

/**
 * Heuristic 0-4 password strength score. Not a substitute for the
 * server-side length check (the API enforces ``MIN_PASSWORD_LENGTH``),
 * but a useful nudge: encourages mixed character classes and
 * discourages obvious weak passwords.
 *
 *   0 — empty / shorter than MIN_LEN
 *   1 — meets minimum length
 *   2 — adds one extra character class
 *   3 — adds two extra classes OR length >= 12
 *   4 — three+ classes AND length >= 12
 */
function scoreStrength(pw: string): number {
  if (pw.length < MIN_LEN) return 0;
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^A-Za-z0-9]/.test(pw)) classes++;
  let score = 1;
  if (classes >= 2) score = 2;
  if (classes >= 3 || pw.length >= 12) score = 3;
  if (classes >= 3 && pw.length >= 12) score = 4;
  return score;
}

const STRENGTH_LABELS = ['too short', 'weak', 'fair', 'good', 'strong'];

/**
 * Change password — the post-login first-login flow plus the
 * "I want to rotate my password" use case (same endpoint).
 *
 * On success the cookie is reissued by the server with
 * ``must_change_password=false`` and we redirect to /.
 */
export default function ChangePasswordForm() {
  const [oldPw, setOldPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const score = useMemo(() => scoreStrength(newPw), [newPw]);
  const mismatch = confirm.length > 0 && confirm !== newPw;
  const tooShort = newPw.length > 0 && newPw.length < MIN_LEN;

  const canSubmit =
    !submitting &&
    oldPw.length > 0 &&
    newPw.length >= MIN_LEN &&
    confirm === newPw;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setError(null);
    setSubmitting(true);
    try {
      await changePassword(oldPw, newPw);
      window.location.assign('/');
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setError('Old password is incorrect.');
        } else if (err.status === 400) {
          const detail =
            err.payload && typeof err.payload === 'object' && 'detail' in err.payload
              ? String((err.payload as { detail?: unknown }).detail ?? '')
              : '';
          setError(detail || 'Password did not meet requirements.');
        } else {
          setError(`Could not change password (${err.status}). Try again.`);
        }
      } else {
        setError('Could not change password. Check your connection and try again.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="auth-shell">
      <div className="auth-card">
        <a className="auth-brand" href="/" aria-label="Cullis Frontdesk home">
          <img src="/cullis-mark.svg" alt="" width="22" height="22" />
          <span className="auth-wordmark">
            Cullis <span className="tail">Frontdesk</span>
          </span>
        </a>

        <h1 className="auth-title">Set a new password</h1>
        <p className="auth-subtitle">
          Required on first sign-in. Minimum {MIN_LEN} characters.
        </p>

        <form className="auth-form" onSubmit={onSubmit} noValidate>
          <div className="auth-field">
            <label className="auth-label" htmlFor="old_password">Current password</label>
            <input
              id="old_password"
              name="old_password"
              type="password"
              className="auth-input"
              autoComplete="current-password"
              required
              value={oldPw}
              onChange={(e) => setOldPw(e.target.value)}
              disabled={submitting}
            />
          </div>

          <div className="auth-field">
            <label className="auth-label" htmlFor="new_password">New password</label>
            <input
              id="new_password"
              name="new_password"
              type="password"
              className="auth-input"
              autoComplete="new-password"
              required
              minLength={MIN_LEN}
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              disabled={submitting}
              aria-invalid={tooShort}
            />
            <div className="pw-strength" aria-live="polite">
              <div className="pw-strength-bar">
                <div
                  className="pw-strength-fill"
                  data-level={score}
                  aria-hidden="true"
                />
              </div>
              <span className="pw-strength-label">{STRENGTH_LABELS[score]}</span>
            </div>
          </div>

          <div className="auth-field">
            <label className="auth-label" htmlFor="confirm_password">Confirm new password</label>
            <input
              id="confirm_password"
              name="confirm_password"
              type="password"
              className="auth-input"
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={submitting}
              aria-invalid={mismatch}
            />
            {mismatch && (
              <span className="auth-help" style={{ color: 'var(--accent-amber)' }}>
                Passwords do not match.
              </span>
            )}
          </div>

          {error && (
            <div className="auth-error" role="alert">
              {error}
            </div>
          )}

          <button type="submit" className="auth-button" disabled={!canSubmit}>
            {submitting ? 'Updating...' : 'Confirm'}
          </button>
        </form>

        <p className="auth-footer">
          Choose a unique password. Mix letters, numbers, and symbols for the strongest result.
        </p>
      </div>
    </main>
  );
}
