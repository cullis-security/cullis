import { useEffect, useState } from 'react';
import { LoginError, loginLocal } from '../../lib/auth';

/**
 * Local-mode sign-in form — ADR-025 Phase 5.
 *
 * On success:
 *   - if ``must_change_password`` is true, redirect to /change-password
 *   - otherwise redirect to /
 *
 * On 401: render a generic "invalid credentials" error (the server
 * deliberately collapses missing-user, wrong-password, and disabled-
 * account into the same response so we cannot enumerate users).
 *
 * On 429: render a Retry-After countdown so the user can see how long
 * the lockout lasts. The ticker decrements once per second and the
 * submit button stays disabled until the lockout clears.
 *
 * If the login response carries ``provisioning: "deferred"`` (Phase 3
 * — Mastio CSR enrollment failed but the cookie was issued anyway),
 * we surface a one-line non-blocking warning before redirecting.
 */
export default function LoginForm() {
  const [userName, setUserName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);
  const [provisioningWarn, setProvisioningWarn] = useState<string | null>(null);

  // Tick down the retry-after countdown.
  useEffect(() => {
    if (retryAfter <= 0) return;
    const t = setTimeout(() => setRetryAfter((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(t);
  }, [retryAfter]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (submitting || retryAfter > 0) return;
    setError(null);
    setProvisioningWarn(null);
    setSubmitting(true);
    try {
      const res = await loginLocal(userName.trim(), password);
      if (res.provisioning === 'deferred') {
        setProvisioningWarn(
          'Sign-in succeeded, but agent enrollment with Mastio is pending. Some features may be unavailable until enrollment completes.',
        );
        // Brief pause so the user can read the banner before redirect.
        await new Promise((r) => setTimeout(r, 1500));
      }
      const next = res.must_change_password ? '/change-password' : '/';
      window.location.assign(next);
    } catch (err) {
      if (err instanceof LoginError) {
        if (err.details.status === 429) {
          setError(
            err.details.retryAfter
              ? `Too many sign-in attempts. Try again in ${err.details.retryAfter} seconds.`
              : 'Too many sign-in attempts. Try again later.',
          );
          if (err.details.retryAfter) setRetryAfter(err.details.retryAfter);
        } else if (err.details.status === 401) {
          setError('Invalid username or password.');
        } else {
          setError(`Sign-in failed (${err.details.status}). Try again.`);
        }
      } else {
        setError('Sign-in failed. Check your connection and try again.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  const disabled = submitting || retryAfter > 0;

  return (
    <main className="auth-shell">
      <div className="auth-card">
        <a className="auth-brand" href="/" aria-label="Cullis Frontdesk home">
          <img src="/cullis-mark.svg" alt="" width="22" height="22" />
          <span className="auth-wordmark">
            Cullis <span className="tail">Frontdesk</span>
          </span>
        </a>

        <h1 className="auth-title">Sign in</h1>
        <p className="auth-subtitle">Local account · per-user identity</p>

        {provisioningWarn && (
          <div className="auth-banner auth-banner-warn" role="status">
            {provisioningWarn}
          </div>
        )}

        <form className="auth-form" onSubmit={onSubmit} noValidate>
          <div className="auth-field">
            <label className="auth-label" htmlFor="user_name">Username</label>
            <input
              id="user_name"
              name="user_name"
              type="text"
              className="auth-input"
              autoComplete="username"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              required
              value={userName}
              onChange={(e) => setUserName(e.target.value)}
              disabled={disabled}
              placeholder="mario"
              aria-invalid={!!error}
            />
          </div>

          <div className="auth-field">
            <label className="auth-label" htmlFor="password">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              className="auth-input"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={disabled}
              aria-invalid={!!error}
            />
          </div>

          {error && (
            <div className="auth-error" role="alert">
              {error}
            </div>
          )}

          <button
            type="submit"
            className="auth-button"
            disabled={disabled || !userName || !password}
          >
            {retryAfter > 0
              ? `Locked · ${retryAfter}s`
              : submitting ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <p className="auth-footer">
          Forgot your password? Contact your administrator.
        </p>
      </div>
    </main>
  );
}
