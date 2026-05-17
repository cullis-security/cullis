import { useEffect, useState } from 'react';
import { fetchRuntimeInfo, LoginError, loginLocal } from '../../lib/auth';

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
// Cap on the username we reflect back into the "Forgot password?"
// mailto subject. Mirrors the server-side cap in
// ``cullis_connector/auth/local_router.py::_FORGOT_USER_NAME_MAX_LEN``
// so a malformed value from auto-fill cannot bloat the subject.
const FORGOT_USER_NAME_MAX_LEN = 64;

export default function LoginForm() {
  const [userName, setUserName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);
  const [provisioningWarn, setProvisioningWarn] = useState<string | null>(null);
  const [supportEmail, setSupportEmail] = useState('');
  const [forgotOpen, setForgotOpen] = useState(false);

  // Pull the configured IT-support email from /api/auth/runtime-info so
  // the "Forgot password?" panel can offer a one-click mailto. Falls
  // back to the CLI-hint variant when the env var is unset on the
  // bundle (or when this Connector is too old to surface it).
  useEffect(() => {
    let cancelled = false;
    fetchRuntimeInfo().then((info) => {
      if (cancelled) return;
      const email = (info && info.support_email) || '';
      setSupportEmail(email.trim());
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // ADR-025 Phase 5 follow-up (bug N17, 2026-05-09 VM dogfood): if the
  // browser's password manager auto-fills both fields before React
  // hydrates, the controlled inputs end up displaying the auto-filled
  // values but our React state stays at the empty initial value. The
  // submit button (disabled on ``!userName || !password``) never
  // re-enables and clicks do nothing. Reading the DOM values once the
  // hydration is mounted backfills the state so the form behaves the
  // way the user expects.
  useEffect(() => {
    const u = document.getElementById('user_name') as HTMLInputElement | null;
    const p = document.getElementById('password') as HTMLInputElement | null;
    if (u && u.value && !userName) setUserName(u.value);
    if (p && p.value && !password) setPassword(p.value);
    // Defer one tick so Brave / Chrome autofill (which fires AFTER the
    // mount event in some flows) has had a chance to populate.
    const t = setTimeout(() => {
      if (u && u.value && !userName) setUserName(u.value);
      if (p && p.value && !password) setPassword(p.value);
    }, 200);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
          <button
            type="button"
            className="auth-link"
            onClick={() => setForgotOpen(true)}
          >
            Forgot password?
          </button>
        </p>

        {forgotOpen && (
          <ForgotPasswordPanel
            supportEmail={supportEmail}
            userName={userName.trim().slice(0, FORGOT_USER_NAME_MAX_LEN)}
            onClose={() => setForgotOpen(false)}
          />
        )}
      </div>
    </main>
  );
}

/** "Forgot password?" panel. Mailto when CULLIS_FRONTDESK_SUPPORT_EMAIL
 * is set, CLI hint for the IT admin otherwise. */
function ForgotPasswordPanel(props: {
  supportEmail: string;
  userName: string;
  onClose: () => void;
}) {
  const { supportEmail, userName, onClose } = props;
  const subject = 'Password reset request' + (userName ? ` - ${userName}` : '');
  const body =
    `Hi,\n\nI cannot sign in to the Cullis Frontdesk workspace and would ` +
    `like my password reset.\n\nUsername: ${userName || '(please fill in)'}\n` +
    `Connector profile: frontdesk\nBrowser URL: (paste from the address bar)\n\nThanks.`;
  const mailto = supportEmail
    ? `mailto:${encodeURIComponent(supportEmail)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`
    : '';
  return (
    <div className="auth-forgot-panel" role="dialog" aria-labelledby="forgot-title">
      <h2 id="forgot-title" className="auth-forgot-title">Reset your password</h2>
      {supportEmail ? (
        <>
          <p>Your account password is managed by your IT administrator. Send a short note and they will reset it for you.</p>
          <p><a className="auth-button auth-button-secondary" href={mailto}>Email IT support</a></p>
          <p className="auth-forgot-hint">Or contact <a href={`mailto:${encodeURIComponent(supportEmail)}`}>{supportEmail}</a> directly.</p>
        </>
      ) : (
        <>
          <p>Contact your local IT administrator to reset your password. They can run the following on the Frontdesk host without taking the bundle offline:</p>
          <pre className="auth-forgot-code"><code>{`docker exec -it cullis-frontdesk-connector \\\n  cullis-connector users reset-password ${userName || '<your-username>'}`}</code></pre>
          <p className="auth-forgot-hint">The IT admin can pre-configure a support contact by setting <code>CULLIS_FRONTDESK_SUPPORT_EMAIL</code> in the bundle&rsquo;s <code>frontdesk.env</code>.</p>
        </>
      )}
      <p>
        <button type="button" className="auth-button auth-button-secondary" onClick={onClose}>Close</button>
      </p>
    </div>
  );
}
