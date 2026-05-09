import { useEffect, useState } from 'react';
import {
  ADMIN_SECRET_STORAGE_KEY,
  fetchRuntimeInfo,
  logoutLocal,
} from '../../lib/auth';
import { redirectToLogin } from '../../lib/session-singleton';

/**
 * Right-side TopBar overflow — ADR-025 Phase 5.
 *
 * Two affordances:
 *
 *   - Logout button (visible only when the Connector is in local
 *     mode; in OIDC mode the IdP owns sign-out).
 *   - Admin link (visible only when the SPA has the admin secret
 *     in sessionStorage — i.e. the user already authenticated to
 *     /admin/users in this tab).
 *
 * Both surfaces are progressive enhancement; the badge already shows
 * the principal so this component stays small and non-blocking.
 */
export default function TopBarSessionMenu() {
  const [authMode, setAuthMode] = useState<string | null>(null);
  const [hasAdminSecret, setHasAdminSecret] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const info = await fetchRuntimeInfo();
      if (!cancelled) setAuthMode(info?.auth_mode ?? null);
    })();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    function check() {
      try {
        setHasAdminSecret(!!sessionStorage.getItem(ADMIN_SECRET_STORAGE_KEY));
      } catch {
        setHasAdminSecret(false);
      }
    }
    check();
    // Cross-tab updates fire `storage` for localStorage only, but a
    // hand-edit in DevTools is detectable on focus.
    window.addEventListener('focus', check);
    return () => window.removeEventListener('focus', check);
  }, []);

  if (authMode !== 'local') return null;

  async function onLogout() {
    if (busy) return;
    setBusy(true);
    try {
      await logoutLocal();
    } catch {
      /* ignore — clearing the cookie always succeeds client-side. */
    }
    redirectToLogin();
  }

  return (
    <div className="topbar-session-menu">
      {hasAdminSecret && (
        <a className="topbar-link" href="/admin/users" title="Manage local users">
          <span className="folio">admin</span>
          <span className="topbar-link-label">Users</span>
        </a>
      )}
      <button
        type="button"
        className="topbar-logout"
        onClick={onLogout}
        disabled={busy}
        title="Sign out of this session"
      >
        {busy ? '...' : 'Logout'}
      </button>
    </div>
  );
}
