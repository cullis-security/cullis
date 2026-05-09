import { useEffect, useState } from 'react';
import { ApiError } from '../lib/api';
import { whoamiAuto } from '../lib/auth';
import { ensureSession, redirectToLogin } from '../lib/session-singleton';
import type { Principal } from '../lib/types';

/**
 * Live identity badge in the TopBar. Reads the principal via
 * ``whoamiAuto`` (ADR-025 Phase 5):
 *
 *   1. Try the Ambassador's ``/api/session/whoami`` (ADR-020 shape).
 *   2. On 401/404, fall back to ``/api/auth/whoami-local`` so local-
 *      mode Frontdesk users see their username before Mastio CSR
 *      enrollment completes (Phase 3 deferred-provisioning case).
 *   3. On any other error, render the offline placeholder.
 *
 * If both probes fail with 401 we redirect to ``/login`` rather than
 * leaving the badge stuck on "offline" — the user is just not signed
 * in, and the SPA's ``ensureSession`` already redirected anyway, so
 * we mirror that behaviour from this island for safety.
 */
export default function IdentityBadge() {
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await ensureSession();
        const result = await whoamiAuto();
        if (cancelled) return;
        setPrincipal(result.principal);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 401) {
          redirectToLogin();
          return;
        }
        setError(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <span className="identity-badge identity-badge-error" title="whoami unavailable">
        <span className="folio">principal</span>
        <span className="identity-name">
          <em>?</em>
          <span className="identity-sep">·</span>offline
        </span>
      </span>
    );
  }

  if (!principal) {
    return (
      <span className="identity-badge identity-badge-loading" aria-busy="true">
        <span className="folio">principal</span>
        <span className="identity-name">
          <em>...</em>
        </span>
      </span>
    );
  }

  return (
    <span className="identity-badge" title={principal.spiffe_id ?? undefined}>
      <span className="folio">principal</span>
      <span className="identity-name">
        <em>{principal.principal_type}</em>
        <span className="identity-sep">·</span>
        {principal.name}
      </span>
    </span>
  );
}
