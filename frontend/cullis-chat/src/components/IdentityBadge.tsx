import { useEffect, useState } from 'react';
import { whoami } from '../lib/api';
import { ensureSession } from '../lib/session-singleton';
import type { Principal } from '../lib/types';

/**
 * Live identity badge in the TopBar. Reads the principal from
 * the local Astro `/api/session/whoami` route, which forwards to
 * the Ambassador's shared-mode `/api/session/whoami` endpoint and
 * translates the cookie-payload shape into the ADR-020 principal
 * shape we render here. Single mode falls through to a "local"
 * placeholder so the badge still shows something useful.
 *
 * v0.1 shape (ADR-020): principal_type display em + name.
 */
export default function IdentityBadge() {
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await ensureSession();
        const raw = await whoami();
        if (cancelled) return;
        const p =
          raw && typeof raw === 'object' && 'principal' in raw
            ? (raw as { principal: Principal }).principal
            : (raw as Principal);
        setPrincipal(p);
      } catch {
        if (!cancelled) setError(true);
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
