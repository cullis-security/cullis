import type { Principal, PrincipalType } from './types';

/**
 * Parse a SPIFFE id into a Principal (ADR-020 §2).
 *
 * New-style:    spiffe://<td>/<org>/<type>/<name>
 * Legacy:       spiffe://<td>/<org>/<name>     → principal_type='agent'
 *
 * Returns null on a path we cannot parse (caller should not block on
 * this — fall back to whatever the server told us).
 */
export function parseSpiffe(spiffeId: string): Principal | null {
  let url: URL;
  try {
    url = new URL(spiffeId);
  } catch {
    return null;
  }
  if (url.protocol !== 'spiffe:') return null;

  const trust_domain = url.hostname || null;
  // url.pathname starts with '/'
  const segments = url.pathname.split('/').filter(Boolean);

  if (segments.length === 3 && isPrincipalType(segments[1])) {
    return {
      spiffe_id: spiffeId,
      principal_type: segments[1],
      org: segments[0],
      name: segments[2],
      trust_domain,
    };
  }

  if (segments.length >= 2) {
    // legacy: <org>/<name>...
    return {
      spiffe_id: spiffeId,
      principal_type: 'agent',
      org: segments[0],
      name: segments.slice(1).join('/'),
      trust_domain,
    };
  }

  return null;
}

function isPrincipalType(value: string): value is PrincipalType {
  return value === 'user' || value === 'agent' || value === 'workload';
}

/** Short-form display: `<em>type</em> · name` (used by IdentityBadge). */
export function formatPrincipalLabel(p: Principal): { type: PrincipalType; name: string } {
  return { type: p.principal_type, name: p.name };
}
