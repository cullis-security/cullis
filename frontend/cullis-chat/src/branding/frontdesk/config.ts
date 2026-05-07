/**
 * Cullis Frontdesk brand — enterprise multi-user surface.
 *
 * Built from the same SPA source via `CULLIS_BRAND=frontdesk astro build`.
 * Layout, palette, animations are identical to the consumer build —
 * only the lockup, copy, and folio change. Per-user KMS + SSO + the
 * X-Forwarded-User topbar are the runtime-shape differences and live
 * outside the brand config (they switch on at the Connector level
 * once shared mode is detected).
 */
import type { BrandConfig } from '../types';

const config: BrandConfig = {
  id: 'frontdesk',
  displayName: 'Cullis Frontdesk',
  brandHead: 'Cullis',
  brandTail: 'Frontdesk',
  ariaHome: 'Cullis Frontdesk home',
  layoutTitle: 'Cullis Frontdesk',
  layoutDescription:
    'Identity-aware chat for enterprise teams. SSO + per-user KMS, signed and audited end-to-end.',
  inboxTitle: 'Inbox · Cullis Frontdesk',
  inboxDescription:
    'Cullis Frontdesk inbox — cross-org messages for enterprise teams.',
  logoMark: 'cullis-mark.svg',
  sidebarFolio: 'CLLS-FRONTDESK',
};

export default config;
