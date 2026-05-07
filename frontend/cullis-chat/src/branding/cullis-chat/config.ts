/**
 * Cullis Chat brand — consumer single-user surface.
 *
 * Imported via the `@brand` alias declared in astro.config.mjs.
 * Build-time selection: `CULLIS_BRAND=cullis-chat` (default) sets the
 * alias to this file; `CULLIS_BRAND=frontdesk` swaps to the
 * `frontdesk/config.ts` sibling. Same SPA, different identity.
 */
import type { BrandConfig } from '../types';

const config: BrandConfig = {
  id: 'cullis-chat',
  displayName: 'Cullis Chat',
  brandHead: 'Cullis',
  brandTail: 'Chat',
  ariaHome: 'Cullis Chat home',
  layoutTitle: 'Cullis Chat',
  layoutDescription:
    'Identity-aware chat. Every message is signed, audited, and traceable.',
  inboxTitle: 'Inbox · Cullis Chat',
  inboxDescription:
    'Cullis Chat inbox — identity-aware messages for users and agents.',
  logoMark: 'cullis-mark.svg',
  sidebarFolio: 'CLLS-CHAT',
};

export default config;
