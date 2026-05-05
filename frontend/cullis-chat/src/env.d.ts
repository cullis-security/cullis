/// <reference path="../.astro/types.d.ts" />
/// <reference types="astro/client" />

interface ImportMetaEnv {
  /**
   * When set to '1', renders the inline audit panel + topbar toggle.
   * Default off: in production the audit chain belongs to the CISO
   * dashboard (Mastio admin UI), not to the end-user chat surface.
   */
  readonly PUBLIC_DEV_AUDIT_PANEL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
