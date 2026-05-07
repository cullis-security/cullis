/**
 * BrandConfig — shape of a SPA brand identity.
 *
 * The two implementations live in `cullis-chat/config.ts` (consumer)
 * and `frontdesk/config.ts` (enterprise). Build-time aliasing in
 * `astro.config.mjs` resolves `@brand/config` to one or the other
 * based on the `CULLIS_BRAND` env var.
 *
 * Keep this lean: every field added here must be defined in both
 * sibling configs. Brand split intentionally covers identity only,
 * not layout, palette, or capabilities.
 */
export interface BrandConfig {
  /** Stable identifier, equal to the folder name. */
  id: 'cullis-chat' | 'frontdesk';
  /** "Cullis Chat" or "Cullis Frontdesk" — the human label. */
  displayName: string;
  /** First half of the wordmark lockup ("Cullis"). */
  brandHead: string;
  /** Second half of the wordmark lockup ("Chat" / "Frontdesk"). */
  brandTail: string;
  /** aria-label on the brand link. */
  ariaHome: string;
  /** <title> on the chat layout. */
  layoutTitle: string;
  /** <meta name="description"> on the chat layout. */
  layoutDescription: string;
  /** <title> on the inbox page. */
  inboxTitle: string;
  /** <meta name="description"> on the inbox page. */
  inboxDescription: string;
  /** Filename under /public for the brand mark SVG. */
  logoMark: string;
  /** Folio code shown in SidebarLeft and other footer-style spots. */
  sidebarFolio: string;
}
