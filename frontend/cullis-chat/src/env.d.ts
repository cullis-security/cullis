/// <reference path="../.astro/types.d.ts" />
/// <reference types="astro/client" />

declare namespace App {
  interface Locals {
    /** Per-request CSP nonce, set by `src/middleware.ts`. */
    cspNonce: string;
  }
}
