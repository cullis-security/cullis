# Deploying the Cullis site to Cloudflare Pages

The site lives in `site/` and builds to `site/dist/`. Cloudflare Pages pulls
the repo on every push, runs the build, and serves the output behind the
Cloudflare CDN.

## First-time setup (new CF Pages project)

Safe rollout — this creates a **new** Cloudflare Pages project alongside the
existing one. The existing `cullis.io` site is untouched until you explicitly
swap the custom domain.

1. Cloudflare dashboard → **Workers & Pages** → **Create application** → **Pages** → **Connect to Git**.
2. Select the `cullis-security/cullis` repo.
3. Build configuration:

   | Field | Value |
   |---|---|
   | Framework preset | `Astro` |
   | Build command | `cd site && npm ci && npm run build` |
   | Build output directory | `site/dist` |
   | Root directory | *(leave empty)* |
   | Production branch | `site-next` (or whichever branch holds this work) |

4. Environment variables:

   | Variable | Value |
   |---|---|
   | `NODE_VERSION` | `20` |

5. Save and deploy. First build takes ~90s. When it's done you get a preview
   URL like `cullis-next.pages.dev` — check it live.

## Custom domain swap (only when ready)

Once the preview on `*.pages.dev` looks right:

1. In the **new** CF Pages project → **Custom domains** → **Add custom domain** → `cullis.io`.
2. Cloudflare will warn that the domain is assigned to another project — confirm the takeover.
3. Propagation is a few seconds on Cloudflare. No DNS change needed because
   the domain is already on Cloudflare nameservers.
4. Verify `https://cullis.io` serves the new site.
5. Once satisfied, you can delete the old CF Pages project (the one that
   served from `docs/`). The `docs/index.html` file stays in git history either way.

## Subsequent deploys

Any push to the configured production branch triggers a new build and deploy
automatically. No manual step. Pull-requests and other branches get preview
deploys on `{branch}.{project}.pages.dev`.

## Notes

- `public/_headers` defines security headers applied by Cloudflare.
- The site is fully static — no Pages Functions needed for this version.
- Build is deterministic: same input, same output. The dev server (`npm run dev`) produces the same visual result as the production build.
