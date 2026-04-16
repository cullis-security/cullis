# Cullis site (Astro)

Static site for cullis.io, built with Astro. Produces plain HTML to `dist/`.

## Dev

From inside the Nix shell (`nix-shell` in repo root):

```bash
cd site
npm install
npm run dev        # http://localhost:4321
```

## Build

```bash
npm run build      # output in site/dist/
npm run preview    # preview the built site locally
```

## Structure

```
site/
├── public/              Static assets (served as-is)
└── src/
    ├── components/      Reusable .astro components (Nav, Footer)
    ├── layouts/         Base page layout
    ├── pages/           One .astro file per route
    └── styles/          Global CSS (design tokens, base rules)
```

The legacy single-file site still lives at `/docs/index.html` and is untouched.
