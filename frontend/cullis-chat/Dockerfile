# Cullis Chat — production container (ADR-019 Phase 8b-2b: pure static).
#
# Two stages: a Node 22 builder produces ``dist/`` (Astro static output,
# all pages prerendered, no server entry), and an Alpine nginx runtime
# serves those static files on :8080.
#
# Topology:
#   - Frontdesk container (datacenter): nginx in this image is fronted by
#     packaging/frontdesk-bundle/nginx, which proxies /api/session/* and
#     /v1/* to the Connector. The static SPA + the proxied APIs share an
#     origin so the cookie minted by /api/session/init reaches /v1/*.
#   - Desktop installer (Phase 8c): FastAPI mounts ``dist/`` at /chat and
#     serves the same /api/session/* /v1/* on the same origin. This image
#     is unused in that topology — the static is shipped inside the Python
#     wheel.

FROM node:22-alpine AS builder
WORKDIR /app

# Install deps from the lockfile (deterministic).
COPY package.json package-lock.json ./
RUN npm ci --include=dev

# Build.
COPY astro.config.mjs tsconfig.json ./
COPY src ./src
COPY public ./public
RUN npm run build

# ---

FROM nginx:1.27-alpine AS runtime

# Drop the default nginx welcome page; we ship our own config.
RUN rm /etc/nginx/conf.d/default.conf

COPY --from=builder /app/dist /usr/share/nginx/html

# A minimal SPA-friendly nginx config: serve static, fall back to
# index.html for unknown paths (single-page app routing). The Frontdesk
# bundle's outer nginx layer adds the /api/session/* /v1/* proxy rules
# and the security headers; this inner nginx stays focused on static.
COPY ./nginx-static.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

# nginx default CMD — alpine image already runs nginx in foreground.
