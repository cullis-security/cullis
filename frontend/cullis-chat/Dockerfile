# Cullis Chat — production container.
#
# Two stages: a Node 22 builder produces `dist/server/entry.mjs`
# (Astro standalone Node adapter), and an Alpine Node 22 runtime
# serves the bundle on :4321.
#
# Why Node 22 here vs Node 20 in package.json `engines`: Astro 5
# accepts both, the docker base is the only place where we can
# pin freely; we use the latest LTS. CI dev still works on Node 20.
#
# Topology:
#   - Topology L (laptop): the Frontdesk image (a future ADR-019
#     Step 4 artefact) bundles this image + the Connector daemon
#     under one supervisor.
#   - Topology S (datacenter): this image runs as a sidecar to the
#     Connector. CULLIS_AMBASSADOR_URL points at the Connector's
#     loopback port.

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

# Prune to production deps only for the runtime stage.
RUN npm prune --omit=dev

# ---

FROM node:22-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=4321 \
    CULLIS_AMBASSADOR_URL=http://127.0.0.1:7777 \
    CULLIS_CONNECTOR_PROFILE=default

# Drop root.
RUN addgroup -S cullis && adduser -S -G cullis cullis

COPY --from=builder --chown=cullis:cullis /app/dist ./dist
COPY --from=builder --chown=cullis:cullis /app/node_modules ./node_modules
COPY --from=builder --chown=cullis:cullis /app/package.json ./package.json

USER cullis

EXPOSE 4321

# Astro standalone server entry. No `npm start` indirection.
CMD ["node", "./dist/server/entry.mjs"]
