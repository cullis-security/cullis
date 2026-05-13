# syntax=docker/dockerfile:1.6

# -----------------------------------------------------------------------------
# Stage 1: Tailwind CSS build (shake-out P1-10)
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS tailwind-build
ARG TAILWIND_VERSION=v3.4.10
ARG TARGETARCH=amd64
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY scripts/tailwind-sha256.txt /tmp/tailwind-sha256.txt
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) TW_ARCH=x64 ;; \
      arm64) TW_ARCH=arm64 ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cd /usr/local/bin; \
    curl -sSLf "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-${TW_ARCH}" \
      -o "tailwindcss-linux-${TW_ARCH}"; \
    # Wave B F1 (audit 2026-05-11) — verify SHA-256 before trusting.
    grep " tailwindcss-linux-${TW_ARCH}$" /tmp/tailwind-sha256.txt | sha256sum -c -; \
    mv "tailwindcss-linux-${TW_ARCH}" tailwindcss; \
    chmod +x tailwindcss; \
    rm -f /tmp/tailwind-sha256.txt
WORKDIR /src
COPY tailwind.config.js ./
COPY mcp_proxy/dashboard/static_src/ ./mcp_proxy/dashboard/static_src/
COPY mcp_proxy/dashboard/templates/ ./mcp_proxy/dashboard/templates/
COPY app/dashboard/templates/ ./app/dashboard/templates/
RUN mkdir -p /out \
 && tailwindcss \
      -c ./tailwind.config.js \
      -i ./mcp_proxy/dashboard/static_src/input.css \
      -o /out/tailwind.css \
      --minify

# -----------------------------------------------------------------------------
# Stage 2: Python runtime
# -----------------------------------------------------------------------------
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY mcp_proxy/requirements-proxy.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy proxy code + SDK
COPY mcp_proxy/ ./mcp_proxy/
COPY cullis_sdk/ ./cullis_sdk/

# Inject pre-compiled Tailwind stylesheet (shake-out P1-10)
COPY --from=tailwind-build /out/tailwind.css /app/mcp_proxy/dashboard/static/css/tailwind.css

# Data directory for SQLite + ADR-014 nginx-cert directory shared with
# the mastio-nginx sidecar (Mastio writes Org CA + server cert here at
# first-boot; sidecar mounts read-only). UID/GID pinned to 10001:10001
# (ADR-030, aligned with Frontdesk bundle) so bind-mount host
# directories can be chown'd to a fixed numeric pair at every
# ``compose up`` via the init-permissions service, without having to
# resolve the system-allocated UID of an opaque ``useradd --system``.
RUN mkdir -p /data /var/lib/mastio/nginx-certs && \
    groupadd --system --gid 10001 proxyuser && \
    useradd --no-create-home --system --uid 10001 --gid 10001 proxyuser && \
    chown proxyuser:proxyuser /data /var/lib/mastio/nginx-certs

ENV PYTHONPATH=/app
ENV MCP_PROXY_DATABASE_URL=sqlite+aiosqlite:////data/mcp_proxy.db

# Surface the Mastio release version on /health. release-mastio.yml passes
# ``--build-arg VERSION=<tag>``; un-passed builds fall back to ``dev`` so a
# developer-laptop curl yields ``"version":"dev"`` rather than a stale literal
# that drifts from the running tag.
ARG VERSION=dev
ENV CULLIS_MASTIO_VERSION=${VERSION}

# cullis-enterprise#11 — Python defaults stderr to block-buffering when
# connected to a pipe (container stdio goes through a pipe to the runtime).
# Under burst load, logging.StreamHandler(sys.stderr) records accumulate
# in the 8 KB buffer and never surface in `docker logs` until the buffer
# fills. Boot-time INFO records appear only because several seconds pass
# before they hit the buffer cap. Forcing line-buffered mode fixes the
# WARNING visibility gap surfaced by the global rate-limit middleware —
# and, in general, keeps every mcp_proxy logger record live for ops.
ENV PYTHONUNBUFFERED=1

EXPOSE 9100

USER proxyuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9100/health')" || exit 1

# ADR-014 — the Mastio is always fronted by the mastio-nginx sidecar
# (TLS termination + mTLS gate). nginx sets X-Forwarded-Proto: https
# and X-Forwarded-For; uvicorn must opt in to those headers via
# ``--proxy-headers`` or it reconstructs ``request.url`` from its own
# bind (``http://localhost:9100/...``), and DPoP htu validation 401s
# every host-side egress call (host signs ``https://<public>:9443/...``,
# server expects ``http``).
#
# ``--forwarded-allow-ips='*'`` is safe in this image because the
# backend listener (9100) is **never** published to the host or LAN —
# it is reachable only from the sidecar inside the same docker pod /
# k8s pod / compose network. Operators who run the bare image without
# a sidecar (not the supported topology) override this CMD or rebind
# 9100 to 127.0.0.1.
CMD ["uvicorn", "mcp_proxy.main:app", "--host", "0.0.0.0", "--port", "9100", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
