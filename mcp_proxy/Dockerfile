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
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) TW_ARCH=x64 ;; \
      arm64) TW_ARCH=arm64 ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -sSLf "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-${TW_ARCH}" \
      -o /usr/local/bin/tailwindcss; \
    chmod +x /usr/local/bin/tailwindcss
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

# Data directory for SQLite
RUN mkdir -p /data && \
    useradd --no-create-home --system proxyuser && \
    chown proxyuser:proxyuser /data

ENV PYTHONPATH=/app
ENV MCP_PROXY_DATABASE_URL=sqlite+aiosqlite:////data/mcp_proxy.db

EXPOSE 9100

USER proxyuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9100/health')" || exit 1

CMD ["uvicorn", "mcp_proxy.main:app", "--host", "0.0.0.0", "--port", "9100"]
