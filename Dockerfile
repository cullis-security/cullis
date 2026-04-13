# syntax=docker/dockerfile:1.6

# -----------------------------------------------------------------------------
# Stage 1: Tailwind CSS build (shake-out P1-10)
# Uses the Tailwind standalone CLI so no Node/npm is pulled into the image.
# Output: app/static/css/tailwind.css
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
COPY app/dashboard/static_src/ ./app/dashboard/static_src/
COPY app/dashboard/templates/ ./app/dashboard/templates/
# Proxy templates are referenced by the shared tailwind.config.js content glob;
# copy them so class detection works when this stage is used by either image.
COPY mcp_proxy/dashboard/templates/ ./mcp_proxy/dashboard/templates/
RUN mkdir -p /out \
 && tailwindcss \
      -c ./tailwind.config.js \
      -i ./app/dashboard/static_src/input.css \
      -o /out/tailwind.css \
      --minify

# -----------------------------------------------------------------------------
# Stage 2: Python runtime
# -----------------------------------------------------------------------------
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code + migrations
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini .

# Inject pre-compiled Tailwind stylesheet (shake-out P1-10)
COPY --from=tailwind-build /out/tailwind.css /app/app/static/css/tailwind.css

ENV PYTHONPATH=/app

# Run as non-root user
RUN useradd --no-create-home --system appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "172.16.0.0/12"]
