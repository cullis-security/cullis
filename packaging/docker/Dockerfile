# Multi-stage Dockerfile for the Cullis Connector.
#
# Build context: the monorepo root (NOT this directory). The release
# workflow and local developers invoke it as:
#
#   docker build -f packaging/docker/Dockerfile -t cullis-connector .
#
# Why multi-stage:
#   • Stage 1 (`builder`) owns build-time toolchain (gcc, rust for
#     cryptography) and produces a single wheel from the standalone
#     `packaging/pypi/pyproject.toml`.
#   • Stage 2 (`runtime`) is a slim python base that only installs the
#     wheel plus its dependencies — no toolchain, no build artefacts.
#
# Image size target: ~100 MiB uncompressed. If this grows significantly,
# revisit by switching to `python:3.12-alpine` (requires musl-compatible
# cryptography wheels) or distroless.

# ── Stage 1: builder ────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Build deps only — discarded in the runtime stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN python -m pip install --upgrade pip build \
 && python -m build --wheel --outdir /dist packaging/pypi

# ── Stage 2: runtime ────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root user — the connector never needs privileged ops.
RUN useradd --create-home --uid 10001 --shell /bin/false cullis

COPY --from=builder /dist/*.whl /tmp/
RUN pip install /tmp/cullis_connector-*.whl && rm /tmp/cullis_connector-*.whl

USER cullis
WORKDIR /home/cullis

# ``cullis-connector`` reads config + identity from ``~/.cullis``. Mount
# a host directory there to persist the enrollment across container
# restarts, e.g.:
#
#   docker run --rm -v ~/.cullis:/home/cullis/.cullis \
#       ghcr.io/cullis-security/cullis-connector enroll \
#       --site-url https://cullis-site.acme.local \
#       --requester-name "Alice" --requester-email "alice@acme.example"

ENTRYPOINT ["cullis-connector"]
CMD ["--help"]

LABEL org.opencontainers.image.title="cullis-connector" \
      org.opencontainers.image.description="MCP connector for the Cullis agent-trust network" \
      org.opencontainers.image.source="https://github.com/cullis-security/cullis" \
      org.opencontainers.image.licenses="FSL-1.1-Apache-2.0" \
      org.opencontainers.image.vendor="Cullis Security"
