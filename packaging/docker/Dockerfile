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
 && bash packaging/pypi-sdk/build.sh \
 && bash packaging/pypi/build.sh \
 && mkdir -p /dist \
 && mv dist/cullis_sdk-*.whl /dist/ \
 && mv dist/cullis_connector-*.whl /dist/

# ── Stage 2: runtime ────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root user — the connector never needs privileged ops.
RUN useradd --create-home --uid 10001 --shell /bin/false cullis

COPY --from=builder /dist/*.whl /tmp/
# Install with the ``dashboard`` extra so ``cullis-connector dashboard``
# (and the Frontdesk shared-mode embedded server) work out of the box —
# without it FastAPI/Starlette/Jinja2/python-multipart are missing and
# ``dashboard`` ImportErrors. The plain ``serve`` (MCP stdio) and
# ``enroll`` paths do not need the extra but it costs ~25 MiB and keeps
# the image single-purpose.
#
# We install the locally-built ``cullis-sdk`` wheel BEFORE the
# connector wheel (and pin pip to the local copy) so the ADR-021 PR4c
# user-principal factory + ADR-017 ``chat_completion`` ship in the
# image. Without this step pip would fall back to the published
# ``cullis-sdk>=0.1.2`` which predates both features and the Frontdesk
# shared-mode chat path 401s on every request.
RUN SDK_WHEEL=$(ls /tmp/cullis_sdk-*.whl) \
 && CONN_WHEEL=$(ls /tmp/cullis_connector-*.whl) \
 && pip install "${SDK_WHEEL}" \
 && pip install "${CONN_WHEEL}[dashboard]" \
 && rm "${SDK_WHEEL}" "${CONN_WHEEL}"

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
