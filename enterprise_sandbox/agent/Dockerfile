# Demo Cullis agent — installs the SDK from the local repo (with [spiffe] extra)
# and uses CullisClient.from_spiffe_workload_api() to authenticate.
#
# Build context must be the repo root (so pyproject.toml + cullis_sdk/ are visible).
FROM python:3.11-slim

# Install deps first for caching
COPY pyproject.toml /build/pyproject.toml
COPY cullis_sdk/ /build/cullis_sdk/
COPY cullis_connector/ /build/cullis_connector/

RUN pip install --no-cache-dir "/build[spiffe]"

COPY enterprise_sandbox/agent/agent.py /app/agent.py
# ADR-009 sandbox PR 4 — ship the scenario drivers alongside the runtime
# agent so `docker compose exec agent-X python /app/scenarios/…` works
# without extra build or volume wiring.
COPY enterprise_sandbox/scenarios/ /app/scenarios/

# Match spire-server registration entry `unix:uid:1000`
RUN groupadd -g 1000 agent && useradd -u 1000 -g 1000 -m -s /bin/sh agent
USER 1000:1000

WORKDIR /app
ENTRYPOINT ["python", "/app/agent.py"]
