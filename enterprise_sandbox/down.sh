#!/usr/bin/env bash
# Enterprise sandbox — down
#
# ``--profile full`` is required: several services (byoca-a, mcp-catalog,
# the runtime agents) are gated behind ``profiles: ["full"]`` in
# docker-compose.yml. A vanilla ``docker compose down`` ignores them, so
# after ``demo.sh full`` they survive as zombies on stale networks, and
# the next ``demo.sh full`` reuses them without recreating — which breaks
# inter-org DNS and surfaces as spurious 401s on ``/v1/egress/message/inbox``
# in smoke B4.7. Whenever a new profile is added to compose, extend this.
set -euo pipefail

cd "$(dirname "$0")"

docker compose --profile full down -v --remove-orphans
