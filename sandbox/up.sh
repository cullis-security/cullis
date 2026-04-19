#!/usr/bin/env bash
# Enterprise sandbox — up
# Status: stub, populated per block in imp/sandbox_plan.md
set -euo pipefail

cd "$(dirname "$0")"

echo "[sandbox] docker compose config check"
docker compose config >/dev/null

echo "[sandbox] starting services"
docker compose up -d --wait

echo "[sandbox] status"
docker compose ps
