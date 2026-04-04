#!/usr/bin/env bash
# Start the Agent Trust Network broker
# Usage: ./run.sh [--port 8000] [--no-reload]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"
LIBSTDCXX=$(find /nix/store -maxdepth 3 -name "libstdc++.so.6" 2>/dev/null | head -1 | xargs dirname)

if [ ! -d "$VENV" ]; then
  echo "[run.sh] venv not found — run first: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

export LD_LIBRARY_PATH="$LIBSTDCXX:$LD_LIBRARY_PATH"
export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"

# --proxy-headers: trust X-Forwarded-Proto and X-Forwarded-Host from the reverse
# proxy so that request.url is reconstructed correctly for DPoP HTU validation.
# --forwarded-allow-ips: restrict which IPs can inject forwarded headers.
# Defaults to 127.0.0.1; set FORWARDED_ALLOW_IPS env var to override (e.g. "10.0.0.0/8").
FORWARDED_ALLOW_IPS="${FORWARDED_ALLOW_IPS:-127.0.0.1}"

exec "$VENV/bin/uvicorn" app.main:app \
  --reload \
  --host 0.0.0.0 \
  --port 8000 \
  --proxy-headers \
  --forwarded-allow-ips "$FORWARDED_ALLOW_IPS" \
  "$@"
