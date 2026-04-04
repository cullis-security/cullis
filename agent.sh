#!/usr/bin/env bash
# Start an agent client
#
# PREREQUISITE: run the administrative bootstrap first (once only):
#   python bootstrap.py
#
# Usage:
#   ./agent.sh --config agents/manufacturer.env   # terminal 1 (responder)
#   ./agent.sh --config agents/buyer.env          # terminal 2 (initiator)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"
LIBSTDCXX=$(find /nix/store -maxdepth 3 -name "libstdc++.so.6" 2>/dev/null | head -1 | xargs dirname)

if [ ! -d "$VENV" ]; then
  echo "[agent.sh] venv not found — run first: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

export LD_LIBRARY_PATH="$LIBSTDCXX:$LD_LIBRARY_PATH"
export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"

exec "$VENV/bin/python" "$SCRIPT_DIR/agents/client.py" "$@"
