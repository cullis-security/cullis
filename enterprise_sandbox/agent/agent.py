"""Sandbox demo agent — fetches SVID from SPIRE Workload API and authenticates to broker.

Env:
    BROKER_URL                e.g. http://broker:8000
    ORG_ID                    e.g. orga
    AGENT_NAME                e.g. agent-a (short name, becomes {ORG_ID}::{AGENT_NAME})
    SPIFFE_ENDPOINT_SOCKET    path to SPIRE Workload API socket
    AGENT_MODE                'responder' (default) or 'initiator'

Blocco 4a scope: prove SPIFFE auth works end-to-end.
  - fetch SVID
  - login to broker
  - drop a ready-marker file (/tmp/ready) for smoke to detect
  - stay alive

Cross-org messaging lives in Blocco 4c.
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

from cullis_sdk import CullisClient


def wait_for_socket(path: str, timeout: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pathlib.Path(path).exists():
            return True
        time.sleep(0.5)
    return False


def wait_for_http(url: str, timeout: float = 60.0) -> bool:
    import urllib.request
    import urllib.error
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


def main() -> int:
    broker = os.environ["BROKER_URL"].rstrip("/")
    org_id = os.environ["ORG_ID"]
    name = os.environ["AGENT_NAME"]
    socket = os.environ.get(
        "SPIFFE_ENDPOINT_SOCKET", "/run/spire/sockets/agent.sock"
    )
    agent_id = f"{org_id}::{name}"

    # Wait for Workload API socket (spire-agent may still be starting)
    raw = socket.removeprefix("unix://") if socket.startswith("unix://") else socket
    if not wait_for_socket(raw, timeout=60):
        print(f"[{agent_id}] FAIL: socket {raw} not available after 60s",
              file=sys.stderr, flush=True)
        return 1

    # Wait for broker (we start in parallel with it)
    if not wait_for_http(f"{broker}/health", timeout=60):
        print(f"[{agent_id}] FAIL: broker {broker} not reachable", file=sys.stderr, flush=True)
        return 1

    # Authenticate via SPIFFE — this is the whole point of the demo
    try:
        client = CullisClient.from_spiffe_workload_api(
            broker, org_id=org_id, socket_path=socket,
        )
    except Exception as e:
        print(f"[{agent_id}] FAIL: SPIFFE auth: {e!r}", file=sys.stderr, flush=True)
        return 2

    print(f"[{agent_id}] SPIFFE auth OK — token={client.token[:24] if client.token else None}...",
          flush=True)

    # Ready-marker: smoke reads this to assert success without parsing logs.
    pathlib.Path("/tmp/ready").write_text(agent_id + "\n")

    # Keep alive (long-running responder). Token refresh via SVID rotation
    # is a later concern — SDK currently does not auto-rotate.
    while True:
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
