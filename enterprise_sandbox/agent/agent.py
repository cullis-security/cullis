"""Sandbox demo agent — authenticates to broker via SPIFFE or classic BYOCA.

Env:
    BROKER_URL                e.g. http://broker:8000
    ORG_ID                    e.g. orga
    AGENT_NAME                short name (becomes {ORG_ID}::{AGENT_NAME})
    AGENT_AUTH                'spire' (default) or 'byoca'
    SPIFFE_ENDPOINT_SOCKET    path to SPIRE Workload API socket (spire mode only)
    CERT_PATH, KEY_PATH       PEM paths for classic BYOCA cert (byoca mode only)

Scope: prove both auth paths work end-to-end against the same broker and
that a classic BYOCA agent can live next to a SPIRE SVID agent inside
the same org (ADR-003 §2.6 mixed mode).

Cross-org messaging lives in a follow-up (Blocco 4c, issue #96).
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


def _auth_spire(broker: str, org_id: str) -> CullisClient:
    socket = os.environ.get(
        "SPIFFE_ENDPOINT_SOCKET", "/run/spire/sockets/agent.sock"
    )
    raw = socket.removeprefix("unix://") if socket.startswith("unix://") else socket
    if not wait_for_socket(raw, timeout=60):
        raise RuntimeError(f"socket {raw} not available after 60s")
    return CullisClient.from_spiffe_workload_api(
        broker, org_id=org_id, socket_path=socket,
    )


def _auth_byoca(broker: str, org_id: str, agent_id: str) -> CullisClient:
    cert_path = os.environ["CERT_PATH"]
    key_path = os.environ["KEY_PATH"]
    # Wait for bootstrap to publish the cert on the shared volume.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if pathlib.Path(cert_path).exists() and pathlib.Path(key_path).exists():
            break
        time.sleep(0.5)
    else:
        raise RuntimeError(f"BYOCA cert/key not found at {cert_path} / {key_path}")
    cert_pem = pathlib.Path(cert_path).read_text()
    key_pem = pathlib.Path(key_path).read_text()
    client = CullisClient(broker)
    client.login_from_pem(agent_id, org_id, cert_pem, key_pem)
    return client


def main() -> int:
    broker = os.environ["BROKER_URL"].rstrip("/")
    org_id = os.environ["ORG_ID"]
    name = os.environ["AGENT_NAME"]
    auth_mode = os.environ.get("AGENT_AUTH", "spire").lower()
    agent_id = f"{org_id}::{name}"

    # Wait for broker (we start in parallel with it)
    if not wait_for_http(f"{broker}/health", timeout=60):
        print(f"[{agent_id}] FAIL: broker {broker} not reachable", file=sys.stderr, flush=True)
        return 1

    try:
        if auth_mode == "spire":
            client = _auth_spire(broker, org_id)
            auth_label = "SPIFFE"
        elif auth_mode == "byoca":
            client = _auth_byoca(broker, org_id, agent_id)
            auth_label = "BYOCA"
        else:
            print(f"[{agent_id}] FAIL: unknown AGENT_AUTH={auth_mode!r}",
                  file=sys.stderr, flush=True)
            return 2
    except Exception as e:
        print(f"[{agent_id}] FAIL: {auth_mode} auth: {e!r}",
              file=sys.stderr, flush=True)
        return 2

    print(f"[{agent_id}] {auth_label} auth OK — token={client.token[:24] if client.token else None}...",
          flush=True)

    # Ready-marker: smoke reads this to assert success without parsing logs.
    pathlib.Path("/tmp/ready").write_text(agent_id + "\n")

    # Keep alive (long-running responder). Token refresh via SVID rotation
    # is a later concern — SDK currently does not auto-rotate.
    while True:
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
