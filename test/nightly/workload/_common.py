"""Shared helpers for nightly workload drivers: identity loading, JSONL
logging, graceful shutdown. Each driver runs as its own process and writes
to test/nightly/logs/<run-ts>/<driver>-<agent>.jsonl.

Identity pattern mirrors sandbox/scenarios/_identity.py — ADR-014 mTLS
client cert + DPoP runtime auth needs both login_via_proxy() (for
session APIs that go through _authed_request) and _signing_key_pem
(for send_oneshot outer signature).
"""
from __future__ import annotations

import json
import os
import pathlib
import signal
import sys
import threading
import time
from typing import Any

from cullis_sdk import CullisClient

STATE = pathlib.Path(__file__).resolve().parent.parent / "state"
LOGS_ROOT = pathlib.Path(__file__).resolve().parent.parent / "logs"

MASTIO_URLS = {
    "orga": os.environ.get("MASTIO_A_URL", "https://localhost:9443"),
    "orgb": os.environ.get("MASTIO_B_URL", "https://localhost:9543"),
}


def load_manifest() -> list[dict]:
    path = STATE / "agents.json"
    if not path.exists():
        raise SystemExit(
            f"{path} missing — run './nightly.sh full' before a workload driver"
        )
    return json.loads(path.read_text())


def load_client(agent_id: str) -> CullisClient:
    """Replicates sandbox/scenarios/_identity.load_enrolled_client but
    reads state from the local test/nightly/state/ bind mount.

    ADR-014 — TLS client cert authenticates against the per-org nginx
    sidecar; ``verify_tls=False`` for the self-signed Org CA.
    """
    org_id, agent_name = agent_id.split("::", 1)
    identity_dir = STATE / org_id / "agents" / agent_name
    for f in ("agent.pem", "agent-key.pem", "dpop.jwk"):
        if not (identity_dir / f).exists():
            raise SystemExit(
                f"{identity_dir / f} missing — agent not enrolled"
            )

    mastio_url = MASTIO_URLS[org_id]
    key_path = identity_dir / "agent-key.pem"
    client = CullisClient.from_identity_dir(
        mastio_url,
        cert_path=identity_dir / "agent.pem",
        key_path=key_path,
        dpop_key_path=identity_dir / "dpop.jwk",
        agent_id=agent_id,
        org_id=org_id,
        verify_tls=False,
        timeout=30.0,
    )
    # login_via_proxy mints a broker JWT so session APIs work.
    client.login_via_proxy()
    client._signing_key_pem = key_path.read_text()
    return client


class JsonlLogger:
    """Line-oriented JSON logger, thread-safe, flushes every event so
    tail -f works and so a crashed driver doesn't lose the tail.
    """

    def __init__(self, path: pathlib.Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", buffering=1)  # line-buffered
        self._lock = threading.Lock()

    def write(self, **fields: Any) -> None:
        fields.setdefault("ts", time.time())
        line = json.dumps(fields, separators=(",", ":"), default=str)
        with self._lock:
            self._fh.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._fh.close()


def run_ts() -> str:
    """Single run timestamp — nightly.sh exports this so all drivers in
    the same go-invocation land in the same logs subdir."""
    return os.environ.get("NIGHTLY_RUN_TS") or time.strftime("%Y%m%d-%H%M%S")


def logger_for(driver: str, agent_id: str) -> JsonlLogger:
    safe = agent_id.replace("::", "_")
    path = LOGS_ROOT / run_ts() / f"{driver}-{safe}.jsonl"
    return JsonlLogger(path)


class Shutdown:
    """Cooperative stop flag, toggled by SIGINT/SIGTERM. Drivers poll
    ``stopped`` in their main loop and exit cleanly on True."""

    def __init__(self) -> None:
        self._event = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._handler)

    def _handler(self, *_: Any) -> None:
        sys.stderr.write("[workload] shutdown signal received\n")
        self._event.set()

    @property
    def stopped(self) -> bool:
        return self._event.is_set()

    def wait(self, seconds: float) -> bool:
        """Sleep ``seconds`` but wake up early on shutdown. Returns True
        if shutdown triggered during the wait."""
        return self._event.wait(seconds)
