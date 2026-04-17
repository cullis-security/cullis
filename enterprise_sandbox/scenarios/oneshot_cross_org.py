"""Sandbox scenario — cross-org one-shot messaging (ADR-008 envelope).

Executed inside a running agent container with:
    docker compose exec agent-X python /app/scenarios/oneshot_cross_org.py

Reuses the agent's own auth path (SPIRE or BYOCA) so the output
mirrors what a production deployment would look like — just with
narrated, colorized steps the user can follow by eye.

Env:
    BROKER_URL         proxy reverse-proxy URL
    ORG_ID             this agent's org
    AGENT_NAME         this agent's short name
    AGENT_AUTH         'spire' (default) | 'byoca'
    TARGET_AGENT_ID    peer (e.g. orgb::agent-b) — required
    SPIFFE_ENDPOINT_SOCKET  (spire mode only)
    CERT_PATH, KEY_PATH     (byoca mode only)
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

from cullis_sdk import CullisClient


RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[32m"
CYAN  = "\033[36m"
YELLOW = "\033[33m"
GRAY  = "\033[90m"


def _step(n: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}▶ Step {n} — {title}{RESET}", flush=True)


def _ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}", flush=True)


def _info(msg: str) -> None:
    print(f"  {GRAY}…{RESET} {msg}", flush=True)


def _fail(msg: str) -> None:
    print(f"  {YELLOW}✗{RESET} {msg}", flush=True)


def _auth() -> CullisClient:
    broker = os.environ["BROKER_URL"]
    org_id = os.environ["ORG_ID"]
    agent_name = os.environ["AGENT_NAME"]
    mode = os.environ.get("AGENT_AUTH", "spire").lower()

    if mode == "spire":
        socket = os.environ.get(
            "SPIFFE_ENDPOINT_SOCKET", "/run/spire/sockets/agent.sock",
        )
        _info(f"authenticating via SPIRE workload API at {socket}")
        return CullisClient.from_spiffe_workload_api(
            broker, org_id=org_id, socket_path=socket,
        )

    if mode == "byoca":
        cert = Path(os.environ["CERT_PATH"]).read_text()
        key = Path(os.environ["KEY_PATH"]).read_text()
        _info(f"authenticating via BYOCA (cert={os.environ['CERT_PATH']})")
        client = CullisClient(broker, verify_tls=False)
        client.login_from_pem(f"{org_id}::{agent_name}", org_id, cert, key)
        return client

    raise SystemExit(f"unknown AGENT_AUTH: {mode}")


def main() -> int:
    target = os.environ.get("TARGET_AGENT_ID")
    if not target:
        _fail("TARGET_AGENT_ID is required (e.g. orgb::agent-b)")
        return 2

    org_id = os.environ["ORG_ID"]
    agent_name = os.environ["AGENT_NAME"]
    sender = f"{org_id}::{agent_name}"

    print(
        f"\n{BOLD}═══ Cross-org one-shot — "
        f"{sender} → {target} ═══{RESET}",
        flush=True,
    )

    _step(1, "Authenticate through the local Mastio")
    client = _auth()
    _ok(f"logged in as {sender}")

    _step(2, "Resolve the recipient path + envelope transport")
    _info("the Mastio will call /v1/egress/resolve and return 'cross-org'")
    _info("with 'envelope' transport (ADR-008 Phase 1 / PR #3)")

    nonce = uuid.uuid4().hex[:16]
    payload = {
        "nonce": nonce,
        "hello": "ADR-008 cross-org sessionless message",
        "sender": sender,
        "sent_at": time.time(),
    }

    _step(3, "Send the envelope one-shot")
    _info(f"payload nonce = {nonce}")
    try:
        resp = client.send_oneshot(
            recipient_id=target,
            payload=payload,
            ttl_seconds=300,
        )
    except Exception as exc:
        _fail(f"send failed: {exc!r}")
        return 1

    _ok(f"enqueued — msg_id={resp.get('msg_id')}  status={resp.get('status')}")
    _ok(f"correlation_id={resp.get('correlation_id')}")

    _step(4, "Verify on the recipient side")
    _info(
        f"grep the recipient's log — "
        f"`demo.sh logs {target.split('::', 1)[1]} | grep {nonce}`"
    )
    _info("the recipient agent's polling loop will decrypt + surface it")

    print(
        f"\n{BOLD}{GREEN}✓ one-shot path exercised end-to-end{RESET}",
        flush=True,
    )
    print(
        f"{GRAY}Run `demo.sh logs {target.split('::', 1)[1]}` "
        f"to see the receiver's view.{RESET}\n",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
