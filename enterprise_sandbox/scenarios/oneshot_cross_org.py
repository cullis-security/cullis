"""Sandbox scenario — cross-org A2A message round-trip.

Executed inside a running agent container with:
    docker compose exec agent-X python /app/scenarios/oneshot_cross_org.py

Uses the session flow (``open_session`` + ``send`` + ``close``) because
the SPIRE and BYOCA agents in this sandbox authenticate directly to the
broker, and ``send_oneshot`` requires proxy API-key enrollment
(``CullisClient.from_connector`` or ``from_enrollment``). The session
path exercises the same cross-org envelope + ADR-009 counter-signature
chain, just with a session handshake in front.

Env:
    BROKER_URL         proxy reverse-proxy URL
    ORG_ID             this agent's org
    AGENT_NAME         this agent's short name
    AGENT_AUTH         'spire' (default) | 'byoca'
    TARGET_AGENT_ID    peer (e.g. orgb::agent-b) — required
    TARGET_ORG_ID      peer org_id (defaults to the prefix of TARGET_AGENT_ID)
    SPIFFE_ENDPOINT_SOCKET  (spire mode only)
    CERT_PATH, KEY_PATH     (byoca mode only)
"""
from __future__ import annotations

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
    if not target or "::" not in target:
        _fail("TARGET_AGENT_ID is required, format ``org::agent``")
        return 2

    target_org = os.environ.get("TARGET_ORG_ID") or target.split("::", 1)[0]
    org_id = os.environ["ORG_ID"]
    agent_name = os.environ["AGENT_NAME"]
    sender = f"{org_id}::{agent_name}"

    print(
        f"\n{BOLD}═══ Cross-org session message — "
        f"{sender} → {target} ═══{RESET}",
        flush=True,
    )

    _step(1, "Authenticate through the local Mastio")
    client = _auth()
    _ok(f"logged in as {sender}")

    _step(2, "Open a cross-org session")
    _info(f"target_org={target_org}, target_agent={target}")
    try:
        session_id = client.open_session(
            target_agent_id=target,
            target_org_id=target_org,
            capabilities=["oneshot.message"],
        )
    except Exception as exc:
        _fail(f"open_session failed: {exc!r}")
        return 1
    _ok(f"session_id={session_id}")

    _step(3, "Send an end-to-end encrypted message")
    nonce = uuid.uuid4().hex[:16]
    payload = {
        "nonce": nonce,
        "hello": "cross-org message from the sandbox scenario driver",
        "sender": sender,
        "sent_at": time.time(),
    }
    _info(f"payload nonce = {nonce}")
    try:
        msg_id = client.send(
            session_id=session_id,
            sender_agent_id=sender,
            payload=payload,
            recipient_agent_id=target,
        )
    except Exception as exc:
        _fail(f"send failed: {exc!r}")
        return 1
    _ok(f"message enqueued — msg_id={msg_id}")

    _step(4, "Verify on the recipient side")
    _info(
        f"grep the recipient's log — "
        f"`demo.sh logs {target.split('::', 1)[1]} | grep {nonce}`"
    )
    _info("the recipient agent's polling loop will decrypt + surface it")

    print(
        f"\n{BOLD}{GREEN}✓ cross-org session + envelope exercised end-to-end{RESET}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
