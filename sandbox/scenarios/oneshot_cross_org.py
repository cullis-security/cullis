"""Sandbox scenario — cross-org A2A message via sessionless one-shot (ADR-011 Phase 4b).

Executed inside a running agent container with:
    docker compose exec agent-X python /app/scenarios/oneshot_cross_org.py

Uses ``send_oneshot`` on the proxy egress surface — the intra-org
short-circuit (ADR-001) routes same-proxy peers without involving the
Court, while cross-org targets resolve to ``envelope`` transport and
ride the ADR-009 counter-signature chain end-to-end. No session
handshake, no accept: fire-and-forget enqueue, inbox-polled on the
recipient side.

Env:
    BROKER_URL         proxy reverse-proxy URL (the Mastio this agent sits behind)
    ORG_ID             this agent's org
    AGENT_NAME         this agent's short name
    TARGET_AGENT_ID    peer (e.g. orgb::agent-b) — required
    IDENTITY_ROOT      where bootstrap-mastio wrote credentials (default /state)
"""
from __future__ import annotations

import os
import sys
import time
import uuid

from _identity import load_enrolled_client


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


def main() -> int:
    target = os.environ.get("TARGET_AGENT_ID")
    if not target or "::" not in target:
        _fail("TARGET_AGENT_ID is required, format ``org::agent``")
        return 2

    broker = os.environ["BROKER_URL"].rstrip("/")
    org_id = os.environ["ORG_ID"]
    agent_name = os.environ["AGENT_NAME"]
    identity_root = os.environ.get("IDENTITY_ROOT", "/state")
    sender = f"{org_id}::{agent_name}"

    print(
        f"\n{BOLD}═══ Cross-org sessionless one-shot — "
        f"{sender} → {target} ═══{RESET}",
        flush=True,
    )

    _step(1, "Load enrolled identity and authenticate to the local Mastio")
    _info(
        f"reading agent.pem + agent-key.pem + dpop.jwk from {identity_root}/{org_id}/agents/{agent_name}/"
    )
    try:
        client = load_enrolled_client(broker, org_id, agent_name, identity_root)
    except Exception as exc:
        _fail(f"auth failed: {exc!r}")
        return 1
    _ok(f"ready as {sender}")

    _step(2, "Send an end-to-end encrypted one-shot")
    nonce = uuid.uuid4().hex[:16]
    payload = {
        "nonce": nonce,
        "hello": "cross-org message from the sandbox scenario driver",
        "sender": sender,
        "sent_at": time.time(),
    }
    _info(f"payload nonce = {nonce}")
    try:
        resp = client.send_oneshot(target, payload)
    except Exception as exc:
        _fail(f"send_oneshot failed: {exc!r}")
        return 1
    msg_id = resp.get("msg_id")
    status = resp.get("status")
    correlation_id = resp.get("correlation_id")
    _ok(
        f"enqueued — msg_id={msg_id}, status={status}, "
        f"correlation_id={correlation_id}"
    )

    _step(3, "Verify on the recipient side")
    recipient_name = target.split("::", 1)[1]
    _info(
        f"the recipient's inbox loop prints incoming nonces — tail with: "
        f"`demo.sh logs {recipient_name} | grep {nonce}`"
    )

    print(
        f"\n{BOLD}{GREEN}✓ cross-org one-shot exercised end-to-end "
        f"({sender} → {target}, nonce={nonce}){RESET}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
