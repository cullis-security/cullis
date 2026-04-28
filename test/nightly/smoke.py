"""Smoke test: load identity files for every enrolled agent and verify
each can authenticate against its Mastio by calling GET /v1/egress/peers.

Run with './nightly.sh smoke' after './nightly.sh full' has completed.
Exits 0 if N/N agents are online, 1 otherwise.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import sys
import time

from cullis_sdk import CullisClient

STATE = pathlib.Path(__file__).parent / "state"
MANIFEST = STATE / "agents.json"
MASTIO_URLS = {
    "orga": os.environ.get("MASTIO_A_URL", "https://localhost:9443"),
    "orgb": os.environ.get("MASTIO_B_URL", "https://localhost:9543"),
}

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"


def _probe(entry: dict) -> tuple[str, bool, str]:
    org_id = entry["org_id"]
    name = entry["agent_name"]
    agent_id = entry["agent_id"]
    agent_dir = STATE / org_id / "agents" / name
    cert = agent_dir / "agent.pem"
    key = agent_dir / "agent-key.pem"
    dpop = agent_dir / "dpop.jwk"

    for f in (cert, key, dpop):
        if not f.exists():
            return agent_id, False, f"missing {f.name}"

    mastio_url = MASTIO_URLS[org_id]
    try:
        client = CullisClient.from_identity_dir(
            mastio_url,
            cert_path=cert, key_path=key, dpop_key_path=dpop,
            agent_id=agent_id, org_id=org_id,
            verify_tls=False,
            timeout=30.0,
        )
        peers = client.list_peers(limit=50)
        return agent_id, True, f"{len(peers)} peers visible"
    except Exception as exc:  # noqa: BLE001 — capture any failure mode
        return agent_id, False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    if not MANIFEST.exists():
        print(f"{RED}✗{RESET} {MANIFEST} missing — run './nightly.sh full' first",
              file=sys.stderr)
        return 1

    manifest = json.loads(MANIFEST.read_text())
    total = len(manifest)
    print(f"[smoke] probing {total} agents via Mastio /v1/egress/peers")

    start = time.monotonic()
    # Parallel probe — the Mastio auth path is non-blocking post-fix
    # (issue #2), so fan-out N=10 clears 20/20 in a couple seconds.
    results: list[tuple[str, bool, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, total)) as pool:
        results = list(pool.map(_probe, manifest))

    ok = sum(1 for _, up, _ in results if up)
    elapsed = time.monotonic() - start

    # Always log failures, summarize successes
    for agent_id, up, detail in results:
        if not up:
            print(f"  {RED}✗{RESET} {agent_id:<28} {detail}")

    print(f"\n[smoke] {GREEN if ok == total else RED}{ok}/{total}{RESET} "
          f"agents online  ({elapsed:.1f}s)")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
