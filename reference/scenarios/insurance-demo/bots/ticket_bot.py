"""Ticket Bot — request-response agent for the insurance demo.

Identity: ``mediterranean::agent::ticket-bot``
Reach:    intra-org only
Scope:    claims-db.write + oneshot.message

What it does (event loop):

  1. Authenticate to Mediterranean's Mastio with the cert/key minted by ``seed.py``
  2. Poll the inbox for incoming requests addressed to this agent
     (typically from ``mediterranean::user::claim-manager``)
  3. For each request, parse the natural-language claim context, generate
     a deterministic ticket ID (``TKT-YYYY-MM-DD-NNN``), persist a
     formal record into the claims-db (status=under-review, ticket_ref
     populated), and reply to the sender with the ticket ID + URL
  4. Continue polling until SIGINT

Run modes:

  python ticket_bot.py --once                # process one inbox message, exit
  python ticket_bot.py --watch               # daemon, polls forever
  python ticket_bot.py --demo                # one-shot for the recording

This is the U2A return path: claim-manager (user) asks ticket-bot (agent)
to formalise a claim, ticket-bot writes to the DB and answers back. Both
sides intra-org. Zero cross-org traffic from this bot.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time

from cullis_sdk import CullisClient


HERE = pathlib.Path(__file__).resolve().parent
STATE_DIR = (HERE.parents[2] / "state" / "insurance-demo" / "agents" / "ticket-bot").resolve()
MASTIO_URL = os.environ.get("CULLIS_PROXY_A_URL", "https://localhost:9100")
POLL_INTERVAL_S = 3.0


def _next_ticket_id() -> str:
    """``TKT-YYYY-MM-DD-NNN`` — counter persisted to a file so two runs
    in the same day don't collide."""
    counter_path = STATE_DIR / "ticket-counter"
    today = time.strftime("%Y-%m-%d")
    if counter_path.exists():
        try:
            saved_date, saved_n = counter_path.read_text().strip().split(":")
            n = int(saved_n) + 1 if saved_date == today else 1
        except Exception:
            n = 1
    else:
        n = 1
    counter_path.write_text(f"{today}:{n}")
    return f"TKT-{today}-{n:03d}"


def _process_request(client: CullisClient, msg: dict) -> dict | None:
    """Decrypt the incoming request, generate a ticket, persist it,
    return the reply payload. Returns None if the message is not a
    valid request (skip + ack). """
    try:
        decrypted = client.decrypt_oneshot(msg)
    except Exception as exc:
        print(f"[ticket-bot] decrypt failed for msg {msg.get('msg_id')}: {exc}",
              file=sys.stderr)
        return None
    payload = decrypted.get("payload") or {}

    # Expected request shape (from claim-manager):
    #   {"action": "create_ticket", "claim_id": "INC-2026-0501",
    #    "context": "..."}
    if payload.get("action") != "create_ticket":
        return None

    ticket_id = _next_ticket_id()
    claim_id = payload.get("claim_id", "unknown")
    context = payload.get("context", "")

    # Persist into the claims DB via the MCP server.
    try:
        client.call_mcp_tool(
            resource_id="mediterranean::resource::mcp::claims-db",
            tool_name="exec_sql",
            arguments={
                "statement": (
                    "UPDATE claims SET status = 'under-review', "
                    "notes = COALESCE(notes,'') || ' [ticket=' || $1 || ']' "
                    "WHERE claim_id = $2"
                ),
                "params": [ticket_id, claim_id],
            },
        )
    except Exception as exc:
        print(f"[ticket-bot] DB update failed ({exc}) — replying anyway",
              file=sys.stderr)

    return {
        "kind":          "ticket-created",
        "ticket_id":     ticket_id,
        "claim_id":      claim_id,
        "url":           f"https://claims.local/tickets/{ticket_id}",
        "context_echo":  context[:200],
        "created_at":    int(time.time()),
    }


def run_once(verbose: bool = False) -> int:
    cert = STATE_DIR / "agent.pem"
    key  = STATE_DIR / "agent-key.pem"
    if not (cert.exists() and key.exists()):
        print(f"[ticket-bot] missing identity at {STATE_DIR} — "
              "did you run ./run.sh seed?", file=sys.stderr)
        return 2

    client = CullisClient.from_identity_dir(
        MASTIO_URL,
        cert_path=cert,
        key_path=key,
        agent_id="mediterranean::agent::ticket-bot",
        org_id="mediterranean",
        verify_tls=False,
    )
    client.login_via_proxy()
    client._signing_key_pem = key.read_text()

    rows = client.receive_oneshot()
    if not rows:
        if verbose:
            print("[ticket-bot] inbox empty")
        return 0

    handled = 0
    for msg in rows:
        reply = _process_request(client, msg)
        if reply is None:
            continue
        sender = msg["sender_agent_id"]
        resp = client.send_oneshot(
            recipient_id=sender,
            payload=reply,
            reply_to=msg["correlation_id"],
            ttl_seconds=300,
        )
        print(f"[ticket-bot] ticket {reply['ticket_id']} → {sender} "
              f"(reply_to={msg['correlation_id']})")
        if verbose:
            print(json.dumps(reply, indent=2))
        handled += 1
    return 0 if handled or not rows else 0


def watch() -> int:
    print("[ticket-bot] watching inbox… (Ctrl+C to stop)")
    while True:
        try:
            run_once(verbose=False)
        except KeyboardInterrupt:
            print("\n[ticket-bot] stopping")
            return 0
        except Exception as exc:
            print(f"[ticket-bot] error in tick: {exc}", file=sys.stderr)
        time.sleep(POLL_INTERVAL_S)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--once",  action="store_true",
                   help="single inbox sweep then exit")
    p.add_argument("--demo",  action="store_true",
                   help="demo mode: --once + verbose")
    p.add_argument("--watch", action="store_true",
                   help="daemon — poll inbox forever")
    args = p.parse_args()
    if args.watch:
        return watch()
    return run_once(verbose=args.demo)


if __name__ == "__main__":
    sys.exit(main())
