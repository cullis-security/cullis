"""
Demo Supplier Agent — daemon that listens for incoming sessions via WebSocket.

Runs continuously, accepts sessions, and responds to buyer RFQs with
structured JSON. Uses LLM to decide pricing strategy.

Usage:
  python demo/supplier_agent.py --config certs/chipfactory/chipfactory__sales-agent.env
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.sdk import (
    BrokerClient, load_env_file, cfg, log, ask_llm,
    GREEN, CYAN, YELLOW, RED, GRAY, BOLD, RESET,
    _open_ws,
)

CATALOG = {
    "BLT-M8-ZN": {
        "name": "Zinc-plated M8 bolts",
        "stock": 8500,
        "base_price": 0.048,
        "discounts": {"500": 0.05, "2000": 0.10},
        "lead_days": 2,
        "min_order": 100,
        "payment_terms": "Net 30",
    },
    "BLT-M10-ZN": {
        "name": "Zinc-plated M10 bolts",
        "stock": 3200,
        "base_price": 0.075,
        "discounts": {"500": 0.05},
        "lead_days": 3,
        "min_order": 50,
        "payment_terms": "Net 30",
    },
    "SCR-M6-IX": {
        "name": "Stainless M6 screws",
        "stock": 12000,
        "base_price": 0.032,
        "discounts": {},
        "lead_days": 1,
        "min_order": 1,
        "payment_terms": "Net 30",
    },
}

SYSTEM_PROMPT = """\
You are a sales agent for ChipFactory (ItalMetal S.p.A.), an Italian manufacturer.
You respond to buyer requests with structured JSON messages.

Your product catalog:
{catalog}

You will receive buyer messages as JSON. Analyze them and respond with ONLY valid JSON.

Message types you can send:

1. Quote (response to RFQ):
   {{"type": "quote", "sku": "...", "name": "...", "quantity": N, "unit_price": N.NNN, "discount_pct": N, "total": N.NN, "lead_days": N, "payment_terms": "...", "available": true}}

2. Counter (if buyer's counter-offer is too low):
   {{"type": "counter", "sku": "...", "min_unit_price": N.NNN, "reason": "..."}}

3. Accept counter-offer:
   {{"type": "order_accepted", "sku": "...", "quantity": N, "unit_price": N.NNN, "total": N.NN, "lead_days": N, "payment_terms": "...", "final": true}}

4. Reject (out of stock or unreasonable):
   {{"type": "order_rejected", "sku": "...", "reason": "...", "final": true}}

Rules:
- Apply discounts automatically based on quantity thresholds in the catalog.
- You can accept counter-offers if the price is at most 5% below your discounted price.
- If stock is insufficient, reject with a clear reason.
- Always output ONLY valid JSON, no extra text.
- Add "final": true when the deal is concluded (accepted or rejected).
""".format(catalog=json.dumps(CATALOG, indent=2))


def extract_json(text: str) -> dict:
    """Extract JSON from LLM response (handles markdown code blocks)."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)
    return json.loads(text)


def handle_message(broker: BrokerClient, agent_id: str, session_id: str,
                   payload: dict, sender: str, conversation: list[dict]) -> bool:
    """Process one incoming message. Returns True if session should continue."""
    msg_type = payload.get("type", "unknown")

    log(agent_id, f"<< {msg_type.upper()} from {sender}", YELLOW)
    print(f"  {YELLOW}<{RESET} {json.dumps(payload, indent=2)}\n")

    if payload.get("final"):
        log(agent_id, "Buyer sent final message. Done.", GREEN)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False

    # Ask LLM to generate response
    llm_prompt = (
        f"Buyer sent: {json.dumps(payload)}\n"
        f"Check the catalog and respond. Output only JSON."
    )
    llm_response = ask_llm(SYSTEM_PROMPT, conversation, llm_prompt)
    msg_out = extract_json(llm_response)
    conversation.append({"role": "user", "content": llm_prompt})
    conversation.append({"role": "assistant", "content": json.dumps(msg_out)})

    log(agent_id, f">> {msg_out['type'].upper()}", CYAN)
    print(f"  {GREEN}>{RESET} {json.dumps(msg_out, indent=2)}\n")
    broker.send(session_id, agent_id, msg_out, recipient_agent_id=sender)

    if msg_out.get("final"):
        log(agent_id, "Order concluded. Closing session.", GREEN)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False

    return True


def handle_session(broker: BrokerClient, agent_id: str, session_id: str) -> None:
    """Handle a single negotiation session using WebSocket for messages."""
    conversation: list[dict] = []

    # Process any queued messages first
    queued = broker.poll(session_id, after=-1)
    for msg in queued:
        if msg["sender_agent_id"] == agent_id:
            continue
        payload = msg["payload"]
        sender = msg["sender_agent_id"]
        if not handle_message(broker, agent_id, session_id, payload, sender, conversation):
            return

    # Listen for new messages via WebSocket
    ws = _open_ws(broker, agent_id)
    if ws is not None:
        try:
            for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") != "new_message":
                    continue
                if msg.get("session_id") != session_id:
                    continue
                m = broker.decrypt_payload(msg["message"], session_id=session_id)
                if m["sender_agent_id"] == agent_id:
                    continue
                if not handle_message(broker, agent_id, session_id, m["payload"],
                                      m["sender_agent_id"], conversation):
                    return
        except Exception as e:
            log(agent_id, f"WS error during session: {e} — falling back to polling", YELLOW)
        finally:
            try:
                ws.close()
            except Exception:
                pass

    # Fallback: polling
    last_seq = max((m["seq"] for m in queued), default=-1)
    while True:
        time.sleep(2)
        sessions = broker.list_sessions()
        current = next((s for s in sessions if s["session_id"] == session_id), None)
        if current is None or current["status"] == "closed":
            log(agent_id, f"Session {session_id} closed.", GREEN)
            return

        messages = broker.poll(session_id, after=last_seq)
        for msg in messages:
            last_seq = msg["seq"]
            if msg["sender_agent_id"] == agent_id:
                continue
            if not handle_message(broker, agent_id, session_id, msg["payload"],
                                  msg["sender_agent_id"], conversation):
                return


def main():
    parser = argparse.ArgumentParser(description="Demo Supplier Agent")
    parser.add_argument("--config", required=True, help="Path to agent .env file")
    args = parser.parse_args()

    root_env = Path(__file__).parent.parent / ".env"
    if root_env.exists():
        load_env_file(str(root_env))
    load_env_file(args.config, override=True)

    agent_id   = cfg("AGENT_ID")
    org_id     = cfg("ORG_ID")
    cert_path  = cfg("AGENT_CERT_PATH")
    key_path   = cfg("AGENT_KEY_PATH")
    broker_url = cfg("BROKER_URL", "http://localhost:8000")
    caps       = cfg("CAPABILITIES", "order.read,order.write").split(",")

    print(f"\n{BOLD}{'='*50}{RESET}")
    print(f"{BOLD}  Supplier Agent — {agent_id}{RESET}")
    print(f"  Catalog: {', '.join(CATALOG.keys())}")
    print(f"{BOLD}{'='*50}{RESET}\n")

    verify_tls = not broker_url.startswith("https://localhost")
    broker = BrokerClient(broker_url, verify_tls=verify_tls)
    try:
        # ── Auth ────────────────────────────────────────────
        log(agent_id, "Authenticating...", CYAN)
        broker.register(agent_id, org_id, agent_id, caps)
        broker.login(agent_id, org_id, cert_path, key_path)
        log(agent_id, "Authenticated.", GREEN)

        # ── Listen loop with WebSocket ──────────────────────
        while True:
            # Check for any already-pending sessions first
            pending = broker.list_sessions(status_filter="pending")
            my_pending = [s for s in pending if s["target_agent_id"] == agent_id]
            if my_pending:
                session = my_pending[0]
                session_id = session["session_id"]
                initiator = session["initiator_agent_id"]
                log(agent_id, f"New session from {initiator}", GREEN)
                broker.accept_session(session_id)
                log(agent_id, f"Session accepted: {session_id}", GREEN)
                print()
                handle_session(broker, agent_id, session_id)
                log(agent_id, "Ready for next session...\n", CYAN)
                continue

            # Wait for new sessions via WebSocket
            ws = _open_ws(broker, agent_id)
            if ws is not None:
                try:
                    log(agent_id, "Listening for sessions...", GRAY)
                    for raw in ws:
                        msg = json.loads(raw)
                        if msg.get("type") == "session_pending":
                            session_id = msg["session_id"]
                            initiator = msg.get("initiator_agent_id", "unknown")
                            broker.accept_session(session_id)
                            log(agent_id, f"New session from {initiator}: {session_id}", GREEN)
                            ws.close()
                            handle_session(broker, agent_id, session_id)
                            log(agent_id, "Ready for next session...\n", CYAN)
                            break
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    log(agent_id, f"WS error: {e} — retrying...", YELLOW)
                finally:
                    try:
                        ws.close()
                    except Exception:
                        pass
            else:
                # Fallback to polling
                time.sleep(2)

    except KeyboardInterrupt:
        print(f"\n  {GRAY}Supplier agent stopped.{RESET}\n")
    finally:
        broker.close()


if __name__ == "__main__":
    main()
