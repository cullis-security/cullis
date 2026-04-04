"""
Demo Buyer Agent — hybrid JSON + LLM negotiation.

Triggered by inventory_watcher.py (or manually). Authenticates with the broker,
opens a session with the supplier, and negotiates using structured JSON messages.
Uses WebSocket for real-time message exchange.

Usage:
  python demo/buyer_agent.py --config certs/electrostore/electrostore__procurement-agent.env \
    --sku BLT-M8-ZN --item "Zinc-plated M8 bolts" --quantity 5000 --supplier-org chipfactory
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

SYSTEM_PROMPT = """\
You are a procurement agent for ElectroStore. You negotiate purchase orders
with suppliers via structured JSON messages.

You will receive supplier responses as JSON. Analyze them and decide your next action.
Your output must ALWAYS be valid JSON matching one of these message types:

1. Request for Quote:
   {{"type": "rfq", "sku": "...", "quantity": N, "note": "optional note"}}

2. Counter-offer (if price is too high):
   {{"type": "counter_offer", "sku": "...", "quantity": N, "max_unit_price": N.NN, "reason": "..."}}

3. Accept quote:
   {{"type": "order_confirm", "sku": "...", "quantity": N, "accepted_price": N.NN, "delivery_days": N, "final": true}}

4. Reject (walk away):
   {{"type": "order_reject", "sku": "...", "reason": "...", "final": true}}

Rules:
- Start with an RFQ for the requested item and quantity.
- If the quoted price seems reasonable (within 20% of market), accept it.
- If too expensive, counter-offer once with a 10% lower price.
- If the supplier rejects your counter-offer, accept their original price.
- Always output ONLY valid JSON, no extra text.
- After sending order_confirm or order_reject, add "final": true to your JSON.
"""


def extract_json(text: str) -> dict:
    """Extract JSON from LLM response (handles markdown code blocks)."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)
    return json.loads(text)


def _save_result(args, last_msg: dict) -> None:
    """Save negotiation result to a file for ERP integration."""
    result = {
        "sku": args.sku,
        "item": args.item,
        "requested_quantity": args.quantity,
        "supplier_org": args.supplier_org,
        "result": last_msg,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out_path = Path(__file__).parent / f"result_{args.sku}.json"
    out_path.write_text(json.dumps(result, indent=2))
    log("RESULT", f"Saved to {out_path}", GREEN)


def main():
    parser = argparse.ArgumentParser(description="Demo Buyer Agent")
    parser.add_argument("--config",       required=True, help="Path to agent .env file")
    parser.add_argument("--sku",          required=True, help="SKU to order")
    parser.add_argument("--item",         required=True, help="Item description")
    parser.add_argument("--quantity",     required=True, type=int, help="Quantity to order")
    parser.add_argument("--supplier-org", required=True, help="Target supplier org ID")
    args = parser.parse_args()

    # Load env
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
    print(f"{BOLD}  Buyer Agent — {agent_id}{RESET}")
    print(f"  Order: {args.quantity}x {args.item} ({args.sku})")
    print(f"  Supplier: {args.supplier_org}")
    print(f"{BOLD}{'='*50}{RESET}\n")

    verify_tls = not broker_url.startswith("https://localhost")
    broker = BrokerClient(broker_url, verify_tls=verify_tls)
    try:
        # ── Auth ────────────────────────────────────────────
        log(agent_id, "Authenticating...", CYAN)
        broker.register(agent_id, org_id, agent_id, caps)
        broker.login(agent_id, org_id, cert_path, key_path)
        log(agent_id, "Authenticated.", GREEN)

        # ── Find supplier ───────────────────────────────────
        log(agent_id, f"Discovering supplier in {args.supplier_org}...", CYAN)
        candidates = broker.discover(caps)
        target = next(
            (a for a in candidates if a["org_id"] == args.supplier_org), None
        )
        if not target:
            log(agent_id, f"No supplier found in {args.supplier_org}!", RED)
            return
        target_agent_id = target["agent_id"]
        target_org_id   = target["org_id"]
        log(agent_id, f"Found: {target_agent_id}", GREEN)

        # ── Open session ────────────────────────────────────
        log(agent_id, "Opening session...", CYAN)
        session_id = broker.open_session(target_agent_id, target_org_id, ["order.write"])
        log(agent_id, f"Session: {session_id}", GREEN)

        # Wait for supplier to accept
        log(agent_id, "Waiting for supplier to accept...", GRAY)
        for _ in range(30):
            sessions = broker.list_sessions()
            s = next((x for x in sessions if x["session_id"] == session_id), None)
            if s and s["status"] == "active":
                break
            time.sleep(2)
        else:
            log(agent_id, "Timeout: supplier didn't accept.", RED)
            return
        log(agent_id, "Session active.", GREEN)

        # ── Send RFQ ────────────────────────────────────────
        conversation: list[dict] = []
        max_turns = 6

        initial_prompt = (
            f"Send an RFQ for SKU {args.sku} ({args.item}), quantity {args.quantity}. "
            f"Output only the JSON."
        )
        llm_response = ask_llm(SYSTEM_PROMPT, conversation, initial_prompt)
        msg_out = extract_json(llm_response)
        conversation.append({"role": "user", "content": initial_prompt})
        conversation.append({"role": "assistant", "content": json.dumps(msg_out)})

        log(agent_id, f">> {msg_out['type'].upper()}", CYAN)
        print(f"  {GREEN}>{RESET} {json.dumps(msg_out, indent=2)}\n")
        broker.send(session_id, agent_id, msg_out, recipient_agent_id=target_agent_id)

        # ── Negotiation via WebSocket ───────────────────────
        turns = 0
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

                    payload = m["payload"]
                    msg_type = payload.get("type", "unknown")

                    log(agent_id, f"<< {msg_type.upper()} from {m['sender_agent_id']}", YELLOW)
                    print(f"  {YELLOW}<{RESET} {json.dumps(payload, indent=2)}\n")

                    if payload.get("final"):
                        log(agent_id, "Supplier sent final message. Done.", GREEN)
                        broker.close_session(session_id)
                        _save_result(args, payload)
                        return

                    # Ask LLM what to do
                    llm_prompt = (
                        f"Supplier responded with: {json.dumps(payload)}\n"
                        f"Decide your next action. Output only JSON."
                    )
                    llm_response = ask_llm(SYSTEM_PROMPT, conversation, llm_prompt)
                    msg_out = extract_json(llm_response)
                    conversation.append({"role": "user", "content": llm_prompt})
                    conversation.append({"role": "assistant", "content": json.dumps(msg_out)})

                    log(agent_id, f">> {msg_out['type'].upper()}", CYAN)
                    print(f"  {GREEN}>{RESET} {json.dumps(msg_out, indent=2)}\n")
                    broker.send(session_id, agent_id, msg_out, recipient_agent_id=target_agent_id)

                    if msg_out.get("final"):
                        log(agent_id, "Order complete. Closing session.", GREEN)
                        broker.close_session(session_id)
                        _save_result(args, msg_out)
                        return

                    turns += 1
                    if turns >= max_turns:
                        log(agent_id, "Max turns reached.", YELLOW)
                        broker.close_session(session_id)
                        return
            except Exception as e:
                log(agent_id, f"WS error: {e} — falling back to polling", YELLOW)
            finally:
                try:
                    ws.close()
                except Exception:
                    pass

        # ── Fallback: polling ───────────────────────────────
        last_seq = -1
        for turn in range(max_turns):
            for _ in range(30):
                messages = broker.poll(session_id, after=last_seq)
                incoming = [m for m in messages if m["sender_agent_id"] != agent_id]
                if incoming:
                    break
                time.sleep(2)
            else:
                log(agent_id, "Timeout waiting for supplier response.", YELLOW)
                break

            for msg in incoming:
                last_seq = msg["seq"]
                payload = msg["payload"]
                msg_type = payload.get("type", "unknown")

                log(agent_id, f"<< {msg_type.upper()} from {msg['sender_agent_id']}", YELLOW)
                print(f"  {YELLOW}<{RESET} {json.dumps(payload, indent=2)}\n")

                if payload.get("final"):
                    log(agent_id, "Supplier sent final message. Done.", GREEN)
                    broker.close_session(session_id)
                    _save_result(args, payload)
                    return

                llm_prompt = (
                    f"Supplier responded with: {json.dumps(payload)}\n"
                    f"Decide your next action. Output only JSON."
                )
                llm_response = ask_llm(SYSTEM_PROMPT, conversation, llm_prompt)
                msg_out = extract_json(llm_response)
                conversation.append({"role": "user", "content": llm_prompt})
                conversation.append({"role": "assistant", "content": json.dumps(msg_out)})

                log(agent_id, f">> {msg_out['type'].upper()}", CYAN)
                print(f"  {GREEN}>{RESET} {json.dumps(msg_out, indent=2)}\n")
                broker.send(session_id, agent_id, msg_out, recipient_agent_id=target_agent_id)

                if msg_out.get("final"):
                    log(agent_id, "Order complete. Closing session.", GREEN)
                    broker.close_session(session_id)
                    _save_result(args, msg_out)
                    return

        log(agent_id, "Max turns reached.", YELLOW)
        broker.close_session(session_id)

    except KeyboardInterrupt:
        log(agent_id, "Interrupted.", GRAY)
    except Exception as e:
        log(agent_id, f"Error: {e}", RED)
        raise
    finally:
        broker.close()


if __name__ == "__main__":
    main()
