"""
Enterprise Buyer Agent — reads stock from ERPNext, negotiates via ATN.

Replaces the demo buyer_agent.py: instead of reading inventory.json,
this agent queries ERPNext's REST API for real stock levels and creates
actual Purchase Orders when negotiations succeed.

Usage:
  python buyer_agent.py --config agent.env
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

# Add project root to path for SDK imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.sdk import (
    BrokerClient, load_env_file, cfg, log, ask_llm,
    GREEN, CYAN, YELLOW, RED, GRAY, BOLD, RESET,
    _open_ws,
)
from connectors.erp_connector import ERPNextConnector

SYSTEM_PROMPT = """\
You are a procurement agent for ElectroStore. You negotiate purchase orders
with suppliers via structured JSON messages.

You will receive supplier responses as JSON. Analyze them and decide your next action.
Your output must ALWAYS be valid JSON matching one of these message types:

1. Request for Quote:
   {{"type": "rfq", "sku": "...", "quantity": N, "note": "optional note"}}

2. Counter-offer (if price is too high):
   {{"type": "counter_offer", "sku": "...", "quantity": N, "max_unit_price": N.NNN, "reason": "..."}}

3. Accept quote:
   {{"type": "order_confirm", "sku": "...", "quantity": N, "accepted_price": N.NNN, "delivery_days": N, "final": true}}

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


def negotiate(broker: BrokerClient, agent_id: str, session_id: str,
              target_agent_id: str, sku: str, item_name: str, quantity: int) -> dict | None:
    """Run a negotiation session. Returns the final result or None."""
    conversation: list[dict] = []
    max_turns = 6

    # Send initial RFQ
    initial_prompt = (
        f"Send an RFQ for SKU {sku} ({item_name}), quantity {quantity}. "
        f"Output only the JSON."
    )
    llm_response = ask_llm(SYSTEM_PROMPT, conversation, initial_prompt)
    msg_out = extract_json(llm_response)
    conversation.append({"role": "user", "content": initial_prompt})
    conversation.append({"role": "assistant", "content": json.dumps(msg_out)})

    log(agent_id, f">> {msg_out['type'].upper()}", CYAN)
    print(f"  {GREEN}>{RESET} {json.dumps(msg_out, indent=2)}\n")
    broker.send(session_id, agent_id, msg_out, recipient_agent_id=target_agent_id)

    # Negotiate via WebSocket
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
                    return payload

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
                    return msg_out

                max_turns -= 1
                if max_turns <= 0:
                    break
        except Exception as e:
            log(agent_id, f"WS error: {e}", YELLOW)
        finally:
            try:
                ws.close()
            except Exception:
                pass

    return None


def main():
    parser = argparse.ArgumentParser(description="Enterprise Buyer Agent")
    parser.add_argument("--config", required=True, help="Path to agent .env file")
    args = parser.parse_args()

    # Load env
    root_env = Path(__file__).parent.parent.parent / ".env"
    if root_env.exists():
        load_env_file(str(root_env))
    load_env_file(args.config, override=True)

    agent_id = cfg("AGENT_ID")
    org_id = cfg("ORG_ID")
    cert_path = cfg("AGENT_CERT_PATH")
    key_path = cfg("AGENT_KEY_PATH")
    broker_url = cfg("BROKER_URL", "https://localhost:8443")
    caps = cfg("CAPABILITIES", "order.read,order.write").split(",")
    supplier_org = cfg("SUPPLIER_ORG", "chipfactory")

    # ERPNext connection
    erp_url = cfg("ERPNEXT_URL", "http://localhost:8080")
    erp_key = cfg("ERPNEXT_API_KEY", "")
    erp_secret = cfg("ERPNEXT_API_SECRET", "")
    erp_warehouse = cfg("ERPNEXT_WAREHOUSE", "Main Warehouse - ES")
    erp_supplier = cfg("ERPNEXT_SUPPLIER", "ChipFactory S.p.A.")

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  Enterprise Buyer Agent — {agent_id}{RESET}")
    print(f"  ERP: {erp_url}")
    print(f"  Broker: {broker_url}")
    print(f"  Supplier org: {supplier_org}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    # Connect to ERPNext
    erp = ERPNextConnector(erp_url, erp_key, erp_secret)
    if not erp.ping():
        log(agent_id, "ERPNext not reachable!", RED)
        return

    log(agent_id, "Connected to ERPNext", GREEN)

    # Check stock levels
    log(agent_id, "Checking stock levels...", CYAN)
    low_items = erp.get_low_stock_items(erp_warehouse)

    if not low_items:
        log(agent_id, "All stock levels OK. Nothing to order.", GREEN)
        return

    log(agent_id, f"Found {len(low_items)} items below reorder threshold:", YELLOW)
    for item in low_items:
        print(f"  {RED}LOW{RESET}  {item.item_code}: {item.actual_qty}/{item.reorder_level} "
              f"(need {item.reorder_qty})")
    print()

    # Connect to ATN broker
    verify_tls = not broker_url.startswith("https://localhost")
    broker = BrokerClient(broker_url, verify_tls=verify_tls)

    try:
        log(agent_id, "Authenticating with ATN broker...", CYAN)
        broker.register(agent_id, org_id, agent_id, caps)
        broker.login(agent_id, org_id, cert_path, key_path)
        log(agent_id, "Authenticated.", GREEN)

        # Find supplier agent
        log(agent_id, f"Discovering supplier in {supplier_org}...", CYAN)
        candidates = broker.discover(caps)
        target = next((a for a in candidates if a["org_id"] == supplier_org), None)
        if not target:
            log(agent_id, f"No supplier agent found in {supplier_org}!", RED)
            return
        target_agent_id = target["agent_id"]
        log(agent_id, f"Found supplier: {target_agent_id}", GREEN)

        # Negotiate each low-stock item
        for item in low_items:
            log(agent_id, f"\n{'─'*40}", GRAY)
            log(agent_id, f"Negotiating: {item.item_code} ({item.item_name})", BOLD)

            # Open session
            session_id = broker.open_session(target_agent_id, supplier_org, ["order.write"])
            log(agent_id, f"Session: {session_id}", GREEN)

            # Wait for acceptance
            log(agent_id, "Waiting for supplier...", GRAY)
            for _ in range(30):
                sessions = broker.list_sessions()
                s = next((x for x in sessions if x["session_id"] == session_id), None)
                if s and s["status"] == "active":
                    break
                time.sleep(2)
            else:
                log(agent_id, "Timeout waiting for supplier.", RED)
                continue

            # Negotiate
            result = negotiate(
                broker, agent_id, session_id, target_agent_id,
                item.item_code, item.item_name, int(item.reorder_qty),
            )

            broker.close_session(session_id)

            # Create Purchase Order in ERPNext if negotiation succeeded
            if result and result.get("type") in ("order_confirm", "order_accepted"):
                price = result.get("accepted_price") or result.get("unit_price", 0)
                qty = result.get("quantity", item.reorder_qty)

                log(agent_id, f"Creating Purchase Order in ERPNext...", CYAN)
                try:
                    po_name = erp.create_purchase_order(
                        supplier=erp_supplier,
                        items=[{
                            "item_code": item.item_code,
                            "qty": qty,
                            "rate": price,
                            "warehouse": erp_warehouse,
                        }],
                    )
                    log(agent_id, f"Purchase Order created: {po_name}", GREEN)
                except Exception as exc:
                    log(agent_id, f"Failed to create PO: {exc}", RED)
            else:
                log(agent_id, "Negotiation failed or rejected.", YELLOW)

    except KeyboardInterrupt:
        log(agent_id, "Interrupted.", GRAY)
    except Exception as e:
        log(agent_id, f"Error: {e}", RED)
        raise
    finally:
        broker.close()

    print(f"\n{BOLD}Done.{RESET}\n")


if __name__ == "__main__":
    main()
