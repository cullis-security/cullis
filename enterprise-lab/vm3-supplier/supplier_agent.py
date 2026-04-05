"""
Enterprise Supplier Agent — reads catalog from Odoo, negotiates via ATN.

Replaces the demo supplier_agent.py: instead of a hardcoded CATALOG dict,
this agent queries Odoo's XML-RPC API for real product data and creates
actual Sale Orders when negotiations succeed.

Usage:
  python supplier_agent.py --config agent.env
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.sdk import (
    BrokerClient, load_env_file, cfg, log, ask_llm,
    GREEN, CYAN, YELLOW, RED, GRAY, BOLD, RESET,
    _open_ws,
)
from connectors.crm_connector import OdooConnector, CatalogProduct


def build_system_prompt(catalog: list[CatalogProduct]) -> str:
    """Build LLM system prompt with real catalog data from Odoo."""
    catalog_json = {}
    for p in catalog:
        catalog_json[p.default_code] = {
            "name": p.name,
            "stock": int(p.qty_available),
            "base_price": p.list_price,
            "discounts": p.discounts,
            "uom": p.uom,
        }

    return f"""\
You are a sales agent for ChipFactory (ItalMetal S.p.A.), an Italian manufacturer.
You respond to buyer requests with structured JSON messages.

Your product catalog (live from CRM):
{json.dumps(catalog_json, indent=2)}

You will receive buyer messages as JSON. Analyze them and respond with ONLY valid JSON.

Message types you can send:

1. Quote (response to RFQ):
   {{"type": "quote", "sku": "...", "name": "...", "quantity": N, "unit_price": N.NNN, "discount_pct": N, "total": N.NN, "lead_days": N, "payment_terms": "Net 30", "available": true}}

2. Counter (if buyer's counter-offer is too low):
   {{"type": "counter", "sku": "...", "min_unit_price": N.NNN, "reason": "..."}}

3. Accept counter-offer:
   {{"type": "order_accepted", "sku": "...", "quantity": N, "unit_price": N.NNN, "total": N.NN, "lead_days": N, "payment_terms": "Net 30", "final": true}}

4. Reject (out of stock or unreasonable):
   {{"type": "order_rejected", "sku": "...", "reason": "...", "final": true}}

Rules:
- Apply discounts automatically based on quantity thresholds in the catalog.
- You can accept counter-offers if the price is at most 5% below your discounted price.
- If stock is insufficient, reject with a clear reason.
- Lead time: 2 days for in-stock, 5 days if qty > 50% of stock.
- Always output ONLY valid JSON, no extra text.
- Add "final": true when the deal is concluded (accepted or rejected).
"""


def extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)
    return json.loads(text)


def handle_message(broker: BrokerClient, agent_id: str, session_id: str,
                   payload: dict, sender: str, conversation: list[dict],
                   system_prompt: str) -> dict | None:
    """Process one incoming message. Returns final result or None to continue."""
    msg_type = payload.get("type", "unknown")
    log(agent_id, f"<< {msg_type.upper()} from {sender}", YELLOW)
    print(f"  {YELLOW}<{RESET} {json.dumps(payload, indent=2)}\n")

    if payload.get("final"):
        log(agent_id, "Buyer sent final message.", GREEN)
        return payload

    llm_prompt = (
        f"Buyer sent: {json.dumps(payload)}\n"
        f"Check the catalog and respond. Output only JSON."
    )
    llm_response = ask_llm(system_prompt, conversation, llm_prompt)
    msg_out = extract_json(llm_response)
    conversation.append({"role": "user", "content": llm_prompt})
    conversation.append({"role": "assistant", "content": json.dumps(msg_out)})

    log(agent_id, f">> {msg_out['type'].upper()}", CYAN)
    print(f"  {GREEN}>{RESET} {json.dumps(msg_out, indent=2)}\n")
    broker.send(session_id, agent_id, msg_out, recipient_agent_id=sender)

    if msg_out.get("final"):
        return msg_out

    return None


def handle_session(broker: BrokerClient, agent_id: str, session_id: str,
                   system_prompt: str, crm: OdooConnector, buyer_org: str) -> None:
    """Handle a single negotiation session."""
    conversation: list[dict] = []
    final_result = None

    # Process queued messages
    queued = broker.poll(session_id, after=-1)
    for msg in queued:
        if msg["sender_agent_id"] == agent_id:
            continue
        result = handle_message(
            broker, agent_id, session_id, msg["payload"],
            msg["sender_agent_id"], conversation, system_prompt,
        )
        if result:
            final_result = result
            break

    # Listen via WebSocket
    if not final_result:
        ws = _open_ws(broker, agent_id)
        if ws is not None:
            try:
                for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("type") != "new_message" or msg.get("session_id") != session_id:
                        continue
                    m = broker.decrypt_payload(msg["message"], session_id=session_id)
                    if m["sender_agent_id"] == agent_id:
                        continue
                    result = handle_message(
                        broker, agent_id, session_id, m["payload"],
                        m["sender_agent_id"], conversation, system_prompt,
                    )
                    if result:
                        final_result = result
                        break
            except Exception as e:
                log(agent_id, f"WS error: {e}", YELLOW)
            finally:
                try:
                    ws.close()
                except Exception:
                    pass

    # Create Sale Order in Odoo if negotiation succeeded
    if final_result and final_result.get("type") in ("order_confirm", "order_accepted"):
        sku = final_result.get("sku", "")
        qty = final_result.get("quantity", 0)
        price = final_result.get("accepted_price") or final_result.get("unit_price", 0)

        log(agent_id, "Creating Sale Order in Odoo...", CYAN)
        try:
            partner_id = crm.get_or_create_partner(f"{buyer_org} (via ATN)", buyer_org)
            product = crm.get_product_by_sku(sku)
            if product:
                order_id = crm.create_sale_order(
                    partner_id=partner_id,
                    lines=[{"product_id": product.product_id, "qty": qty, "price": price}],
                )
                log(agent_id, f"Sale Order created: SO #{order_id}", GREEN)
            else:
                log(agent_id, f"Product {sku} not found in Odoo", YELLOW)
        except Exception as exc:
            log(agent_id, f"Failed to create SO: {exc}", RED)

    try:
        broker.close_session(session_id)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Enterprise Supplier Agent")
    parser.add_argument("--config", required=True, help="Path to agent .env file")
    args = parser.parse_args()

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

    # Odoo connection
    odoo_url = cfg("ODOO_URL", "http://localhost:8069")
    odoo_db = cfg("ODOO_DB", "odoo")
    odoo_user = cfg("ODOO_USER", "admin")
    odoo_password = cfg("ODOO_PASSWORD", "admin")

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  Enterprise Supplier Agent — {agent_id}{RESET}")
    print(f"  CRM: {odoo_url}")
    print(f"  Broker: {broker_url}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    # Connect to Odoo and load catalog
    crm = OdooConnector(odoo_url, odoo_db, odoo_user, odoo_password)
    if not crm.ping():
        log(agent_id, "Odoo not reachable!", RED)
        return

    log(agent_id, "Connected to Odoo", GREEN)
    catalog = crm.get_catalog()
    log(agent_id, f"Loaded {len(catalog)} products from catalog", GREEN)

    system_prompt = build_system_prompt(catalog)

    # Connect to ATN broker
    verify_tls = not broker_url.startswith("https://localhost")
    broker = BrokerClient(broker_url, verify_tls=verify_tls)

    try:
        log(agent_id, "Authenticating with ATN broker...", CYAN)
        broker.register(agent_id, org_id, agent_id, caps)
        broker.login(agent_id, org_id, cert_path, key_path)
        log(agent_id, "Authenticated.", GREEN)

        # Listen loop
        while True:
            pending = broker.list_sessions(status_filter="pending")
            my_pending = [s for s in pending if s["target_agent_id"] == agent_id]
            if my_pending:
                session = my_pending[0]
                session_id = session["session_id"]
                initiator = session["initiator_agent_id"]
                buyer_org = session.get("initiator_org_id", "unknown")
                log(agent_id, f"Session from {initiator} ({buyer_org})", GREEN)
                broker.accept_session(session_id)

                # Refresh catalog for each session (prices may have changed)
                catalog = crm.get_catalog()
                system_prompt = build_system_prompt(catalog)

                handle_session(broker, agent_id, session_id, system_prompt, crm, buyer_org)
                log(agent_id, "Ready for next session...\n", CYAN)
                continue

            ws = _open_ws(broker, agent_id)
            if ws is not None:
                try:
                    log(agent_id, "Listening for sessions...", GRAY)
                    for raw in ws:
                        msg = json.loads(raw)
                        if msg.get("type") == "session_pending":
                            session_id = msg["session_id"]
                            initiator = msg.get("initiator_agent_id", "unknown")
                            buyer_org = msg.get("initiator_org_id", "unknown")
                            broker.accept_session(session_id)
                            log(agent_id, f"Session from {initiator}: {session_id}", GREEN)
                            ws.close()

                            catalog = crm.get_catalog()
                            system_prompt = build_system_prompt(catalog)

                            handle_session(broker, agent_id, session_id, system_prompt, crm, buyer_org)
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
                time.sleep(2)

    except KeyboardInterrupt:
        print(f"\n  {GRAY}Supplier agent stopped.{RESET}\n")
    finally:
        broker.close()


if __name__ == "__main__":
    main()
