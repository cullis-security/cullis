"""
AcmeBuyer Corp — Agente di procurement

Acquista componenti industriali da fornitori certificati nel network.
Legge identità e certificati dal file .env passato con --config.

Usage:
  python agents/buyer.py --config certs/acme/procurement/agent.env
"""
import argparse
import os
import sys
from pathlib import Path

# Aggiungi la root del progetto al path per importare app.auth.message_signer
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.sdk import (
    BrokerClient, load_env_file, cfg, log,
    run_initiator, GREEN, CYAN,
)

# ─────────────────────────────────────────────
# System prompt — identità e istruzioni fisse
# di AcmeBuyer Corp. Non modificare via .env.
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are the procurement agent for AcmeBuyer Corp, a B2B industrial buyer.
Your task is to place a purchase order with the supplier's sales agent,
negotiate price and delivery terms, and confirm the order.

Rules:
- Always communicate in English.
- Be precise and professional, as in a B2B context.
- Before confirming the order, make sure you have ALL of the following:
    1. Confirmed availability for the requested quantity
    2. Unit price with any applicable discount
    3. Total price calculated
    4. Exact delivery lead time (date or business days)
    5. Payment terms
- Do not say "ORDER CONFIRMED" until all points above are satisfied.
  Ask clarifying questions until you have everything.
- Once all information is received, close with "ORDER CONFIRMED" followed
  by a summary (product, quantity, unit price, total, delivery date, payment terms).
- When concluding, end with the word FINE on the final line.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="AcmeBuyer Corp — Agente procurement")
    parser.add_argument("--config", required=True,
                        help="Path al file .env generato da join_agent.py")
    args = parser.parse_args()

    # Carica variabili d'ambiente dal file .env dell'agente
    root_env = Path(__file__).parent.parent / ".env"
    if root_env.exists():
        load_env_file(str(root_env))
    load_env_file(args.config, override=True)

    agent_id      = cfg("AGENT_ID")
    org_id        = cfg("ORG_ID")
    cert_path     = cfg("AGENT_CERT_PATH")
    key_path      = cfg("AGENT_KEY_PATH")
    broker_url    = cfg("BROKER_URL", "http://localhost:8000")
    poll_interval = int(cfg("POLL_INTERVAL", "2"))
    max_turns     = int(cfg("MAX_TURNS", "20"))
    display_name  = cfg("DISPLAY_NAME", agent_id)
    capabilities  = cfg("CAPABILITIES", "order.read,order.write").split(",")

    broker = BrokerClient(broker_url)
    try:
        log(agent_id, f"Registrazione presso il broker ({broker_url})...", CYAN)
        created = broker.register(agent_id, org_id, display_name, capabilities)
        if created:
            log(agent_id, "Registrazione completata.", GREEN)
        else:
            log(agent_id, "Agente già presente nel registry.", GREEN)

        log(agent_id, "Login in corso...", CYAN)
        broker.login(agent_id, org_id, cert_path, key_path)
        log(agent_id, "Token JWT ottenuto.", GREEN)
        print(flush=True)

        run_initiator(broker, agent_id, max_turns, poll_interval, SYSTEM_PROMPT)

    except KeyboardInterrupt:
        print()
        log(agent_id, "Interrotto dall'utente.", "")
    finally:
        broker.close()


if __name__ == "__main__":
    main()
