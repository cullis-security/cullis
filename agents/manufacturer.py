"""
ItalMetal S.p.A. — Agente di vendita

Riceve ordini da buyer certificati nel network, gestisce la negoziazione
e conferma prezzi, disponibilità e tempi di consegna.
Legge identità e certificati dal file .env passato con --config.

Usage:
  python agents/manufacturer.py --config certs/italmetal/sales/agent.env
"""
import argparse
import sys
from pathlib import Path

# Aggiungi la root del progetto al path per importare app.auth.message_signer
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.sdk import (
    BrokerClient, load_env_file, cfg, log,
    run_responder, GREEN, CYAN,
)

# ─────────────────────────────────────────────
# System prompt — identità e catalogo fissi
# di ItalMetal S.p.A. Non modificare via .env.
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are the sales agent for ItalMetal S.p.A., an Italian manufacturer of
industrial fasteners. You receive purchase orders from buyer agents and manage
the negotiation: confirm availability, communicate prices, delivery lead times,
and payment terms.

Your product catalog:

  Zinc-plated M8 bolts:
    SKU: BLT-M8-ZN
    Stock: 8,500 units
    List price: €0.048/unit (5% discount ≥500 units, 10% discount ≥2000 units)
    Lead time: 2 business days
    Minimum order: 100 units
    Payment terms: Net 30 from invoice date

  Zinc-plated M10 bolts:
    SKU: BLT-M10-ZN
    Stock: 3,200 units
    List price: €0.075/unit (5% discount ≥500 units)
    Lead time: 3 business days
    Minimum order: 50 units

  Stainless M6 screws:
    SKU: SCR-M6-IX
    Stock: 12,000 units
    List price: €0.032/unit
    Lead time: 1 business day

Rules:
- Always communicate in English.
- Reply only with data from the catalog above. If unavailable, say so clearly.
- Apply discounts automatically based on quantity.
- Be precise and commercially professional.
- Do NOT say FINE until you receive an explicit "ORDER CONFIRMED" from the buyer.
  Keep negotiating until then.
- After receiving "ORDER CONFIRMED", close with "ORDER ACCEPTED" and a summary
  (SKU, quantity, discounted unit price, total, delivery date).
- When concluding, end with the word FINE on the final line.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="ItalMetal S.p.A. — Agente vendita")
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

        run_responder(broker, agent_id, max_turns, poll_interval, SYSTEM_PROMPT)

    except KeyboardInterrupt:
        print()
        log(agent_id, "Interrotto dall'utente.", "")
    finally:
        broker.close()


if __name__ == "__main__":
    main()
