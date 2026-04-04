"""
Generate demo org CAs and agent certs for the Docker/local demo environment.

Creates (idempotent — skips files that already exist):
  certs/manufacturer/ca.pem + ca-key.pem
  certs/manufacturer/manufacturer__sales-agent.pem + -key.pem
  certs/manufacturer/manufacturer__sales-agent.env
  certs/buyer/ca.pem + ca-key.pem
  certs/buyer/buyer__procurement-agent.pem + -key.pem
  certs/buyer/buyer__procurement-agent.env

Usage:
  python generate_demo_certs.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from generate_certs import gen_broker_ca, gen_org_ca, gen_agent_cert, CERTS_DIR

TRUST_DOMAIN = "atn.local"
BROKER_URL   = "http://localhost:8000"

DEMO_ORGS = [
    {
        "org_id": "manufacturer",
        "agents": ["manufacturer::sales-agent"],
    },
    {
        "org_id": "buyer",
        "agents": ["buyer::procurement-agent"],
    },
]


def _write_env(org_id: str, agent_id: str) -> None:
    safe = agent_id.replace("::", "__")
    env_path = CERTS_DIR / org_id / f"{safe}.env"
    if env_path.exists():
        print(f"  \033[33m→\033[0m  {env_path.name} (already exists — skip)")
        return
    env_path.write_text(
        f"AGENT_ID={agent_id}\n"
        f"ORG_ID={org_id}\n"
        f"BROKER_URL={BROKER_URL}\n"
        f"AGENT_CERT_PATH=certs/{org_id}/{safe}.pem\n"
        f"AGENT_KEY_PATH=certs/{org_id}/{safe}-key.pem\n"
    )
    print(f"  \033[32m✓\033[0m  {env_path.name} generated")


def main() -> None:
    print("\n\033[1mAgent Trust Network — Demo Certificate Generation\033[0m\n")
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    print("\033[1m[0] Broker CA\033[0m")
    broker_key, broker_cert = gen_broker_ca()

    for org in DEMO_ORGS:
        org_id = org["org_id"]
        print(f"\n\033[1m[org] {org_id}\033[0m")
        org_key, org_cert = gen_org_ca(org_id, broker_key, broker_cert)
        for agent_id in org["agents"]:
            gen_agent_cert(agent_id, org_id, org_key, org_cert, trust_domain=TRUST_DOMAIN)
            _write_env(org_id, agent_id)

    print(f"\n\033[32m\033[1mDemo certs ready in {CERTS_DIR}\033[0m\n")


if __name__ == "__main__":
    main()
