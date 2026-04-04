"""
Agent Trust Network — Administrative Bootstrap

Simula l'onboarding effettuato da un admin prima che gli agenti possano operare.

Operazioni (tutte idempotenti):
  0. Genera certificati x509 (broker CA + org CA + agent certs)
  1. Registra le organizzazioni (join request + approvazione admin)
  2. Registra gli agenti + crea binding + session policy
  3. Verifica stato binding

Usage:
  python bootstrap.py

Il broker deve essere già avviato (./run.sh).
"""
import os
import sys
from pathlib import Path

import httpx

# ─────────────────────────────────────────────
# Configurazione
# ─────────────────────────────────────────────

def load_env_file(path: str) -> None:
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


root_env = Path(__file__).parent / ".env"
if root_env.exists():
    load_env_file(str(root_env))

BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:8000").rstrip("/")

# Org
MANUFACTURER_ORG_ID      = "manufacturer"
MANUFACTURER_DISPLAY     = "ChipFactory"
MANUFACTURER_ORG_SECRET  = "org-secret-manufacturer-demo"

BUYER_ORG_ID     = "buyer"
BUYER_DISPLAY    = "ElectroStore"
BUYER_ORG_SECRET = "org-secret-buyer-demo"

# Agents
MANUFACTURER_AGENT_ID   = "manufacturer::sales-agent"
BUYER_AGENT_ID   = "buyer::procurement-agent"

CAPABILITIES = ["order.read", "order.write"]

# PDP webhook URLs (mock server for demo — each org runs its own)
# In Docker the mock PDPs are reachable at their service names
_pdp_base = os.environ.get("MOCK_PDP_BASE_URL", "")
MANUFACTURER_WEBHOOK_URL = (
    _pdp_base + "/policy" if _pdp_base
    else os.environ.get("MANUFACTURER_WEBHOOK_URL", "http://mock-pdp-manufacturer:9000/policy")
)
BUYER_WEBHOOK_URL = (
    _pdp_base + "/policy" if _pdp_base
    else os.environ.get("BUYER_WEBHOOK_URL", "http://mock-pdp-buyer:9001/policy")
)

# Org CA certificate paths
CERTS_DIR = Path(__file__).parent / "certs"
MANUFACTURER_ORG_CA_PEM = CERTS_DIR / MANUFACTURER_ORG_ID / "ca.pem"
BUYER_ORG_CA_PEM        = CERTS_DIR / BUYER_ORG_ID / "ca.pem"

# ─────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
GRAY   = "\033[90m"


def ok(msg: str)   -> None: print(f"  {GREEN}✓{RESET} {msg}")
def skip(msg: str) -> None: print(f"  {YELLOW}→{RESET} {GRAY}{msg} (already present — skip){RESET}")
def err(msg: str)  -> None: print(f"  {RED}✗{RESET} {msg}", file=sys.stderr)


# ─────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────

http = httpx.Client(timeout=10)


def post(path: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    resp = http.post(f"{BROKER_URL}{path}", json=body, headers=headers or {})
    return resp.status_code, resp.json() if resp.content else {}


def get(path: str, params: dict | None = None, headers: dict | None = None) -> tuple[int, dict | list]:
    resp = http.get(f"{BROKER_URL}{path}", params=params or {}, headers=headers or {})
    return resp.status_code, resp.json() if resp.content else {}


def org_headers(org_id: str, org_secret: str) -> dict:
    return {"x-org-id": org_id, "x-org-secret": org_secret}


# ─────────────────────────────────────────────
# Operazioni
# ─────────────────────────────────────────────

created: list[str] = []
skipped: list[str] = []


ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change-me-in-production")


def admin_headers() -> dict:
    return {"x-admin-secret": ADMIN_SECRET}


def join_and_approve(org_id: str, display_name: str, secret: str,
                     ca_pem_path: Path, contact: str = "",
                     webhook_url: str | None = None) -> None:
    """Invia join request via /onboarding/join e approva subito come admin."""
    if not ca_pem_path.exists():
        err(f"CA cert not found: {ca_pem_path} — run 'python generate_certs.py' first")
        sys.exit(1)
    ca_pem = ca_pem_path.read_text()

    # Join request
    payload: dict = {
        "org_id": org_id, "display_name": display_name,
        "secret": secret, "ca_certificate": ca_pem, "contact_email": contact,
    }
    if webhook_url:
        payload["webhook_url"] = webhook_url
    code, body = post("/onboarding/join", payload)
    if code == 202:
        ok(f"Join request sent: {org_id} ({display_name})")
        created.append(f"join:{org_id}")
    elif code == 409:
        skip(f"Org {org_id} already registered")
        skipped.append(f"org:{org_id}")
        return
    else:
        err(f"Join {org_id} — HTTP {code}: {body}")
        sys.exit(1)

    # Admin approval
    code, body = post(f"/admin/orgs/{org_id}/approve", {}, headers=admin_headers())
    if code == 200:
        ok(f"Org approved: {org_id}")
        created.append(f"approved:{org_id}")
    else:
        err(f"Approval {org_id} — HTTP {code}: {body}")
        sys.exit(1)


def register_agent(agent_id: str, org_id: str, display_name: str,
                   capabilities: list[str]) -> dict:
    payload: dict = {
        "agent_id": agent_id, "org_id": org_id, "display_name": display_name,
        "capabilities": capabilities,
    }
    code, body = post("/registry/agents", payload)
    if code == 201:
        ok(f"Agente registrato: {agent_id}")
        created.append(f"agent:{agent_id}")
    elif code == 409:
        skip(f"Agent {agent_id}")
        skipped.append(f"agent:{agent_id}")
    else:
        err(f"Agent {agent_id} — HTTP {code}: {body}")
        sys.exit(1)
    return body if isinstance(body, dict) else {}


def create_and_approve_binding(agent_id: str, org_id: str, org_secret: str,
                                scope: list[str]) -> None:
    hdrs = org_headers(org_id, org_secret)

    code, body = post("/registry/bindings",
                      {"org_id": org_id, "agent_id": agent_id, "scope": scope},
                      headers=hdrs)

    if code == 201:
        binding_id = body["id"]
        code2, _ = post(f"/registry/bindings/{binding_id}/approve", {}, headers=hdrs)
        if code2 == 200:
            ok(f"Binding created and approved: {agent_id} → {org_id} scope={scope}")
            created.append(f"binding:{agent_id}")
        else:
            err(f"Binding approval failed — HTTP {code2}")
            sys.exit(1)
    elif code == 409:
        # Binding exists — check if already approved, otherwise approve it
        _, bindings = get("/registry/bindings", params={"org_id": org_id}, headers=hdrs)
        if isinstance(bindings, list):
            match = next((b for b in bindings if b["agent_id"] == agent_id), None)
            if match and match["status"] == "approved":
                skip(f"Binding {agent_id} (already approved)")
                skipped.append(f"binding:{agent_id}")
            elif match and match["status"] == "pending":
                post(f"/registry/bindings/{match['id']}/approve", {}, headers=hdrs)
                ok(f"Binding approved (was pending): {agent_id}")
                created.append(f"binding:{agent_id}:approved")
            else:
                skip(f"Binding {agent_id} (status: {match['status'] if match else 'unknown'})")
                skipped.append(f"binding:{agent_id}")
        else:
            skip(f"Binding {agent_id} (already exists)")
            skipped.append(f"binding:{agent_id}")
    else:
        err(f"Binding {agent_id} — HTTP {code}: {body}")
        sys.exit(1)


def create_session_policy(org_id: str, org_secret: str,
                           target_org_id: str, capabilities: list[str]) -> None:
    policy_id = f"{org_id}::session-v1"
    hdrs = org_headers(org_id, org_secret)

    code, body = post("/policy/rules", {
        "policy_id": policy_id,
        "org_id": org_id,
        "policy_type": "session",
        "rules": {
            "effect": "allow",
            "conditions": {
                "target_org_id": [target_org_id],
                "capabilities": capabilities,
            },
        },
    }, headers=hdrs)

    if code == 201:
        ok(f"Session policy created: {policy_id} ({org_id} → {target_org_id})")
        created.append(f"policy:{policy_id}")
    elif code == 409:
        skip(f"Policy {policy_id}")
        skipped.append(f"policy:{policy_id}")
    else:
        err(f"Policy {policy_id} — HTTP {code}: {body}")
        sys.exit(1)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}Agent Trust Network — Bootstrap{RESET}")
    print(f"Broker: {BROKER_URL}\n")

    # Verifica che il broker sia raggiungibile
    try:
        code, _ = get("/health")
        if code != 200:
            err(f"Broker non raggiungibile (HTTP {code})")
            sys.exit(1)
    except httpx.ConnectError:
        err(f"Broker non raggiungibile su {BROKER_URL} — avvia ./run.sh prima")
        sys.exit(1)

    # Step 0: genera certificati se mancanti
    print(f"{BOLD}[0/3] Certificati x509{RESET}")
    import subprocess
    subprocess.run([sys.executable, str(Path(__file__).parent / "generate_certs.py")],
                   check=True, capture_output=True)
    if not MANUFACTURER_ORG_CA_PEM.exists() or not BUYER_ORG_CA_PEM.exists():
        err("CA org mancante — esegui prima: python generate_demo_certs.py")
        sys.exit(1)
    skip("Certificati presenti")

    # Step 1: registra org con webhook PDP (join + approvazione admin)
    print(f"\n{BOLD}[1/4] Organizzazioni (join + approve + webhook PDP){RESET}")
    join_and_approve(MANUFACTURER_ORG_ID, MANUFACTURER_DISPLAY,
                     MANUFACTURER_ORG_SECRET, MANUFACTURER_ORG_CA_PEM,
                     contact="admin@manufacturer.demo",
                     webhook_url=MANUFACTURER_WEBHOOK_URL)
    join_and_approve(BUYER_ORG_ID, BUYER_DISPLAY,
                     BUYER_ORG_SECRET, BUYER_ORG_CA_PEM,
                     contact="admin@buyer.demo",
                     webhook_url=BUYER_WEBHOOK_URL)

    # Step 2: registra agenti
    print(f"\n{BOLD}[2/4] Agenti{RESET}")
    register_agent(MANUFACTURER_AGENT_ID, MANUFACTURER_ORG_ID,
                   "Sales Agent", CAPABILITIES)
    register_agent(BUYER_AGENT_ID, BUYER_ORG_ID,
                   "Procurement Agent", CAPABILITIES)

    # Step 3: binding + session policy
    print(f"\n{BOLD}[3/4] Binding + session policy{RESET}")
    create_and_approve_binding(MANUFACTURER_AGENT_ID, MANUFACTURER_ORG_ID,
                                MANUFACTURER_ORG_SECRET, CAPABILITIES)
    create_and_approve_binding(BUYER_AGENT_ID, BUYER_ORG_ID,
                                BUYER_ORG_SECRET, CAPABILITIES)
    create_session_policy(MANUFACTURER_ORG_ID, MANUFACTURER_ORG_SECRET,
                           BUYER_ORG_ID, CAPABILITIES)
    create_session_policy(BUYER_ORG_ID, BUYER_ORG_SECRET,
                           MANUFACTURER_ORG_ID, CAPABILITIES)

    # Verifica stato binding
    print(f"\n{BOLD}[4/4] Verifica binding{RESET}")
    for agent_id, org_id, secret in [
        (MANUFACTURER_AGENT_ID, MANUFACTURER_ORG_ID, MANUFACTURER_ORG_SECRET),
        (BUYER_AGENT_ID,        BUYER_ORG_ID,        BUYER_ORG_SECRET),
    ]:
        _, bindings = get("/registry/bindings",
                          params={"org_id": org_id},
                          headers=org_headers(org_id, secret))
        if isinstance(bindings, list):
            b = next((x for x in bindings if x["agent_id"] == agent_id), None)
            if b and b["status"] == "approved":
                ok(f"{agent_id}  →  binding {b['status']}  scope={b['scope']}")
            elif b:
                print(f"  {YELLOW}!{RESET} {agent_id}  →  binding {b['status']}")
            else:
                ok(f"{agent_id}  →  binding non trovato (agente già esistente?)")

    print(f"\n{'─'*40}")
    print(f"{BOLD}Riepilogo{RESET}")
    print(f"  Creati:   {len(created)}  {GREEN}{', '.join(created) or '—'}{RESET}")
    print(f"  Saltati:  {len(skipped)}  {GRAY}{', '.join(skipped) or '—'}{RESET}")
    print(f"\n{GREEN}{BOLD}Bootstrap completato.{RESET} Avvia gli agenti:\n")
    print(f"  python agents/manufacturer.py --config certs/manufacturer/manufacturer__sales-agent.env")
    print(f"  python agents/buyer.py        --config certs/buyer/buyer__procurement-agent.env\n")

    http.close()


if __name__ == "__main__":
    main()
