"""
Agent Trust Network — Join Tool

A tool for external companies that want to join the network.

Operations:
  1. Generate x509 certificates for the organization and its agents
  2. Send the join request to the broker (org in "pending" state)
  3. Wait for TrustLink approval (automatic polling or manual)

Prerequisites:
  pip install httpx cryptography

Usage:
  python join.py --broker http://trustlink-broker:8000 \
                 --org-id acme-corp \
                 --display-name "ACME Corporation" \
                 --secret my-org-secret \
                 --contact admin@acme.com \
                 --agents "acme-corp::sales-agent,acme-corp::support-agent"
"""
import argparse
import ipaddress
import json
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[32m"
CYAN  = "\033[36m"
YELLOW= "\033[33m"
RED   = "\033[31m"
GRAY  = "\033[90m"


def ok(msg):   print(f"  {GREEN}✓{RESET} {msg}")
def info(msg): print(f"  {CYAN}→{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET} {msg}")
def err(msg):  print(f"  {RED}✗{RESET} {msg}", file=sys.stderr)


# ── PKI helpers ───────────────────────────────────────────────────────────────

def _gen_rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _key_to_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


def _cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def generate_org_pki(org_id: str, agent_ids: list[str],
                     output_dir: Path, trust_domain: str = "atn.local") -> dict:
    """
    Genera:
      - CA dell'organizzazione  (certs/<org_id>/ca.pem + ca-key.pem)
      - Un certificato per agente con SAN URI SPIFFE  (certs/<org_id>/<agent_id>.pem + key)

    Restituisce { "ca_pem": str, "agents": { agent_id: { cert, key } } }
    """
    org_dir = output_dir / org_id
    org_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)

    # ── CA ────────────────────────────────────────────────────────────────────
    ca_key = _gen_rsa_key(2048)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} CA"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} CA"),
        ]))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    (org_dir / "ca-key.pem").write_text(_key_to_pem(ca_key))
    (org_dir / "ca.pem").write_text(_cert_to_pem(ca_cert))
    ok(f"CA generated: {org_dir}/ca.pem")

    # ── Agent certs ───────────────────────────────────────────────────────────
    agents = {}
    for agent_id in agent_ids:
        # SPIFFE ID: spiffe://trust-domain/org/agent-name
        _, agent_name = agent_id.split("::", 1)
        spiffe_id = f"spiffe://{trust_domain}/{org_id}/{agent_name}"

        agent_key = _gen_rsa_key(2048)
        agent_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(spiffe_id),
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        safe_id = agent_id.replace("::", "__").replace("/", "_")
        key_path  = org_dir / f"{safe_id}-key.pem"
        cert_path = org_dir / f"{safe_id}.pem"
        key_path.write_text(_key_to_pem(agent_key))
        cert_path.write_text(_cert_to_pem(agent_cert))
        ok(f"Agent certificate: {cert_path}  (spiffe_id={spiffe_id})")

        agents[agent_id] = {
            "cert_path": str(cert_path),
            "key_path":  str(key_path),
            "cert_pem":  _cert_to_pem(agent_cert),
        }

    return {"ca_pem": _cert_to_pem(ca_cert), "agents": agents}


# ── Broker client ─────────────────────────────────────────────────────────────

def send_join_request(broker_url: str, org_id: str, display_name: str,
                      secret: str, ca_pem: str, contact_email: str) -> dict:
    resp = httpx.post(
        f"{broker_url}/onboarding/join",
        json={
            "org_id":        org_id,
            "display_name":  display_name,
            "secret":        secret,
            "ca_certificate": ca_pem,
            "contact_email": contact_email,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def create_and_approve_binding(broker_url: str, org_id: str, secret: str,
                               agent_id: str, capabilities: list[str]) -> None:
    hdrs = {"x-org-id": org_id, "x-org-secret": secret}
    resp = httpx.post(
        f"{broker_url}/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": capabilities},
        headers=hdrs, timeout=10,
    )
    if resp.status_code == 409:
        ok(f"Binding already exists: {agent_id}")
        return
    resp.raise_for_status()
    binding_id = resp.json()["id"]

    resp2 = httpx.post(
        f"{broker_url}/registry/bindings/{binding_id}/approve",
        json={}, headers=hdrs, timeout=10,
    )
    resp2.raise_for_status()
    ok(f"Binding approved: {agent_id}")



def poll_approval(broker_url: str, org_id: str,
                  poll_interval: int = 10, max_wait: int = 300) -> bool:
    """Poll until approval. Returns True if approved within max_wait seconds."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{broker_url}/registry/orgs/{org_id}", timeout=5)
            if resp.status_code == 200:
                status = resp.json().get("status")
                if status == "active":
                    return True
                if status == "rejected":
                    return False
        except Exception:
            pass
        time.sleep(poll_interval)
    return False


def save_agent_config(org_id: str, org_secret: str, broker_url: str,
                      agents: dict, output_dir: Path,
                      capabilities: list[str] | None = None) -> None:
    """Save a .env file for each agent, ready to use."""
    caps_str = ",".join(capabilities) if capabilities else "order.read,order.write"

    for agent_id, info in agents.items():
        safe_id  = agent_id.replace("::", "__").replace("/", "_")
        env_path = output_dir / org_id / f"{safe_id}.env"

        env_path.write_text(
            f"# Generated by join.py — {datetime.now(timezone.utc).isoformat()}\n"
            f"BROKER_URL={broker_url}\n"
            f"AGENT_ID={agent_id}\n"
            f"ORG_ID={org_id}\n"
            f"ORG_DISPLAY_NAME={org_id}\n"
            f"DISPLAY_NAME={agent_id}\n"
            f"AGENT_CERT_PATH={info['cert_path']}\n"
            f"AGENT_KEY_PATH={info['key_path']}\n"
            f"ORG_SECRET={org_secret}\n"
            f"CAPABILITIES={caps_str}\n"
            f"POLL_INTERVAL=2\n"
            f"MAX_TURNS=20\n"
            f"\n# Target agent — leave empty to use automatic capability discovery\n"
            f"TARGET_AGENT_ID=\n"
            f"TARGET_ORG_ID=\n"
            f"\n# LLM backend — leave empty to use Anthropic Claude (default)\n"
            f"LLM_BASE_URL=\n"
            f"LLM_MODEL=claude-sonnet-4-6\n"
            f"LLM_API_KEY=\n"
            f"ANTHROPIC_API_KEY=\n"
        )
        ok(f"Agent config: {env_path}")


# ── Interactive prompt helpers ────────────────────────────────────────────────

def _ask(label: str, default: str = "") -> str:
    prompt = f"  {CYAN}{label}{RESET}"
    if default:
        prompt += f" {GRAY}[{default}]{RESET}"
    prompt += ": "
    value = input(prompt).strip()
    return value if value else default


def _ask_secret(label: str) -> str:
    import getpass
    value = getpass.getpass(f"  {CYAN}{label}{RESET}: ").strip()
    if not value:
        err("The secret cannot be empty.")
        sys.exit(1)
    return value


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{BOLD}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   Agent Trust Network — Join Wizard      ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════╝{RESET}\n")

    broker_url = _ask("Broker URL", "http://localhost:8000").rstrip("/")

    # ── Three questions ───────────────────────────────────────────────────────
    org_id = _ask("Org ID")
    if not org_id:
        err("Org ID is required.")
        sys.exit(1)

    secret = _ask_secret("Org password")

    agents_input = _ask("Agent name(s)", "agent")
    agent_names  = [a.strip() for a in agents_input.split(",") if a.strip()]
    agent_ids    = [f"{org_id}::{name}" for name in agent_names]

    caps_input   = _ask("Capabilities (comma-separated)", "order.read,order.write")
    capabilities = [c.strip() for c in caps_input.split(",") if c.strip()]

    # Trust domain comes from broker settings — use default silently
    trust_domain = "atn.local"
    certs_dir    = Path("certs")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}Summary:{RESET}")
    print(f"  Org:          {org_id}")
    print(f"  Agents:       {', '.join(agent_ids)}")
    print(f"  Capabilities: {', '.join(capabilities)}")
    confirm = input(f"\n  {YELLOW}Confirm? [y/N]{RESET}: ").strip().lower()
    if confirm not in ("s", "si", "sì", "y", "yes"):
        print("Cancelled.")
        sys.exit(0)

    # ── 1. Verify broker ──────────────────────────────────────────────────────
    print(f"\n{BOLD}[1/4] Broker{RESET}")
    try:
        httpx.get(f"{broker_url}/health", timeout=5).raise_for_status()
        ok("Reachable")
    except Exception as e:
        err(f"Broker unreachable: {e}")
        sys.exit(1)

    # ── 2. Generate PKI ───────────────────────────────────────────────────────
    print(f"\n{BOLD}[2/4] Certificates{RESET}")
    pki = generate_org_pki(org_id, agent_ids, certs_dir, trust_domain=trust_domain)

    # ── 3. Send join request ──────────────────────────────────────────────────
    print(f"\n{BOLD}[3/4] Join request{RESET}")
    try:
        result = send_join_request(broker_url, org_id, org_id, secret, pki["ca_pem"], "")
        ok(f"Sent — status: {result['status']}")
        info(result["message"])
    except httpx.HTTPStatusError as e:
        err(f"Failed (HTTP {e.response.status_code}): {e.response.text}")
        sys.exit(1)

    # ── 4. Save agent configs ─────────────────────────────────────────────────
    print(f"\n{BOLD}[4/4] Config files{RESET}")
    save_agent_config(org_id, secret, broker_url, pki["agents"], certs_dir,
                      capabilities=capabilities)

    # ── Wait for approval ─────────────────────────────────────────────────────
    print(f"\n{BOLD}Waiting for approval...{RESET}")
    print(f"  {YELLOW}Run in another terminal:{RESET}")
    print(f"  {GRAY}curl -s -X POST {broker_url}/admin/orgs/{org_id}/approve \\")
    print(f"       -H 'x-admin-secret: <ADMIN_SECRET>'{RESET}\n")
    approved = poll_approval(broker_url, org_id, poll_interval=5, max_wait=300)

    if approved:
        ok(f"'{org_id}' approved!")

        # ── Bindings ──────────────────────────────────────────────────────────
        for agent_id in agent_ids:
            try:
                create_and_approve_binding(broker_url, org_id, secret, agent_id, capabilities)
            except Exception as e:
                warn(f"Binding {agent_id} failed: {e}")

        # ── Done ──────────────────────────────────────────────────────────────
        print(f"\n{GREEN}{BOLD}Ready. Start your agent:{RESET}")
        for agent_id in agent_ids:
            safe = agent_id.replace("::", "__").replace("/", "_")
            print(f"  ./agent.sh --config {certs_dir}/{org_id}/{safe}.env")

        # Show SPIFFE IDs as informational note
        print(f"\n{GRAY}SPIFFE identities assigned:{RESET}")
        for agent_id in agent_ids:
            _, agent_name = agent_id.split("::", 1)
            print(f"  {GRAY}spiffe://{trust_domain}/{org_id}/{agent_name}{RESET}")
        print()

    else:
        warn("Approval timeout.")
        print(f"  curl {broker_url}/registry/orgs/{org_id}")
        for agent_id in agent_ids:
            safe = agent_id.replace("::", "__").replace("/", "_")
            print(f"  ./agent.sh --config {certs_dir}/{org_id}/{safe}.env")


if __name__ == "__main__":
    main()
