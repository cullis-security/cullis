"""
Agent Trust Network — Join Agent

Registra un nuovo agente nel network per un'org già approvata.

Operazioni:
  1. Legge la CA dell'org da certs/<org>/ca.pem + ca-key.pem
  2. Genera keypair RSA 2048 per l'agente
  3. Firma il certificato con la CA locale (con SAN URI SPIFFE)
  4. Registra l'agente nel broker
  5. Salva cert + key + config in certs/<org>/<name>/

Usage:
  python join_agent.py --org acme --name buyer-agent --capabilities order.read,order.write
  python join_agent.py --org acme --name buyer-agent \\
                       --capabilities order.read,order.write \\
                       --broker http://localhost:8000
"""
import argparse
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
RED    = "\033[31m"
GRAY   = "\033[90m"


def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def info(msg): print(f"  {CYAN}→{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET}  {msg}")
def err(msg):  print(f"  {RED}✗{RESET}  {msg}", file=sys.stderr)


# ── PKI helpers ───────────────────────────────────────────────────────────────

def _load_ca(org_id: str, certs_dir: Path) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Carica la CA locale dell'org."""
    ca_cert_path = certs_dir / org_id / "ca.pem"
    ca_key_path  = certs_dir / org_id / "ca-key.pem"

    if not ca_cert_path.exists():
        err(f"CA non trovata: {ca_cert_path}")
        err(f"Esegui prima: python join.py  (per registrare l'org)")
        sys.exit(1)
    if not ca_key_path.exists():
        err(f"CA key non trovata: {ca_key_path}")
        sys.exit(1)

    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    return ca_cert, ca_key


def _gen_agent_cert(
    org_id: str,
    agent_name: str,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    trust_domain: str,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Genera keypair + certificato per l'agente, firmato dalla CA org."""
    agent_id  = f"{org_id}::{agent_name}"
    spiffe_id = f"spiffe://{trust_domain}/{org_id}/{agent_name}"
    now = datetime.now(timezone.utc)

    agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
    return agent_cert, agent_key


def _save_pki(
    org_id: str,
    agent_name: str,
    agent_cert: x509.Certificate,
    agent_key: rsa.RSAPrivateKey,
    certs_dir: Path,
) -> tuple[Path, Path]:
    """Salva cert + key in certs/<org>/<name>/. Restituisce (cert_path, key_path)."""
    agent_dir = certs_dir / org_id / agent_name
    agent_dir.mkdir(parents=True, exist_ok=True)

    cert_path = agent_dir / "agent.pem"
    key_path  = agent_dir / "agent-key.pem"

    cert_path.write_text(
        agent_cert.public_bytes(serialization.Encoding.PEM).decode()
    )
    key_path.write_text(
        agent_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
    )
    ok(f"Certificato: {cert_path}")
    return cert_path, key_path


def _save_env(
    org_id: str,
    agent_name: str,
    capabilities: list[str],
    cert_path: Path,
    key_path: Path,
    org_secret: str,
    broker_url: str,
    certs_dir: Path,
) -> Path:
    """Salva il file .env per l'agente."""
    agent_id   = f"{org_id}::{agent_name}"
    caps_str   = ",".join(capabilities)
    env_path   = certs_dir / org_id / agent_name / "agent.env"

    env_path.write_text(
        f"# Generato da join_agent.py — {datetime.now(timezone.utc).isoformat()}\n"
        f"BROKER_URL={broker_url}\n"
        f"AGENT_ID={agent_id}\n"
        f"ORG_ID={org_id}\n"
        f"ORG_DISPLAY_NAME={org_id}\n"
        f"DISPLAY_NAME={agent_id}\n"
        f"AGENT_CERT_PATH={cert_path}\n"
        f"AGENT_KEY_PATH={key_path}\n"
        f"ORG_SECRET={org_secret}\n"
        f"CAPABILITIES={caps_str}\n"
        f"POLL_INTERVAL=2\n"
        f"MAX_TURNS=20\n"
        f"\n# Target agent — lascia vuoto per discovery automatica\n"
        f"TARGET_AGENT_ID=\n"
        f"TARGET_ORG_ID=\n"
        f"\n# LLM backend — vuoto = Anthropic Claude (default)\n"
        f"LLM_BASE_URL=\n"
        f"LLM_MODEL=claude-sonnet-4-6\n"
        f"LLM_API_KEY=\n"
        f"ANTHROPIC_API_KEY=\n"
    )
    ok(f"Config env:   {env_path}")
    return env_path


# ── Broker calls ─────────────────────────────────────────────────────────────

def register_agent(
    broker_url: str,
    org_id: str,
    agent_name: str,
    capabilities: list[str],
    display_name: str,
) -> dict:
    """POST /registry/agents — registra l'agente nel broker."""
    agent_id = f"{org_id}::{agent_name}"
    resp = httpx.post(
        f"{broker_url}/registry/agents",
        json={
            "agent_id":     agent_id,
            "org_id":       org_id,
            "display_name": display_name or agent_id,
            "capabilities": capabilities,
            "metadata":     {},
        },
        timeout=10,
    )
    if resp.status_code == 409:
        warn(f"Agente già registrato: {agent_id}")
        return resp.json() if resp.content else {}
    resp.raise_for_status()
    return resp.json()


def get_org_secret(org_id: str, certs_dir: Path) -> str:
    """Cerca il secret dell'org nei file .env esistenti nella cartella dell'org."""
    org_dir = certs_dir / org_id
    for env_file in org_dir.glob("**/*.env"):
        for line in env_file.read_text().splitlines():
            if line.startswith("ORG_SECRET="):
                secret = line.split("=", 1)[1].strip()
                if secret:
                    return secret
    return ""


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Agent Trust Network — Registra un agente nel network"
    )
    parser.add_argument("--org",          required=True,  help="Org ID (es. acme)")
    parser.add_argument("--name",         required=True,  help="Nome agente (es. buyer-agent)")
    parser.add_argument("--capabilities", default="",     help="CSV capabilities (es. order.read,order.write)")
    parser.add_argument("--display-name", default="",     help="Nome visualizzato nel registry")
    parser.add_argument("--broker",       default="http://localhost:8000")
    parser.add_argument("--trust-domain", default="atn.local")
    parser.add_argument("--certs-dir",    default="certs")
    args = parser.parse_args()

    broker_url   = args.broker.rstrip("/")
    certs_dir    = Path(args.certs_dir)
    org_id       = args.org
    agent_name   = args.name
    trust_domain = args.trust_domain
    capabilities = [c.strip() for c in args.capabilities.split(",") if c.strip()]
    display_name = args.display_name or f"{org_id}::{agent_name}"

    print(f"\n{BOLD}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   Agent Trust Network — Join Agent       ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════╝{RESET}\n")

    print(f"  Org:          {CYAN}{org_id}{RESET}")
    print(f"  Agente:       {CYAN}{org_id}::{agent_name}{RESET}")
    print(f"  Capabilities: {CYAN}{', '.join(capabilities) if capabilities else '(nessuna specificata)'}{RESET}")
    print(f"  SPIFFE ID:    {GRAY}spiffe://{trust_domain}/{org_id}/{agent_name}{RESET}\n")

    # ── 1. Verifica broker ────────────────────────────────────────────────────
    try:
        httpx.get(f"{broker_url}/health", timeout=5).raise_for_status()
    except Exception as e:
        err(f"Broker non raggiungibile: {e}")
        sys.exit(1)

    # ── 2. Carica CA org ──────────────────────────────────────────────────────
    print(f"{BOLD}[1/4] Caricamento CA org{RESET}")
    ca_cert, ca_key = _load_ca(org_id, certs_dir)
    ok(f"CA caricata: certs/{org_id}/ca.pem")

    # ── 3. Genera certificato agente ──────────────────────────────────────────
    print(f"\n{BOLD}[2/4] Generazione certificato{RESET}")
    agent_cert, agent_key = _gen_agent_cert(org_id, agent_name, ca_cert, ca_key, trust_domain)
    cert_path, key_path = _save_pki(org_id, agent_name, agent_cert, agent_key, certs_dir)

    # ── 4. Registra nel broker ────────────────────────────────────────────────
    print(f"\n{BOLD}[3/4] Registrazione nel broker{RESET}")
    try:
        register_agent(broker_url, org_id, agent_name, capabilities, display_name)
        agent_id = f"{org_id}::{agent_name}"

        # Check binding status
        org_secret = get_org_secret(org_id, certs_dir)
        if org_secret:
            binding_resp = httpx.get(
                f"{broker_url}/registry/bindings",
                headers={"x-org-id": org_id, "x-org-secret": org_secret},
                timeout=10,
            )
            if binding_resp.status_code == 200:
                bindings = binding_resp.json()
                agent_binding = next(
                    (b for b in bindings if b["agent_id"] == agent_id), None
                )
                if agent_binding:
                    bstatus = agent_binding["status"]
                    if bstatus == "approved":
                        ok(f"Binding approved")
                    else:
                        warn(f"Binding status '{bstatus}' — requires admin approval")
    except httpx.HTTPStatusError as e:
        err(f"Errore registrazione (HTTP {e.response.status_code}): {e.response.text}")
        sys.exit(1)

    # ── 5. Salva config env ───────────────────────────────────────────────────
    print(f"\n{BOLD}[4/4] Salvataggio config{RESET}")
    org_secret = get_org_secret(org_id, certs_dir)
    env_path = _save_env(
        org_id, agent_name, capabilities,
        cert_path, key_path, org_secret, broker_url, certs_dir,
    )

    # ── Done ──────────────────────────────────────────────────────────────────
    print(f"\n{GREEN}{BOLD}Agente registrato. Avvia con:{RESET}")
    print(f"  ./agent.sh --config {env_path}")
    print()


if __name__ == "__main__":
    main()
