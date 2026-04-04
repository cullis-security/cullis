"""
Generate x509 certificates for ATN organizations and agents.

Two modes:
  --org    Generate an organization CA (self-signed)
  --agent  Generate an agent certificate (signed by the org CA)

The private keys NEVER leave the customer's infrastructure.
Only the CA public cert (ca.pem) is shared with ATN.

Usage:
  # Step 1: Generate org CA
  python demo/generate_org_certs.py --org manufacturer

  # Step 2: Generate agent cert (after registering the agent in the dashboard)
  python demo/generate_org_certs.py --agent manufacturer::sales-agent --secret org-secret-demo

Output:
  certs/<org>/ca.pem                  Org CA public cert (paste in dashboard)
  certs/<org>/ca-key.pem              Org CA private key (KEEP SECRET)
  certs/<org>/<org>__<agent>.pem      Agent certificate
  certs/<org>/<org>__<agent>-key.pem  Agent private key (KEEP SECRET)
  certs/<org>/<org>__<agent>.env      Agent config file
"""
import argparse
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"


def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def skip(msg): print(f"  {YELLOW}→{RESET}  {msg} (already exists — skip)")


def _gen_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _save_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))


def _save_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ─────────────────────────────────────────────────────────────────────────────
# Mode 1: Generate org CA
# ─────────────────────────────────────────────────────────────────────────────

def cmd_org(org_id: str, out_dir: Path) -> None:
    org_dir = out_dir / org_id
    org_dir.mkdir(parents=True, exist_ok=True)

    key_path  = org_dir / "ca-key.pem"
    cert_path = org_dir / "ca.pem"

    if key_path.exists() and cert_path.exists():
        skip(f"{org_id} CA already exists")
        print(f"\n  CA cert: {cert_path}")
        return

    now = datetime.now(timezone.utc)
    ca_key = _gen_key(4096)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    _save_key(key_path, ca_key)
    _save_cert(cert_path, ca_cert)
    ok(f"{org_id} CA generated")

    print(f"\n  {BOLD}Files:{RESET}")
    print(f"    {cert_path}      — paste this in the ATN dashboard")
    print(f"    {key_path}  — KEEP SECRET\n")
    print(f"  {BOLD}Next:{RESET}")
    print(f"    1. Go to dashboard → Organizations → + Onboard Org")
    print(f"    2. Paste the contents of {CYAN}{cert_path}{RESET}")
    print(f"    3. Click Register & Approve")


# ─────────────────────────────────────────────────────────────────────────────
# Mode 2: Generate agent cert
# ─────────────────────────────────────────────────────────────────────────────

def cmd_agent(agent_id: str, capabilities: list[str], secret: str,
              broker_url: str, trust_domain: str, out_dir: Path) -> None:
    if "::" not in agent_id:
        print(f"  Agent ID must be in format org_id::agent_name (got: {agent_id})")
        sys.exit(1)

    org_id, agent_name = agent_id.split("::", 1)
    org_dir = out_dir / org_id

    # Load org CA
    ca_key_path  = org_dir / "ca-key.pem"
    ca_cert_path = org_dir / "ca.pem"
    if not ca_key_path.exists() or not ca_cert_path.exists():
        print(f"  Org CA not found in {org_dir}/")
        print(f"  Run first: python demo/generate_org_certs.py --org {org_id}")
        sys.exit(1)

    ca_key  = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

    # Generate agent cert
    safe_name = agent_id.replace("::", "__")
    cert_path = org_dir / f"{safe_name}.pem"
    key_path  = org_dir / f"{safe_name}-key.pem"
    env_path  = org_dir / f"{safe_name}.env"

    if cert_path.exists() and key_path.exists():
        skip(f"{agent_id} cert already exists")
    else:
        now = datetime.now(timezone.utc)
        spiffe_id = f"spiffe://{trust_domain}/{org_id}/{agent_name}"

        agent_key = _gen_key(2048)
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

        _save_key(key_path, agent_key)
        _save_cert(cert_path, agent_cert)
        ok(f"{agent_id} cert generated (SPIFFE: {spiffe_id})")

    # Save env config
    env_path.write_text(
        f"# Generated by generate_org_certs.py — {datetime.now(timezone.utc).isoformat()}\n"
        f"BROKER_URL={broker_url}\n"
        f"AGENT_ID={agent_id}\n"
        f"ORG_ID={org_id}\n"
        f"DISPLAY_NAME={agent_id}\n"
        f"AGENT_CERT_PATH={cert_path}\n"
        f"AGENT_KEY_PATH={key_path}\n"
        f"ORG_SECRET={secret}\n"
        f"CAPABILITIES={','.join(capabilities)}\n"
        f"POLL_INTERVAL=2\n"
        f"MAX_TURNS=20\n"
        f"\n# LLM backend\n"
        f"LLM_MODEL=claude-sonnet-4-6\n"
        f"ANTHROPIC_API_KEY=\n"
    )
    ok(f"Config: {env_path}")

    print(f"\n  {BOLD}Files:{RESET}")
    print(f"    {cert_path}")
    print(f"    {key_path}")
    print(f"    {env_path}")
    print(f"\n  {BOLD}Next:{RESET}")
    print(f"    1. Dashboard → Agents → Register Agent (if not done yet)")
    print(f"    2. Approve the binding")
    print(f"    3. Start the agent with: --config {env_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate x509 certificates for ATN organizations and agents"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--org",   help="Generate org CA (e.g. --org manufacturer)")
    group.add_argument("--agent", help="Generate agent cert (e.g. --agent manufacturer::sales-agent)")

    parser.add_argument("--capabilities", default="order.read,order.write", help="Agent capabilities")
    parser.add_argument("--secret",       default="", help="Org secret (saved in .env)")
    parser.add_argument("--broker",       default="https://localhost:8443", help="Broker URL")
    parser.add_argument("--trust-domain", default="atn.local")
    parser.add_argument("--out",          default="certs", help="Output directory")
    args = parser.parse_args()

    if args.org:
        cmd_org(args.org, Path(args.out))
    else:
        caps = [c.strip() for c in args.capabilities.split(",") if c.strip()]
        cmd_agent(args.agent, caps, args.secret, args.broker, args.trust_domain, Path(args.out))


if __name__ == "__main__":
    main()
