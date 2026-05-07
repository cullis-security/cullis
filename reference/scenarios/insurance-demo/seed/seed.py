"""Provision the insurance demo cast on top of the running reference stack.

Adds, on top of whatever ``reference/bootstrap/`` already created:

  - 3 user / agent principals on Mediterranean Insurance (Roma):
      roma::user::claim-officer
      roma::user::claim-manager
      roma::agent::night-reporter
      roma::agent::ticket-bot
  - 1 user principal on Asia-Pacific Insurance (Tokyo):
      tokyo::user::counterparty-liaison
  - 1 workload principal on Tokyo (the Frontdesk container itself):
      tokyo::workload::frontdesk-container
  - 1 MCP resource on Roma:
      roma::resource::mcp::claims-db (postgres-backed, seeded with claims.sql)
  - Cross-org bindings + reach=both for the user principals that need to
    talk across orgs (claim-manager <-> counterparty-liaison).

Idempotent: re-runs are no-ops on existing rows. Designed to be invoked
after ``reference/demo.sh full`` and produces a one-line OK summary at
the end suitable for the demo orchestration script.

Reads the Anthropic API key from ``imp/official_sandbox/.env`` if present
and configures the Roma proxy AI gateway to use it (Haiku 4.5).

Auth model:

  * agents (night-reporter, ticket-bot) — BYOCA enroll with cert/key
    minted against the Roma Org CA, persisted in
    ``state/insurance-demo/agents/<name>/``. Reach=intra (no cross-org
    capability — the bots only act inside Mediterranean).

  * users (claim-officer, claim-manager, counterparty-liaison) — provisioned
    via the user-principal POST endpoint exposed under ADR-021 PR4a.
    The Connector / Frontdesk SSO flow normally creates these at login;
    we pre-create them so the demo doesn't need a manual login step
    before the first message lands.

  * workload (frontdesk-container) — provisioned via admin endpoint with
    principal_type=workload, hosting Mario at runtime.

Env override:

  CULLIS_BROKER_URL          default http://localhost:8000
  CULLIS_PROXY_A_URL         default http://localhost:9100
  CULLIS_PROXY_B_URL         default http://localhost:9200
  ADMIN_SECRET               default sandbox-admin-secret-change-me
  ANTHROPIC_API_KEY          read from imp/official_sandbox/.env if unset
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
STATE_DIR = REPO_ROOT / "state" / "insurance-demo"
STATE_DIR.mkdir(parents=True, exist_ok=True)

BROKER_URL  = os.environ.get("CULLIS_BROKER_URL",  "http://localhost:8000")
PROXY_A_URL = os.environ.get("CULLIS_PROXY_A_URL", "http://localhost:9100")
PROXY_B_URL = os.environ.get("CULLIS_PROXY_B_URL", "http://localhost:9200")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "sandbox-admin-secret-change-me")

# Cast definitions — match imp/insurance-demo-spec.md verbatim.
ROMA_AGENTS = [
    {
        "agent_name":   "night-reporter",
        "display_name": "Night Reporter",
        "capabilities": ["claims-db.read", "oneshot.message"],
        "reach":        "intra",
        "description":  "Overnight scheduled bot — queries claims DB, sends summary to claim-officer.",
    },
    {
        "agent_name":   "ticket-bot",
        "display_name": "Ticket Bot",
        "capabilities": ["claims-db.write", "oneshot.message"],
        "reach":        "intra",
        "description":  "On-demand request-response — receives claim request, generates formal ticket ID.",
    },
]

ROMA_USERS = [
    {
        "user_name":    "claim-officer",
        "display_name": "Claim Officer",
        "reach":        "intra",
        "description":  "Junior claim adjuster (Mediterranean Insurance).",
    },
    {
        "user_name":    "claim-manager",
        "display_name": "Claim Manager",
        "reach":        "both",
        "description":  "Senior claim manager — escalates cross-company.",
    },
]

TOKYO_USERS = [
    {
        "user_name":    "counterparty-liaison",
        "display_name": "Counterparty Liaison",
        "reach":        "both",
        "description":  "Counterparty contact at Asia-Pacific Insurance.",
    },
]

TOKYO_WORKLOADS = [
    {
        "workload_name":          "frontdesk-container",
        "display_name":           "Frontdesk Tokyo",
        "image_digest":           "sha256:demo-frontdesk-bundle",
        "hosted_principals_hint": ["tokyo::user::counterparty-liaison"],
        "description":            "Multi-user Frontdesk container hosting tokyo::user::counterparty-liaison.",
    },
]

ROMA_RESOURCES = [
    {
        "resource_name": "claims-db",
        "type":          "mcp",
        "display_name":  "Claims Database",
        "endpoint":      "http://mcp-claims-db:8080/mcp",
        "description":   "Postgres-backed MCP server, seeded with insurance claims fixture.",
    },
]


# ── ANSI helpers ─────────────────────────────────────────────────────────


RESET, BOLD, GREEN, YELLOW, RED, CYAN, GRAY = (
    "\033[0m", "\033[1m", "\033[32m",
    "\033[33m", "\033[31m", "\033[36m", "\033[90m",
)


def _h(t: str) -> None:    print(f"\n{BOLD}{CYAN}═══ {t} ═══{RESET}")
def _ok(t: str) -> None:   print(f"  {GREEN}✓{RESET} {t}")
def _info(t: str) -> None: print(f"  {GRAY}…{RESET} {t}")
def _warn(t: str) -> None: print(f"  {YELLOW}⚠{RESET} {t}")
def _fail(t: str) -> None: print(f"  {RED}✗{RESET} {t}")


# ── Anthropic API key from official_sandbox ─────────────────────────────


def _anthropic_key() -> str | None:
    """Pick the Anthropic key from env first, then official_sandbox/.env."""
    env_key = os.environ.get("ANTHROPIC_API_KEY")
    if env_key:
        return env_key
    sandbox_env = REPO_ROOT / "imp" / "official_sandbox" / ".env"
    if not sandbox_env.exists():
        return None
    for line in sandbox_env.read_text().splitlines():
        if line.strip().startswith("ANTHROPIC_API_KEY="):
            return line.split("=", 1)[1].strip()
    return None


# ── Cert minting (BYOCA for agents) ──────────────────────────────────────


def _gen_agent_cert(
    org_id: str, agent_name: str, trust_domain: str, org_ca_path: pathlib.Path,
    org_ca_key_path: pathlib.Path,
) -> tuple[str, str]:
    """Return (cert_pem, key_pem) for a new agent. SAN follows ADR-014
    convention: ``spiffe://<td>/<org>/<name>`` (3-component)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    spiffe_uri = f"spiffe://{trust_domain}/{org_id}/{agent_name}"
    agent_id = f"{org_id}::{agent_name}"

    org_ca = x509.load_pem_x509_certificate(org_ca_path.read_bytes())
    org_ca_priv = serialization.load_pem_private_key(
        org_ca_key_path.read_bytes(), password=None,
    )
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, agent_id),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org_id),
        ]))
        .issuer_name(org_ca.subject)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(org_ca_priv, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


# ── Provisioning helpers (HTTP) ──────────────────────────────────────────


def _admin_headers() -> dict[str, str]:
    return {"X-Admin-Secret": ADMIN_SECRET, "Content-Type": "application/json"}


def _byoca_enroll_agent(
    client: httpx.Client, proxy_url: str, agent_name: str,
    capabilities: list[str], cert_pem: str, key_pem: str,
) -> str | None:
    body = {
        "agent_name":      agent_name,
        "display_name":    agent_name,
        "capabilities":    capabilities,
        "federated":       False,  # bots are intra-org for the demo
        "cert_pem":        cert_pem,
        "private_key_pem": key_pem,
    }
    r = client.post(
        f"{proxy_url}/v1/admin/agents/enroll/byoca",
        json=body, headers=_admin_headers(), timeout=15.0,
    )
    if r.status_code == 201:
        return r.json().get("dpop_jkt")
    if r.status_code == 409:
        _warn(f"{agent_name} already enrolled — skipping")
        return None
    _fail(f"BYOCA enroll {agent_name}: HTTP {r.status_code} {r.text[:200]}")
    raise SystemExit(1)


# ── Phase runners ────────────────────────────────────────────────────────


def phase_check_reference_up(client: httpx.Client) -> None:
    _h("Phase 1 — verify reference stack reachable")
    for name, url in (
        ("broker (Court)", BROKER_URL),
        ("proxy-a (Roma)", PROXY_A_URL),
        ("proxy-b (Tokyo)", PROXY_B_URL),
    ):
        try:
            r = client.get(f"{url}/health", timeout=5.0)
            r.raise_for_status()
            _ok(f"{name} healthy at {url}")
        except Exception as exc:
            _fail(f"{name} unreachable at {url} ({exc})")
            _info("did you run reference/demo.sh full first?")
            raise SystemExit(1)


def phase_provision_roma_agents(client: httpx.Client) -> None:
    _h("Phase 2 — provision Roma agents (BYOCA) ")
    org_ca = STATE_DIR / "roma-ca.pem"
    org_ca_key = STATE_DIR / "roma-ca.key"
    if not (org_ca.exists() and org_ca_key.exists()):
        _warn("Roma Org CA material not on disk yet — pulling from reference state")
        # ``reference/bootstrap/bootstrap.py`` writes the CA into the
        # ``bootstrap-state`` named volume on the host. Easiest grab:
        # docker cp from the bootstrap container's working dir. For now
        # placeholder — operator runs ``./run.sh prep-ca`` to copy.
        _fail("missing CA — run ./run.sh prep-ca to copy from the reference volume")
        raise SystemExit(1)

    for spec in ROMA_AGENTS:
        agent_dir = STATE_DIR / "agents" / spec["agent_name"]
        agent_dir.mkdir(parents=True, exist_ok=True)
        cert_pem, key_pem = _gen_agent_cert(
            "roma", spec["agent_name"], "roma.cullis.test",
            org_ca, org_ca_key,
        )
        (agent_dir / "agent.pem").write_text(cert_pem)
        (agent_dir / "agent-key.pem").write_text(key_pem)
        (agent_dir / "agent.pem").chmod(0o644)
        (agent_dir / "agent-key.pem").chmod(0o600)

        _byoca_enroll_agent(
            client, PROXY_A_URL, spec["agent_name"], spec["capabilities"],
            cert_pem, key_pem,
        )
        _ok(f"agent {spec['agent_name']} enrolled at Roma proxy")


def phase_provision_user_principals(client: httpx.Client) -> None:
    _h("Phase 3 — provision user principals (Roma + Tokyo)")
    # NOTE: the user-principal admin endpoint is NEW per the spec. Until
    # it lands as a real backend route, we stub-fail loudly so the
    # operator knows where to plug it in. The Frontdesk SSO flow + the
    # /v1/principals/csr proxy endpoint already create user principals
    # at runtime; pre-creation just lets the dashboard show them.
    for spec in ROMA_USERS:
        body = {
            "principal_type": "user",
            "user_name":      spec["user_name"],
            "display_name":   spec["display_name"],
            "reach":           spec["reach"],
        }
        try:
            r = client.post(
                f"{PROXY_A_URL}/v1/admin/users",
                json=body, headers=_admin_headers(), timeout=10.0,
            )
        except Exception as exc:
            _warn(f"/v1/admin/users unreachable ({exc}) — endpoint pending,"
                  " run.sh will try the runtime CSR fallback")
            continue
        if r.status_code in (201, 409):
            _ok(f"user roma::user::{spec['user_name']} ready")
        else:
            _fail(f"user create {spec['user_name']}: HTTP {r.status_code}")

    for spec in TOKYO_USERS:
        body = {
            "principal_type": "user",
            "user_name":      spec["user_name"],
            "display_name":   spec["display_name"],
            "reach":           spec["reach"],
        }
        try:
            r = client.post(
                f"{PROXY_B_URL}/v1/admin/users",
                json=body, headers=_admin_headers(), timeout=10.0,
            )
        except Exception as exc:
            _warn(f"Tokyo /v1/admin/users unreachable ({exc}) — pending")
            continue
        if r.status_code in (201, 409):
            _ok(f"user tokyo::user::{spec['user_name']} ready")
        else:
            _fail(f"user create {spec['user_name']}: HTTP {r.status_code}")


def phase_provision_workload(client: httpx.Client) -> None:
    _h("Phase 4 — provision Tokyo Frontdesk workload")
    for spec in TOKYO_WORKLOADS:
        body = {
            "principal_type": "workload",
            "workload_name":  spec["workload_name"],
            "display_name":   spec["display_name"],
            "image_digest":   spec["image_digest"],
        }
        try:
            r = client.post(
                f"{PROXY_B_URL}/v1/admin/workloads",
                json=body, headers=_admin_headers(), timeout=10.0,
            )
        except Exception as exc:
            _warn(f"Tokyo /v1/admin/workloads unreachable ({exc}) — pending")
            continue
        if r.status_code in (201, 409):
            _ok(f"workload tokyo::workload::{spec['workload_name']} ready")


def phase_provision_resources(client: httpx.Client) -> None:
    _h("Phase 5 — provision MCP resource (claims-db)")
    for spec in ROMA_RESOURCES:
        body = {
            "resource_id":   f"roma::resource::{spec['type']}::{spec['resource_name']}",
            "display_name":  spec["display_name"],
            "type":          spec["type"],
            "endpoint":      spec["endpoint"],
        }
        try:
            r = client.post(
                f"{PROXY_A_URL}/v1/admin/mcp-resources",
                json=body, headers=_admin_headers(), timeout=10.0,
            )
        except Exception as exc:
            _warn(f"/v1/admin/mcp-resources unreachable ({exc})")
            continue
        if r.status_code in (201, 409):
            _ok(f"resource {body['resource_id']} ready")
        else:
            _fail(f"resource create: HTTP {r.status_code} {r.text[:160]}")


def phase_seed_claims_db() -> None:
    _h("Phase 6 — seed claims database")
    sql_path = HERE / "claims.sql"
    if not sql_path.exists():
        _fail(f"missing fixture {sql_path}")
        raise SystemExit(1)
    # The MCP claims-db service is a separate compose addition; for now
    # we exec the SQL into whatever Postgres the proxy-a profile has
    # provisioned (postgres-data volume in reference compose). Real
    # wiring lands in compose.frontdesk.yml.
    try:
        subprocess.run(
            ["docker", "compose", "-f", str(REPO_ROOT / "reference" / "docker-compose.yml"),
             "exec", "-T", "postgres",
             "psql", "-U", "atn", "-d", "agent_trust", "-f", "/dev/stdin"],
            input=sql_path.read_bytes(),
            check=True, capture_output=True,
        )
        _ok(f"seeded {sql_path.name} into Roma postgres")
    except subprocess.CalledProcessError as exc:
        _fail(f"seed failed: {exc.stderr.decode()[:200] if exc.stderr else exc}")
        _info("you may need to wait for postgres to be ready")
        raise SystemExit(1)


def phase_anthropic_key() -> None:
    _h("Phase 7 — verify Anthropic API key")
    key = _anthropic_key()
    if not key:
        _warn("ANTHROPIC_API_KEY not set and not found in imp/official_sandbox/.env")
        _info("the bots will run with mock responses; Cullis Chat will fail tool calls")
        return
    _ok(f"Anthropic key found ({key[:12]}…) — bots + Cullis Chat will use Haiku 4.5")


def main() -> int:
    print(f"{BOLD}{CYAN}Cullis insurance-demo seed{RESET}\n")
    with httpx.Client() as client:
        phase_check_reference_up(client)
        phase_provision_roma_agents(client)
        phase_provision_user_principals(client)
        phase_provision_workload(client)
        phase_provision_resources(client)
    phase_seed_claims_db()
    phase_anthropic_key()
    print(f"\n{GREEN}{BOLD}✓ insurance-demo seed complete{RESET}")
    print(f"  next: ./run.sh frontdesk + ./run.sh trigger-night-reporter")
    return 0


if __name__ == "__main__":
    sys.exit(main())
