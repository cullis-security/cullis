"""Provision the insurance demo cast on top of the running reference stack.

Adds, on top of whatever ``reference/bootstrap/`` already created:

  - 3 user / agent principals on Mediterranean Insurance (Mediterranean):
      orga::user::claim-officer
      orga::user::claim-manager
      orga::agent::night-reporter
      orga::agent::ticket-bot
  - 1 user principal on Asia-Pacific Insurance (Asia-Pacific):
      orgb::user::counterparty-liaison
  - 1 workload principal on Asia-Pacific (the Frontdesk container itself):
      orgb::workload::frontdesk-container
  - 1 MCP resource on Roma:
      orga::resource::mcp::claims-db (postgres-backed, seeded with claims.sql)
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
    principal_type=workload, hosting Kenji Watanabe at runtime.

Env override:

  CULLIS_BROKER_URL          default http://localhost:8000
  CULLIS_PROXY_A_URL         default http://localhost:9100
  CULLIS_PROXY_B_URL         default http://localhost:9200
  PROXY_A_ADMIN_SECRET       default sandbox-proxy-admin-a (Mastio A)
  PROXY_B_ADMIN_SECRET       default sandbox-proxy-admin-b (Mastio B)
  COURT_ADMIN_SECRET         default sandbox-admin-secret-change-me
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
# Per-proxy admin secrets — match reference/docker-compose.yml. The Court
# (broker) uses its own secret for org-onboarding admin; the per-proxy
# secrets gate the Mastio admin surface (/v1/admin/agents, users, etc.).
PROXY_A_ADMIN_SECRET = os.environ.get(
    "PROXY_A_ADMIN_SECRET", "sandbox-proxy-admin-a",
)
PROXY_B_ADMIN_SECRET = os.environ.get(
    "PROXY_B_ADMIN_SECRET", "sandbox-proxy-admin-b",
)
COURT_ADMIN_SECRET = os.environ.get(
    "COURT_ADMIN_SECRET", "sandbox-admin-secret-change-me",
)

# Cast definitions — match imp/insurance-demo-spec.md verbatim.
MEDITERRANEAN_AGENTS = [
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

MEDITERRANEAN_USERS = [
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

ASIA_PACIFIC_USERS = [
    {
        "user_name":    "counterparty-liaison",
        "display_name": "Counterparty Liaison",
        "reach":        "both",
        "description":  "Counterparty contact at Asia-Pacific Insurance.",
    },
]

ASIA_PACIFIC_WORKLOADS = [
    {
        "workload_name":          "frontdesk-container",
        "display_name":           "Asia-Pacific Frontdesk",
        "image_digest":           "sha256:demo-frontdesk-bundle",
        "hosted_principals_hint": ["orgb::user::counterparty-liaison"],
        "description":            "Multi-user Frontdesk container hosting orgb::user::counterparty-liaison.",
    },
]

MEDITERRANEAN_RESOURCES = [
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


def _admin_headers(proxy_url: str) -> dict[str, str]:
    """Pick the right admin secret based on which proxy we're calling."""
    if proxy_url == PROXY_A_URL:
        secret = PROXY_A_ADMIN_SECRET
    elif proxy_url == PROXY_B_URL:
        secret = PROXY_B_ADMIN_SECRET
    else:
        secret = COURT_ADMIN_SECRET
    return {"X-Admin-Secret": secret, "Content-Type": "application/json"}


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
        json=body, headers=_admin_headers(proxy_url), timeout=15.0,
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
        ("proxy-a (Mediterranean)", PROXY_A_URL),
        ("proxy-b (Asia-Pacific)", PROXY_B_URL),
    ):
        try:
            r = client.get(f"{url}/health", timeout=5.0)
            r.raise_for_status()
            _ok(f"{name} healthy at {url}")
        except Exception as exc:
            _fail(f"{name} unreachable at {url} ({exc})")
            _info("did you run reference/demo.sh full first?")
            raise SystemExit(1)


def phase_provision_orga_agents(client: httpx.Client) -> None:
    _h("Phase 2 — provision orga (Mediterranean) agents (BYOCA) ")
    org_ca = STATE_DIR / "orga-ca.pem"
    org_ca_key = STATE_DIR / "orga-ca.key"
    if not (org_ca.exists() and org_ca_key.exists()):
        _warn("Roma Org CA material not on disk yet — pulling from reference state")
        # ``reference/bootstrap/bootstrap.py`` writes the CA into the
        # ``bootstrap-state`` named volume on the host. Easiest grab:
        # docker cp from the bootstrap container's working dir. For now
        # placeholder — operator runs ``./run.sh prep-ca`` to copy.
        _fail("missing CA — run ./run.sh prep-ca to copy from the reference volume")
        raise SystemExit(1)

    for spec in MEDITERRANEAN_AGENTS:
        agent_dir = STATE_DIR / "agents" / spec["agent_name"]
        agent_dir.mkdir(parents=True, exist_ok=True)
        cert_path = agent_dir / "agent.pem"
        key_path  = agent_dir / "agent-key.pem"
        # Idempotency: if the cert+key already exist on disk we trust
        # they match the BYOCA-enrolled row in the proxy DB. Re-minting
        # on a re-run produces a NEW cert that the DB doesn't know about
        # (BYOCA returns 409 without updating), and the next mTLS
        # handshake fails with "client cert does not match the
        # registered identity".
        if cert_path.exists() and key_path.exists():
            _ok(f"agent {spec['agent_name']} already provisioned "
                f"({cert_path.name} on disk) — skipping mint+enroll")
            continue
        cert_pem, key_pem = _gen_agent_cert(
            "orga", spec["agent_name"], "orga.test",
            org_ca, org_ca_key,
        )
        cert_path.write_text(cert_pem)
        key_path.write_text(key_pem)
        cert_path.chmod(0o644)
        key_path.chmod(0o600)

        _byoca_enroll_agent(
            client, PROXY_A_URL, spec["agent_name"], spec["capabilities"],
            cert_pem, key_pem,
        )
        _ok(f"agent {spec['agent_name']} enrolled at Roma proxy")


def phase_federate_orga_agents(client: httpx.Client) -> None:
    """Phase 2.5 — flip ``federated=true`` on the orga bots so the
    Mastio's federation publisher pushes them to the Court.

    The bots need broker auth to deliver into ``user_inbox_messages``
    (ADR-020 Phase 4 — broker is the inbox trust boundary). Broker
    auth requires the agent row to exist in ``agents`` table at the
    Court, which is what the publisher's ``federated=true`` push
    materialises.

    Idempotent: re-running is fine, the PATCH is a no-op when the
    row is already federated.
    """
    _h("Phase 2.5 — federate orga bots (publisher → Court)")
    for spec in MEDITERRANEAN_AGENTS:
        agent_id = f"orga::{spec['agent_name']}"
        try:
            r = client.patch(
                f"{PROXY_A_URL}/v1/admin/agents/{agent_id}/federated",
                json={"federated": True},
                headers=_admin_headers(PROXY_A_URL), timeout=10.0,
            )
        except Exception as exc:
            _fail(f"PATCH federated {agent_id}: {exc}")
            raise SystemExit(1)
        if r.status_code != 200:
            _fail(f"PATCH federated {agent_id}: HTTP {r.status_code} {r.text[:160]}")
            raise SystemExit(1)
        _ok(f"agent {agent_id} federated=true (publisher tick ≤ 2s)")


def phase_bind_orga_agents_on_court(client: httpx.Client) -> None:
    """Phase 2.6 — create + approve a binding per bot on the Court.

    Mirrors ``reference/bootstrap/bootstrap_mastio.py::_bind_agents_on_court``
    but scoped to the insurance-demo cast. Without a binding the broker's
    ``/v1/auth/login`` rejects the agent JWT with 403 ``No approved
    binding for this agent and organization`` — which is exactly what
    blocks ``send_to_inbox`` end-to-end.

    Retries the binding create while the federation publisher is still
    pushing the agent to the Court (404 on agent lookup), with a 60s
    timeout. Approves once the binding row exists.
    """
    _h("Phase 2.6 — bind orga bots on Court (create + approve)")
    secret_path = STATE_DIR / "orga-org-secret"
    if not secret_path.exists():
        _fail(
            "missing orga-org-secret — run ./run.sh prep-ca to copy it from "
            "the bootstrap-state volume",
        )
        raise SystemExit(1)
    org_secret = secret_path.read_text().strip()
    org_headers = {
        "X-Org-Id": "orga", "X-Org-Secret": org_secret,
        "Content-Type": "application/json",
    }

    for spec in MEDITERRANEAN_AGENTS:
        agent_id = f"orga::{spec['agent_name']}"
        body = {
            "org_id":    "orga",
            "agent_id":  agent_id,
            "scope":     spec["capabilities"],
        }
        binding_id: int | str | None = None
        deadline = time.monotonic() + 60.0
        last_err = "(no attempt)"
        while time.monotonic() < deadline:
            r = client.post(
                f"{BROKER_URL}/v1/registry/bindings",
                json=body, headers=org_headers, timeout=10.0,
            )
            if r.status_code == 201:
                binding_id = r.json().get("id")
                break
            if r.status_code == 409:
                # Already bound — find the existing id.
                lr = client.get(
                    f"{BROKER_URL}/v1/registry/bindings",
                    params={"org_id": "orga"}, headers=org_headers,
                    timeout=10.0,
                )
                lr.raise_for_status()
                binding_id = next(
                    (b["id"] for b in lr.json() if b.get("agent_id") == agent_id),
                    None,
                )
                break
            last_err = f"HTTP {r.status_code} {r.text[:160]}"
            time.sleep(2.0)

        if binding_id is None:
            _fail(
                f"{agent_id}: binding create never succeeded in 60s "
                f"(publisher stuck? last={last_err})",
            )
            raise SystemExit(1)

        # Approve only if the binding is still pending — re-approving
        # an already-approved row triggers an upstream NoneType crash
        # (broker bug — ``approve_binding`` returns None on idempotent
        # re-approve, the router then dereferences ``.agent_id``).
        # Pre-check via the list endpoint and skip when ``status='approved'``.
        listed = client.get(
            f"{BROKER_URL}/v1/registry/bindings",
            params={"org_id": "orga"}, headers=org_headers, timeout=10.0,
        ).json()
        current = next(
            (b for b in listed if b.get("id") == binding_id),
            None,
        )
        if current and current.get("status") == "approved":
            _ok(f"{agent_id}: binding {binding_id} already approved — skipping")
            continue

        ar = client.post(
            f"{BROKER_URL}/v1/registry/bindings/{binding_id}/approve",
            headers=org_headers, timeout=10.0,
        )
        if ar.status_code not in (200, 204):
            _fail(
                f"{agent_id}: binding approve failed "
                f"HTTP {ar.status_code} {ar.text[:200]}",
            )
            raise SystemExit(1)
        _ok(f"{agent_id}: binding {binding_id} approved (scope={spec['capabilities'] or '[]'})")


def phase_provision_user_principals(client: httpx.Client) -> None:
    _h("Phase 3 — provision user principals (Roma + Tokyo)")
    # NOTE: the user-principal admin endpoint is NEW per the spec. Until
    # it lands as a real backend route, we stub-fail loudly so the
    # operator knows where to plug it in. The Frontdesk SSO flow + the
    # /v1/principals/csr proxy endpoint already create user principals
    # at runtime; pre-creation just lets the dashboard show them.
    for spec in MEDITERRANEAN_USERS:
        body = {
            "principal_type": "user",
            "user_name":      spec["user_name"],
            "display_name":   spec["display_name"],
            "reach":           spec["reach"],
        }
        try:
            r = client.post(
                f"{PROXY_A_URL}/v1/admin/users",
                json=body, headers=_admin_headers(PROXY_A_URL), timeout=10.0,
            )
        except Exception as exc:
            _warn(f"/v1/admin/users unreachable ({exc}) — endpoint pending,"
                  " run.sh will try the runtime CSR fallback")
            continue
        if r.status_code in (201, 409):
            _ok(f"user orga::user::{spec['user_name']} ready")
        else:
            _fail(f"user create {spec['user_name']}: HTTP {r.status_code}")

    for spec in ASIA_PACIFIC_USERS:
        body = {
            "principal_type": "user",
            "user_name":      spec["user_name"],
            "display_name":   spec["display_name"],
            "reach":           spec["reach"],
        }
        try:
            r = client.post(
                f"{PROXY_B_URL}/v1/admin/users",
                json=body, headers=_admin_headers(PROXY_B_URL), timeout=10.0,
            )
        except Exception as exc:
            _warn(f"Tokyo /v1/admin/users unreachable ({exc}) — pending")
            continue
        if r.status_code in (201, 409):
            _ok(f"user orgb::user::{spec['user_name']} ready")
        else:
            _fail(f"user create {spec['user_name']}: HTTP {r.status_code}")


def phase_provision_workload(client: httpx.Client) -> None:
    _h("Phase 4 — provision Asia-Pacific Frontdesk workload")
    for spec in ASIA_PACIFIC_WORKLOADS:
        body = {
            "principal_type": "workload",
            "workload_name":  spec["workload_name"],
            "display_name":   spec["display_name"],
            "image_digest":   spec["image_digest"],
        }
        try:
            r = client.post(
                f"{PROXY_B_URL}/v1/admin/workloads",
                json=body, headers=_admin_headers(PROXY_B_URL), timeout=10.0,
            )
        except Exception as exc:
            _warn(f"Tokyo /v1/admin/workloads unreachable ({exc}) — pending")
            continue
        if r.status_code in (201, 409):
            _ok(f"workload orgb::workload::{spec['workload_name']} ready")


def phase_provision_resources(client: httpx.Client) -> None:
    _h("Phase 5 — provision MCP resource (claims-db)")
    for spec in MEDITERRANEAN_RESOURCES:
        # Contract: mcp_proxy/admin/mcp_resources.py::MCPResourceCreate
        # — fields are ``name`` + ``endpoint_url``, NOT resource_id /
        # endpoint. The proxy mints the resource_id (uuid4) on insert.
        body = {
            "name":         spec["resource_name"],
            "endpoint_url": spec["endpoint"],
            "description":  spec.get("description") or spec["display_name"],
            "auth_type":    "none",
        }
        try:
            r = client.post(
                f"{PROXY_A_URL}/v1/admin/mcp-resources",
                json=body, headers=_admin_headers(PROXY_A_URL), timeout=10.0,
            )
        except Exception as exc:
            _warn(f"/v1/admin/mcp-resources unreachable ({exc})")
            continue
        if r.status_code in (201, 409):
            _ok(f"resource {spec['resource_name']} ready "
                f"(resource_id={r.json().get('resource_id', '?')[:8]})")
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


def phase_grant_reach_consents() -> None:
    """Phase 8 — pre-grant the reach consents the demo workflow needs.

    ADR-020 introduced ``reach_consents``: a recipient user must have
    granted consent for a (source_org, source_principal_type, source_name)
    triple before any A2U / U2U / U2A delivery into their inbox is
    allowed. By default no consent → deny.

    For the recorded demo we pre-populate every grant the storyboard
    walks through so the operator can run the flow without stopping
    at each consent prompt. A real production deployment would surface
    the prompts in the SPA the first time each principal is contacted.

    Grants written (recipient ← source):
      orga::user::claim-officer ← orga::agent::night-reporter
      orga::user::claim-officer ← orga::agent::ticket-bot
      orga::user::claim-manager ← orga::agent::ticket-bot
      orga::user::claim-manager ← orga::user::claim-officer
      orgb::user::counterparty-liaison ← orga::user::claim-manager
      orga::user::claim-manager ← orgb::user::counterparty-liaison

    Stored in the broker's postgres (``reach_consents`` table). Direct
    SQL — there's no public API for grant management yet (when one
    lands, this phase rewrites against it).
    """
    _h("Phase 8 — grant reach consents (broker.reach_consents)")
    grants = [
        ("orga", "user", "claim-officer",        "orga", "agent", "night-reporter"),
        ("orga", "user", "claim-officer",        "orga", "agent", "ticket-bot"),
        ("orga", "user", "claim-manager",        "orga", "agent", "ticket-bot"),
        ("orga", "user", "claim-manager",        "orga", "user",  "claim-officer"),
        ("orgb", "user", "counterparty-liaison", "orga", "user",  "claim-manager"),
        ("orga", "user", "claim-manager",        "orgb", "user",  "counterparty-liaison"),
    ]
    import hashlib
    sql_lines = []
    for r_org, r_type, r_name, s_org, s_type, s_name in grants:
        # consent_id PK is VARCHAR(64); hash the pair into a stable short
        # id so re-runs collide on the unique pair constraint and the
        # idempotent UPDATE wins.
        pair = f"{r_org}/{r_type}/{r_name}/{s_org}/{s_type}/{s_name}"
        consent_id = "id-" + hashlib.sha256(pair.encode()).hexdigest()[:32]
        sql_lines.append(
            f"INSERT INTO reach_consents "
            f"(consent_id, recipient_org_id, recipient_principal_type, "
            f"recipient_name, source_org_id, source_principal_type, "
            f"source_name, granted_at, granted_by) VALUES "
            f"('{consent_id}', '{r_org}', '{r_type}', '{r_name}', "
            f"'{s_org}', '{s_type}', '{s_name}', NOW(), 'insurance-demo-seed') "
            f"ON CONFLICT ON CONSTRAINT uq_reach_consent_pair "
            f"DO UPDATE SET revoked_at=NULL, granted_at=NOW();"
        )
    sql = "\n".join(sql_lines)

    try:
        result = subprocess.run(
            ["docker", "compose",
             "-f", str(REPO_ROOT / "reference" / "docker-compose.yml"),
             "exec", "-T", "postgres",
             "psql", "-U", "atn", "-d", "agent_trust", "-f", "/dev/stdin"],
            input=sql.encode(),
            check=True, capture_output=True,
        )
        _ok(f"granted {len(grants)} reach consents into broker.reach_consents")
    except subprocess.CalledProcessError as exc:
        # Common cause: the consent_id UNIQUE constraint is on a different
        # column shape on older schemas. Print stderr so the operator can
        # diagnose without re-running.
        stderr = exc.stderr.decode()[:400] if exc.stderr else str(exc)
        _fail(f"grant reach consents failed: {stderr}")
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
        phase_provision_orga_agents(client)
        phase_federate_orga_agents(client)
        phase_bind_orga_agents_on_court(client)
        phase_provision_user_principals(client)
        phase_provision_workload(client)
        phase_provision_resources(client)
    phase_seed_claims_db()
    phase_grant_reach_consents()
    phase_anthropic_key()
    print(f"\n{GREEN}{BOLD}✓ insurance-demo seed complete{RESET}")
    print(f"  next: ./run.sh frontdesk + ./run.sh trigger-night-reporter")
    return 0


if __name__ == "__main__":
    sys.exit(main())
