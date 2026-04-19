"""Enterprise sandbox bootstrap: 2 orgs, 3 agents, 2 MCP servers, verbose ANSI output."""
from __future__ import annotations

import datetime
import json
import os
import pathlib
import secrets
import sys
import time

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BROKER_URL   = os.environ.get("BROKER_URL", "http://broker:8000")
ADMIN_SECRET = os.environ["ADMIN_SECRET"]
STATE        = pathlib.Path(os.environ.get("STATE_DIR", "/state"))
DONE_FLAG    = STATE / "bootstrap.done"
PKI_KEY_TYPE = os.environ.get("PKI_KEY_TYPE", "ec").strip().lower()
TRUST_DOMAIN_SUFFIX = os.environ.get("TRUST_DOMAIN_SUFFIX", ".test")

# PDP webhook — the Court calls this per cross-org session request.
# The sandbox proxies expose /pdp/policy on their internal port 9100.
# Without a URL set, the Court defaults to "deny" (fail-safe), so cross-
# org session opens 403 at the broker.
_PDP_WEBHOOKS = {
    "orga": os.environ.get("ORGA_PDP_WEBHOOK", "http://proxy-a:9100/pdp/policy"),
    "orgb": os.environ.get("ORGB_PDP_WEBHOOK", "http://proxy-b:9100/pdp/policy"),
}

# ADR-009 sandbox — scope=up leaves org A (Acme Corp) **unregistered on the
# Court**: Mastio A is still booted standalone (CA generated locally, volume
# seeded) so the user can walk through the guided onboarding. scope=full
# registers both orgs + all agents + MCP resources for scenario replay.
SCOPE = os.environ.get("BOOTSTRAP_SCOPE", "full").strip().lower()
if SCOPE not in ("up", "full"):
    print(f"invalid BOOTSTRAP_SCOPE={SCOPE!r} — falling back to 'full'")
    SCOPE = "full"

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
GRAY   = "\033[90m"


def _header(phase: int, title: str) -> None:
    line = f"═══ PHASE {phase} — {title} "
    print(f"\n{BOLD}{CYAN}{line}{'═' * max(0, 60 - len(line))}{RESET}\n", flush=True)


def _ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{RESET} {msg}", flush=True)


def _fail(msg: str) -> None:
    print(f"  {RED}✗{RESET} {msg}", flush=True)


def _info(msg: str) -> None:
    print(f"  {GRAY}…{RESET} {msg}", flush=True)


# ---------------------------------------------------------------------------
# Org / Agent definitions
# ---------------------------------------------------------------------------
ORGS = [
    {"org_id": "orga", "display_name": "Organization A", "flow": "join"},
    {"org_id": "orgb", "display_name": "Organization B", "flow": "attach"},
]

AGENTS = [
    {
        "agent_id": "orga::agent-a",
        "org_id": "orga",
        "capabilities": ["order.read", "order.write", "oneshot.message", "sandbox.read"],
    },
    {
        "agent_id": "orga::byoca-bot",
        "org_id": "orga",
        "capabilities": ["order.read", "oneshot.message", "sandbox.read"],
        "persist_extra": True,  # byoca-a container reads certs from state
    },
    {
        "agent_id": "orgb::agent-b",
        "org_id": "orgb",
        "capabilities": ["order.read", "order.write", "oneshot.message", "sandbox.read"],
    },
]

PEERS = {
    "orga::agent-a":   ["orgb::agent-b", "orga::byoca-bot"],
    "orga::byoca-bot":  ["orgb::agent-b", "orga::agent-a"],
    "orgb::agent-b":   ["orga::agent-a", "orga::byoca-bot"],
}

# ---------------------------------------------------------------------------
# PKI helpers
# ---------------------------------------------------------------------------

def _gen_key():
    """Generate a private key of the configured type."""
    if PKI_KEY_TYPE == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if PKI_KEY_TYPE == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    raise SystemExit(f"bootstrap: unsupported PKI_KEY_TYPE={PKI_KEY_TYPE!r}")


def _thumbprint(cert: x509.Certificate) -> str:
    """SHA-256 thumbprint, first 16 hex chars."""
    return cert.fingerprint(hashes.SHA256()).hex()[:16]


def _serial_hex(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "x")


def _trust_domain(org_id: str) -> str:
    return f"{org_id}{TRUST_DOMAIN_SUFFIX}"


def _spiffe_id(org_id: str, agent_name: str) -> str:
    return f"spiffe://{_trust_domain(org_id)}/{org_id}/{agent_name}"


# ---------------------------------------------------------------------------
# Phase 1 — Wait for broker
# ---------------------------------------------------------------------------

def _wait_broker(client: httpx.Client, timeout_s: float = 120.0) -> None:
    _header(1, "Waiting for Court (broker)")
    _info(f"polling {BROKER_URL}/health (timeout {timeout_s:.0f}s)")
    start = time.monotonic()
    last_exc: Exception | None = None
    while time.monotonic() - start < timeout_s:
        try:
            r = client.get(f"{BROKER_URL}/health")
            if r.status_code == 200:
                elapsed = time.monotonic() - start
                _ok(f"GET /health → 200 OK  ({elapsed:.1f}s)")
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(1)
    _fail(f"broker not healthy after {timeout_s:.0f}s — last error: {last_exc}")
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Phase 2 — Generate Org CAs
# ---------------------------------------------------------------------------

def _gen_org_ca(org_id: str) -> tuple[x509.Certificate, bytes, bytes]:
    """Generate a self-signed org CA. Returns (cert_obj, cert_pem, key_pem)."""
    key = _gen_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert, cert_pem, key_pem


def _persist_org(org_id: str, display_name: str, cert_pem: bytes,
                 key_pem: bytes, org_secret: str) -> None:
    d = STATE / org_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "ca.pem").write_bytes(cert_pem)
    (d / "ca-key.pem").write_bytes(key_pem)
    (d / "org_secret").write_text(org_secret)
    (d / "display_name").write_text(display_name)
    for p in d.iterdir():
        p.chmod(0o644)


def _load_existing_org(org_id: str) -> dict | None:
    """Reload persisted CA + secret from the bootstrap-state volume.

    Returns ``None`` when any of the four files is missing — caller
    falls back to fresh generation. Used to make ``demo.sh full``
    idempotent across ``demo.sh up`` runs that don't fully ``down``
    the stack: the Court's Postgres keeps the org row, so regenerating
    the secret here would mismatch the stored bcrypt hash on the next
    login.
    """
    d = STATE / org_id
    required = ("ca.pem", "ca-key.pem", "org_secret", "display_name")
    if not all((d / f).exists() for f in required):
        return None
    try:
        cert_pem = (d / "ca.pem").read_bytes()
        key_pem = (d / "ca-key.pem").read_bytes()
        org_secret = (d / "org_secret").read_text().strip()
        display_name = (d / "display_name").read_text().strip()
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as exc:
        _warn(f"state files unreadable for {org_id} ({exc}) — regenerating")
        return None
    return {
        "cert": cert, "cert_pem": cert_pem, "key_pem": key_pem,
        "org_secret": org_secret, "display_name": display_name,
    }


def phase_2_generate_cas() -> dict[str, dict]:
    """Returns {org_id: {cert, cert_pem, key_pem, org_secret, display_name}}.

    Idempotent: reuses existing state when every required file is present.
    """
    _header(2, "Generate Org CAs")
    orgs_data: dict[str, dict] = {}
    for org in ORGS:
        oid = org["org_id"]
        reused = _load_existing_org(oid)
        if reused is not None:
            cert = reused["cert"]
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            _ok(f"org_id={BOLD}{oid}{RESET}  [33mreused from state[0m  CN={cn}")
            _ok(f"serial={GRAY}{_serial_hex(cert)}{RESET}  thumbprint={CYAN}{_thumbprint(cert)}{RESET}")
            orgs_data[oid] = reused
            continue
        cert, cert_pem, key_pem = _gen_org_ca(oid)
        org_secret = secrets.token_urlsafe(32)
        _persist_org(oid, org["display_name"], cert_pem, key_pem, org_secret)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        _ok(f"org_id={BOLD}{oid}{RESET}  key={PKI_KEY_TYPE.upper()}  CN={cn}")
        _ok(f"serial={GRAY}{_serial_hex(cert)}{RESET}  thumbprint={CYAN}{_thumbprint(cert)}{RESET}")
        _ok(f"persisted → {STATE / oid}/")
        orgs_data[oid] = {
            "cert": cert, "cert_pem": cert_pem, "key_pem": key_pem,
            "org_secret": org_secret, "display_name": org["display_name"],
        }
    return orgs_data


# ---------------------------------------------------------------------------
# Phase 3 — Register orgs on broker
# ---------------------------------------------------------------------------

def _admin_headers() -> dict[str, str]:
    return {"x-admin-secret": ADMIN_SECRET}


def _org_headers(org_id: str, org_secret: str) -> dict[str, str]:
    return {"x-org-id": org_id, "x-org-secret": org_secret}


def _log_http(method: str, path: str, r: httpx.Response) -> None:
    status = r.status_code
    reason = r.reason_phrase or ""
    color = GREEN if 200 <= status < 300 else (YELLOW if status < 400 else RED)
    _ok(f"{method} {path} → {color}{status} {reason}{RESET}")


def _onboard_via_join(client: httpx.Client, org_id: str, display_name: str,
                      cert_pem: bytes, org_secret: str) -> None:
    # Create invite
    r = client.post(
        f"{BROKER_URL}/v1/admin/invites",
        json={"label": f"sandbox-{org_id}", "ttl_hours": 1},
        headers=_admin_headers(),
    )
    r.raise_for_status()
    token = r.json()["token"]
    _log_http("POST", "/v1/admin/invites", r)

    # Join
    r = client.post(f"{BROKER_URL}/v1/onboarding/join", json={
        "org_id": org_id,
        "display_name": display_name,
        "secret": org_secret,
        "ca_certificate": cert_pem.decode(),
        "contact_email": f"admin@{org_id}.test",
        "invite_token": token,
        "trust_domain": _trust_domain(org_id),
        "webhook_url": _PDP_WEBHOOKS.get(org_id),
    })
    if r.status_code == 409:
        _warn(f"{org_id} already registered — skipping join")
        return
    if r.status_code not in (200, 201, 202):
        _fail(f"join failed: {r.status_code} {r.text}")
        raise SystemExit(1)
    _log_http("POST", "/v1/onboarding/join", r)

    # Admin approve
    r = client.post(
        f"{BROKER_URL}/v1/admin/orgs/{org_id}/approve",
        headers=_admin_headers(),
    )
    if r.status_code not in (200, 409):
        r.raise_for_status()
    _log_http("POST", f"/v1/admin/orgs/{org_id}/approve", r)
    _ok(f"{BOLD}{org_id}{RESET} active via join flow")


def _onboard_via_attach(client: httpx.Client, org_id: str, display_name: str,
                        cert_pem: bytes, org_secret: str) -> None:
    # Admin creates org (409 = already exists → skip to attach)
    r = client.post(f"{BROKER_URL}/v1/registry/orgs", json={
        "org_id": org_id,
        "display_name": display_name,
        "secret": "placeholder-will-be-rotated",
    }, headers=_admin_headers())
    if r.status_code == 409:
        _warn(f"{org_id} already registered — skipping attach")
        return
    r.raise_for_status()
    _log_http("POST", "/v1/registry/orgs", r)

    # Admin generates attach invite
    r = client.post(
        f"{BROKER_URL}/v1/admin/orgs/{org_id}/attach-invite",
        json={"label": f"sandbox-attach-{org_id}", "ttl_hours": 1},
        headers=_admin_headers(),
    )
    r.raise_for_status()
    token = r.json()["token"]
    _log_http("POST", f"/v1/admin/orgs/{org_id}/attach-invite", r)

    # Attach CA + rotate secret
    r = client.post(f"{BROKER_URL}/v1/onboarding/attach", json={
        "ca_certificate": cert_pem.decode(),
        "invite_token": token,
        "secret": org_secret,
        "trust_domain": _trust_domain(org_id),
        "webhook_url": _PDP_WEBHOOKS.get(org_id),
    })
    if r.status_code not in (200, 201, 202):
        _fail(f"attach failed: {r.status_code} {r.text}")
        raise SystemExit(1)
    _log_http("POST", "/v1/onboarding/attach", r)
    _ok(f"{BOLD}{org_id}{RESET} active via attach flow")


def phase_3_register_orgs(client: httpx.Client, orgs_data: dict[str, dict]) -> None:
    # ADR-009 sandbox — scope=up registers only ``orgb``. ``orga`` is left
    # unregistered so the user can walk through the guided Court-side
    # onboarding (see GUIDE.md, step 1). Mastio A is still booted with the
    # locally-generated Org CA so the dashboard is reachable.
    target_orgs = [o for o in ORGS if SCOPE == "full" or o["org_id"] != "orga"]

    _header(3, f"Register orgs on broker (scope={SCOPE})")
    if SCOPE == "up":
        _info("scope=up → registering only orgb; orga left for user onboarding")

    for org in target_orgs:
        oid = org["org_id"]
        d = orgs_data[oid]
        _info(f"registering {BOLD}{oid}{RESET} via {org['flow']} flow")
        if org["flow"] == "join":
            _onboard_via_join(client, oid, d["display_name"],
                              d["cert_pem"], d["org_secret"])
        elif org["flow"] == "attach":
            _onboard_via_attach(client, oid, d["display_name"],
                                d["cert_pem"], d["org_secret"])
        else:
            raise SystemExit(f"unknown flow: {org['flow']}")

    # Verify
    r = client.get(f"{BROKER_URL}/v1/registry/orgs", headers=_admin_headers())
    r.raise_for_status()
    active_ids = {o["org_id"] for o in r.json() if o.get("status") == "active"}
    expected = {o["org_id"] for o in target_orgs}
    missing = expected - active_ids
    if missing:
        _fail(f"orgs not active: {missing}")
        raise SystemExit(1)
    _ok(f"verified {len(expected)} orgs active on broker")


# ---------------------------------------------------------------------------
# Phase 4 — Register agents
# ---------------------------------------------------------------------------

def _gen_agent_cert(agent_id: str, org_id: str,
                    ca_cert_pem: bytes, ca_key_pem: bytes) -> tuple[x509.Certificate, bytes, bytes]:
    """Issue agent cert signed by org CA with SPIFFE SAN."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_pem_private_key(ca_key_pem, password=None)
    key = _gen_key()
    _, agent_name = agent_id.split("::", 1)
    spiffe = _spiffe_id(org_id, agent_name)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert, cert_pem, key_pem


def _provision_agent(client: httpx.Client, agent_def: dict,
                     orgs_data: dict[str, dict]) -> dict:
    """Register one agent + binding; returns metadata dict."""
    agent_id = agent_def["agent_id"]
    org_id = agent_def["org_id"]
    caps = agent_def["capabilities"]
    _, agent_name = agent_id.split("::", 1)
    spiffe = _spiffe_id(org_id, agent_name)

    od = orgs_data[org_id]
    org_secret = od["org_secret"]
    headers = _org_headers(org_id, org_secret)

    # 1. Issue cert
    cert, cert_pem, key_pem = _gen_agent_cert(
        agent_id, org_id, od["cert_pem"], od["key_pem"],
    )

    # Persist cert/key for the agent
    agent_dir = STATE / org_id / "agents" / agent_name
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "agent.pem").write_bytes(cert_pem)
    (agent_dir / "agent-key.pem").write_bytes(key_pem)
    (agent_dir / "agent.pem").chmod(0o644)
    (agent_dir / "agent-key.pem").chmod(0o644)

    _ok(f"agent_id={BOLD}{agent_id}{RESET}  SPIFFE={CYAN}{spiffe}{RESET}")
    _ok(f"cert serial={GRAY}{_serial_hex(cert)}{RESET}  thumbprint={CYAN}{_thumbprint(cert)}{RESET}  key={PKI_KEY_TYPE.upper()}")

    # ADR-010 Phase 4 — registry ownership inverted.
    #
    # Before: bootstrap POSTed ``/v1/registry/agents`` + binding on the
    # Court directly, using ``org_secret`` for auth. That path bypassed
    # the Mastio and left it blind to its own agents.
    #
    # After: bootstrap only mints the cert/key pair and parks them in
    # ``/state/{org}/agents/{name}/`` (so the agent containers can mount
    # them). The post-proxy-boot companion (``bootstrap_mastio.py``)
    # reads the dir, calls ``/v1/admin/agents`` on the Mastio with
    # ``federated=true``, and the Phase 3 publisher loop propagates
    # the row to the Court on its next tick.
    _info(f"cert persisted → /state/{org_id}/agents/{agent_name}/")
    _info(
        f"federation push deferred to bootstrap_mastio.py + publisher loop"
    )

    return {
        "agent_id": agent_id,
        "org_id": org_id,
        "spiffe_id": spiffe,
        "capabilities": caps,
        "cert_serial": _serial_hex(cert),
        "cert_thumbprint": _thumbprint(cert),
    }


def phase_4_register_agents(client: httpx.Client, orgs_data: dict[str, dict]) -> list[dict]:
    # ADR-009 sandbox — scope=up enrolls only orgb agents. orga agents are
    # deferred to the guided walkthrough.
    targets = [a for a in AGENTS if SCOPE == "full" or a["org_id"] != "orga"]
    _header(4, f"Register agents (scope={SCOPE})")
    if SCOPE == "up":
        _info("scope=up → enrolling only orgb agents")
    results = []
    for agent_def in targets:
        _info(f"provisioning {BOLD}{agent_def['agent_id']}{RESET}")
        meta = _provision_agent(client, agent_def, orgs_data)
        results.append(meta)
        print(flush=True)

    # ADR-010 Phase 6a-4 — hand off to bootstrap_mastio.py. It needs the
    # caller-defined capabilities both to seed the Mastio (PATCH is still
    # TODO) and to POST /v1/registry/bindings on the Court. The seeded
    # agent row carries empty caps today; writing a manifest here keeps
    # the two bootstrap stages loosely coupled.
    manifest = [
        {
            "agent_id":     a["agent_id"],
            "org_id":       a["org_id"],
            "agent_name":   a["agent_id"].split("::", 1)[1],
            "capabilities": a["capabilities"],
        }
        for a in targets
    ]
    manifest_path = STATE / "agents.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    manifest_path.chmod(0o644)
    _ok(f"agents manifest → {manifest_path}")
    return results


# ---------------------------------------------------------------------------
# Phase 5 — Session policies
# ---------------------------------------------------------------------------

def phase_5_session_policies(client: httpx.Client, orgs_data: dict[str, dict]) -> None:
    target_orgs = [o for o in ORGS if SCOPE == "full" or o["org_id"] != "orga"]
    _header(5, f"Create session policies (scope={SCOPE})")
    for org in target_orgs:
        oid = org["org_id"]
        od = orgs_data[oid]
        policy_id = f"{oid}::session-allow-all"
        headers = _org_headers(oid, od["org_secret"])
        r = client.post(
            f"{BROKER_URL}/v1/policy/rules",
            json={
                "policy_id": policy_id,
                "org_id": oid,
                "policy_type": "session",
                "rules": {
                    "effect": "allow",
                    "conditions": {"target_org_id": [], "capabilities": []},
                },
            },
            headers=headers,
        )
        if r.status_code not in (200, 201, 409):
            _fail(f"policy create {policy_id}: {r.status_code} {r.text}")
            raise SystemExit(1)
        _log_http("POST", "/v1/policy/rules", r)
        _ok(f"policy_id={BOLD}{policy_id}{RESET}  effect={GREEN}allow{RESET}")


# ---------------------------------------------------------------------------
# Phase 6 — peers.json
# ---------------------------------------------------------------------------

def phase_6_peers_json() -> None:
    _header(6, "Generate peers.json")
    path = STATE / "peers.json"
    path.write_text(json.dumps(PEERS, indent=2))
    path.chmod(0o644)
    for agent_id, peers in PEERS.items():
        _ok(f"{agent_id} → {peers}")
    _ok(f"written → {path}")


# ---------------------------------------------------------------------------
# Phase 7 — Summary
# ---------------------------------------------------------------------------

def phase_7_summary(agents_meta: list[dict]) -> None:
    _header(7, "Summary")

    # Org table
    print(f"  {BOLD}{'ORG ID':<12} {'DISPLAY NAME':<22} {'FLOW':<8}{RESET}", flush=True)
    print(f"  {'─' * 12} {'─' * 22} {'─' * 8}", flush=True)
    for org in ORGS:
        print(f"  {GREEN}{org['org_id']:<12}{RESET} {org['display_name']:<22} {org['flow']:<8}", flush=True)
    print(flush=True)

    # Agent table
    print(f"  {BOLD}{'AGENT ID':<22} {'SPIFFE ID':<42} {'THUMBPRINT':<18} {'CAPABILITIES'}{RESET}", flush=True)
    print(f"  {'─' * 22} {'─' * 42} {'─' * 18} {'─' * 30}", flush=True)
    for m in agents_meta:
        caps_str = ", ".join(m["capabilities"])
        print(
            f"  {GREEN}{m['agent_id']:<22}{RESET} "
            f"{CYAN}{m['spiffe_id']:<42}{RESET} "
            f"{GRAY}{m['cert_thumbprint']:<18}{RESET} "
            f"{caps_str}",
            flush=True,
        )
    print(flush=True)

    DONE_FLAG.touch()
    _ok(f"bootstrap.done → {DONE_FLAG}")
    print(f"\n  {BOLD}{GREEN}Bootstrap complete.{RESET}\n", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    STATE.mkdir(parents=True, exist_ok=True)
    if DONE_FLAG.exists():
        DONE_FLAG.unlink()

    with httpx.Client(verify=False, timeout=30.0) as client:
        # Phase 1
        _wait_broker(client)

        # Phase 2
        orgs_data = phase_2_generate_cas()

        # Phase 3
        phase_3_register_orgs(client, orgs_data)

        # Phase 4
        agents_meta = phase_4_register_agents(client, orgs_data)

        # Phase 5
        phase_5_session_policies(client, orgs_data)

    # Phase 6
    phase_6_peers_json()

    # Phase 7
    phase_7_summary(agents_meta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
