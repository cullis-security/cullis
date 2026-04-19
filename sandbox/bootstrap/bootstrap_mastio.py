"""Post-proxy-boot wiring: mastio_pubkey pin + agent seeding + bindings.

Runs **after** the proxies have booted and generated their Mastio CA +
leaf identity (lifespan hook in ``mcp_proxy/main.py``).

Three responsibilities:

1. **ADR-009 mastio pubkey pinning** (original job):
   - poll ``GET /v1/admin/mastio-pubkey`` on each proxy until populated
   - ``PATCH /v1/admin/orgs/{org_id}/mastio-pubkey`` on the Court

2. **ADR-010 Phase 4 — Mastio-authoritative agent registry seeding**:
   - for every agent the outer bootstrap minted a cert/key for under
     ``/state/{org}/agents/{name}/``, ``POST /v1/admin/agents`` on the
     owning Mastio with the pre-generated material and ``federated=true``
   - the Phase 3 publisher loop picks the row up from
     ``internal_agents`` and pushes it to the Court

3. **ADR-010 Phase 6a-4 — binding create+approve on the Court**:
   - PR #191 removed the binding step from ``bootstrap.py`` but never
     migrated it anywhere; without an approved binding the agent's
     ``/v1/auth/login`` on the Court returns 403 "No approved binding".
   - We retry ``POST /v1/registry/bindings`` until the publisher has
     pushed the agent (404 = not yet visible, retry). 409 = already
     there, fetch id. Then ``POST .../approve``.

Idempotent: the Mastio returns 409 on duplicates; we silently continue.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time

import httpx


BROKER_URL   = os.environ.get("BROKER_URL", "http://broker:8000")
ADMIN_SECRET = os.environ["ADMIN_SECRET"]

# ADR-009 sandbox — scope=up has only orgb on the Court. Patching orga
# would fail with 404 because the bootstrap container skipped its
# registration. scope=full pins both.
SCOPE = os.environ.get("BOOTSTRAP_SCOPE", "full").strip().lower()
if SCOPE not in ("up", "full"):
    SCOPE = "full"

# Per-org proxy URL + proxy admin secret. Sandbox uses the broker's
# admin secret for simplicity — in prod each proxy carries its own.
_ALL_PROXIES = [
    {
        "org_id":       "orga",
        "proxy_url":    os.environ.get("PROXY_A_URL", "http://proxy-a:9100"),
        "admin_secret": os.environ.get("PROXY_A_ADMIN_SECRET", ADMIN_SECRET),
    },
    {
        "org_id":       "orgb",
        "proxy_url":    os.environ.get("PROXY_B_URL", "http://proxy-b:9200"),
        "admin_secret": os.environ.get("PROXY_B_ADMIN_SECRET", ADMIN_SECRET),
    },
]
PROXIES = [
    p for p in _ALL_PROXIES if SCOPE == "full" or p["org_id"] != "orga"
]

RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED   = "\033[31m"
CYAN  = "\033[36m"
GRAY  = "\033[90m"


def _log(sym: str, color: str, msg: str) -> None:
    print(f"  {color}{sym}{RESET} {msg}", flush=True)


def _ok(msg: str) -> None:
    _log("✓", GREEN, msg)


def _warn(msg: str) -> None:
    _log("⚠", YELLOW, msg)


def _fail(msg: str) -> None:
    _log("✗", RED, msg)


def _info(msg: str) -> None:
    _log("…", GRAY, msg)


def _fetch_mastio_pubkey(
    client: httpx.Client, proxy_url: str, admin_secret: str,
    timeout_s: float = 120.0,
) -> str:
    """Poll the proxy until mastio_pubkey is populated. Fails with
    ``SystemExit`` if the deadline elapses."""
    deadline = time.monotonic() + timeout_s
    last_err = "(no response yet)"
    while time.monotonic() < deadline:
        try:
            r = client.get(
                f"{proxy_url}/v1/admin/mastio-pubkey",
                headers={"X-Admin-Secret": admin_secret},
                timeout=5.0,
            )
            if r.status_code == 200:
                pem = r.json().get("mastio_pubkey")
                if pem:
                    return pem
                last_err = "mastio_pubkey still null (first boot finalizing)"
            else:
                last_err = f"HTTP {r.status_code}: {r.text[:120]}"
        except httpx.TransportError as exc:
            last_err = f"connection: {exc}"
        time.sleep(1.0)
    _fail(f"timeout fetching mastio_pubkey from {proxy_url} — last: {last_err}")
    raise SystemExit(1)


def _pin_on_court(
    client: httpx.Client, org_id: str, pem: str,
) -> None:
    r = client.patch(
        f"{BROKER_URL}/v1/admin/orgs/{org_id}/mastio-pubkey",
        headers={"X-Admin-Secret": ADMIN_SECRET},
        json={"mastio_pubkey": pem},
        timeout=10.0,
    )
    if r.status_code != 200:
        _fail(
            f"court PATCH failed for {org_id}: "
            f"HTTP {r.status_code} {r.text[:200]}",
        )
        raise SystemExit(1)


def _load_manifest() -> list[dict]:
    """Load the agents manifest written by bootstrap.py phase_4.

    Each entry has ``agent_id``, ``org_id``, ``agent_name``, and
    ``capabilities``. Returns ``[]`` if the file is missing (older
    bootstrap, or scope=up without agents for this org) — callers fall
    back to directory scan with empty caps.
    """
    path = pathlib.Path("/state/agents.json")
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        _warn(f"/state/agents.json corrupt ({exc}) — treating as empty")
        return []


def _read_org_secret(org_id: str) -> str | None:
    """Read the per-org secret the outer bootstrap persisted."""
    path = pathlib.Path("/state") / org_id / "org_secret"
    if not path.exists():
        return None
    return path.read_text().strip()


def _generate_dpop_jwk() -> tuple[dict, dict]:
    """Generate an EC P-256 DPoP keypair. Returns ``(public_jwk, private_jwk)``.

    ADR-011 Phase 4 — enrollment must ship a public JWK so the Mastio
    pins its jkt from the first request, and the agent container needs
    the matching private JWK on disk to sign proofs at runtime. The
    sandbox bootstrap is the single producer/consumer, so we hand-roll
    the keypair here rather than import cullis_sdk.dpop (keeps the
    container lean — SDK lives in the agent image, not here).
    """
    import base64 as _b64
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_nums = priv.public_key().public_numbers()
    priv_nums = priv.private_numbers()
    def _b64url(n: int) -> str:
        return _b64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()
    public_jwk = {
        "kty": "EC", "crv": "P-256",
        "x": _b64url(pub_nums.x), "y": _b64url(pub_nums.y),
    }
    private_jwk = {**public_jwk, "d": _b64url(priv_nums.private_value)}
    return public_jwk, private_jwk


def _enroll_agents_via_byoca(
    client: httpx.Client, proxy_url: str, admin_secret: str, org_id: str,
    manifest: list[dict],
) -> list[dict]:
    """ADR-011 Phase 4 — enroll each bootstrap-minted agent via
    ``/v1/admin/agents/enroll/byoca``.

    The outer bootstrap already minted an Org-CA-signed cert/key pair
    per agent under ``/state/{org}/agents/{name}/``. Phase 1b exposed a
    verified enrollment endpoint that accepts that material, verifies
    the chain, and emits an API key + pins DPoP jkt. We persist the
    returned credentials alongside the cert so agent containers can
    ``from_api_key_file(...)`` at runtime — no more SPIFFE/BYOCA
    direct login to the Court.

    Returns the subset of manifest rows successfully enrolled so the
    caller can drive binding create+approve on the Court. Row shape
    matches the old ``_seed_agents_on_mastio`` contract for caller
    back-compat.
    """
    agents_dir = pathlib.Path("/state") / org_id / "agents"
    if not agents_dir.exists():
        _info(f"{org_id}: no agents directory — skipping enroll")
        return []

    caps_by_name = {e["agent_name"]: e.get("capabilities", []) for e in manifest
                    if e.get("org_id") == org_id}
    enrolled: list[dict] = []
    for entry in sorted(p for p in agents_dir.iterdir() if p.is_dir()):
        name = entry.name
        cert_path = entry / "agent.pem"
        key_path = entry / "agent-key.pem"
        if not cert_path.exists() or not key_path.exists():
            _warn(f"{org_id}::{name}: missing agent.pem/agent-key.pem — skipping")
            continue
        cert_pem = cert_path.read_text()
        key_pem = key_path.read_text()
        capabilities = caps_by_name.get(name, [])
        public_jwk, private_jwk = _generate_dpop_jwk()
        r = client.post(
            f"{proxy_url}/v1/admin/agents/enroll/byoca",
            headers={"X-Admin-Secret": admin_secret},
            json={
                "agent_name": name,
                "display_name": name,
                "capabilities": capabilities,
                "federated": True,
                "cert_pem": cert_pem,
                "private_key_pem": key_pem,
                "dpop_jwk": public_jwk,
            },
            timeout=10.0,
        )
        if r.status_code == 201:
            resp = r.json()
            # Persist the runtime credentials next to the cert so the
            # agent container's volume mount finds them. Layout matches
            # ``CullisClient.from_api_key_file`` expectations: one file
            # per artifact, 0600-ish (sandbox mount is 0644 by default).
            (entry / "api-key").write_text(resp["api_key"])
            (entry / "api-key").chmod(0o644)
            import json as _json
            (entry / "dpop.jwk").write_text(
                _json.dumps({"private_jwk": private_jwk}, separators=(",", ":"))
            )
            (entry / "dpop.jwk").chmod(0o644)
            _ok(f"{org_id}::{name}: enrolled via BYOCA "
                f"(caps={capabilities or '[]'}, jkt={resp.get('dpop_jkt', '')[:12]}…)")
            enrolled.append({"org_id": org_id, "agent_name": name,
                             "capabilities": capabilities})
        elif r.status_code == 409:
            _info(f"{org_id}::{name}: already enrolled — skipping")
            enrolled.append({"org_id": org_id, "agent_name": name,
                             "capabilities": capabilities})
        else:
            _fail(
                f"{org_id}::{name}: enroll failed "
                f"HTTP {r.status_code} {r.text[:200]}"
            )
    return enrolled


def _bind_agents_on_court(
    client: httpx.Client, seeded: list[dict],
    timeout_s: float = 60.0, retry_s: float = 2.0,
) -> None:
    """ADR-010 Phase 6a-4 — create + approve a binding per seeded agent.

    Retries ``POST /v1/registry/bindings`` while the publisher is still
    catching up (404 on the agent lookup). 409 = already bound, look up
    the existing id and approve idempotently.
    """
    if not seeded:
        return
    for agent in seeded:
        org_id = agent["org_id"]
        agent_name = agent["agent_name"]
        agent_id = f"{org_id}::{agent_name}"
        capabilities = agent["capabilities"]
        org_secret = _read_org_secret(org_id)
        if org_secret is None:
            _fail(f"{agent_id}: no /state/{org_id}/org_secret — cannot bind")
            raise SystemExit(1)
        headers = {"X-Org-Id": org_id, "X-Org-Secret": org_secret}
        body = {"org_id": org_id, "agent_id": agent_id, "scope": capabilities}

        binding_id: int | str | None = None
        deadline = time.monotonic() + timeout_s
        last = "(no attempt)"
        while time.monotonic() < deadline:
            r = client.post(
                f"{BROKER_URL}/v1/registry/bindings",
                json=body, headers=headers, timeout=10.0,
            )
            if r.status_code == 201:
                binding_id = r.json().get("id")
                break
            if r.status_code == 409:
                lr = client.get(
                    f"{BROKER_URL}/v1/registry/bindings",
                    params={"org_id": org_id}, headers=headers, timeout=10.0,
                )
                lr.raise_for_status()
                binding_id = next(
                    (b["id"] for b in lr.json() if b.get("agent_id") == agent_id),
                    None,
                )
                break
            last = f"HTTP {r.status_code} {r.text[:160]}"
            time.sleep(retry_s)

        if binding_id is None:
            _fail(
                f"{agent_id}: binding create never succeeded in {timeout_s:.0f}s "
                f"(publisher stuck? last={last})"
            )
            raise SystemExit(1)

        ar = client.post(
            f"{BROKER_URL}/v1/registry/bindings/{binding_id}/approve",
            headers=headers, timeout=10.0,
        )
        if ar.status_code not in (200, 204):
            _fail(
                f"{agent_id}: binding approve failed "
                f"HTTP {ar.status_code} {ar.text[:200]}"
            )
            raise SystemExit(1)
        _ok(f"{agent_id}: binding {binding_id} approved (scope={capabilities or '[]'})")


def main() -> int:
    print(
        f"\n{BOLD}{CYAN}═══ Post-proxy-boot — mastio_pubkey + agent seeding "
        f"{'═' * 10}{RESET}\n",
        flush=True,
    )
    manifest = _load_manifest()
    all_seeded: list[dict] = []
    with httpx.Client(timeout=10.0) as client:
        for cfg in PROXIES:
            org_id = cfg["org_id"]
            _info(f"fetching mastio_pubkey from {BOLD}{cfg['proxy_url']}{RESET}")
            pem = _fetch_mastio_pubkey(
                client, cfg["proxy_url"], cfg["admin_secret"],
            )
            preview = pem.split("\n")[1][:40] if "\n" in pem else pem[:40]
            _ok(f"{org_id}: pubkey fetched ({preview}…)")

            _info(f"pinning on Court for {BOLD}{org_id}{RESET}")
            _pin_on_court(client, org_id, pem)
            _ok(f"{org_id}: mastio_pubkey pinned — counter-sig enforcement active")

            _info(f"enrolling agents via BYOCA on Mastio {BOLD}{org_id}{RESET}")
            enrolled = _enroll_agents_via_byoca(
                client, cfg["proxy_url"], cfg["admin_secret"], org_id,
                manifest,
            )
            all_seeded.extend(enrolled)

        if all_seeded:
            _info(
                f"creating+approving bindings on Court "
                f"({len(all_seeded)} agent(s), waiting for publisher)"
            )
            _bind_agents_on_court(client, all_seeded)

    print(
        f"\n{BOLD}{GREEN}"
        f"✓ mastio identities pinned + agents seeded + bindings approved{RESET}\n",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
