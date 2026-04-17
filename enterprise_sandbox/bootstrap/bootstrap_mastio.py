"""Post-proxy-boot wiring: mastio_pubkey pin + agent seeding.

Runs **after** the proxies have booted and generated their Mastio CA +
leaf identity (lifespan hook in ``mcp_proxy/main.py``).

Two responsibilities:

1. **ADR-009 mastio pubkey pinning** (original job):
   - poll ``GET /v1/admin/mastio-pubkey`` on each proxy until populated
   - ``PATCH /v1/admin/orgs/{org_id}/mastio-pubkey`` on the Court

2. **ADR-010 Phase 4 — Mastio-authoritative agent registry seeding**:
   - for every agent the outer bootstrap minted a cert/key for under
     ``/state/{org}/agents/{name}/``, ``POST /v1/admin/agents`` on the
     owning Mastio with the pre-generated material and ``federated=true``
   - the Phase 3 publisher loop picks the row up from
     ``internal_agents`` and pushes it to the Court (no more direct
     ``/v1/registry/agents`` call from bootstrap)

Idempotent: the Mastio returns 409 on duplicates; we silently continue.
"""
from __future__ import annotations

import os
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


def _seed_agents_on_mastio(
    client: httpx.Client, proxy_url: str, admin_secret: str, org_id: str,
) -> None:
    """ADR-010 Phase 4 — register each /state/{org}/agents/* on the Mastio.

    The outer bootstrap already generated agent cert/key pairs and wrote
    them under ``/state/{org}/agents/{name}/agent.pem,agent-key.pem``.
    We forward them to the Mastio's ``POST /v1/admin/agents`` with
    ``federated=true``; the publisher loop then pushes to the Court.
    """
    import pathlib
    agents_dir = pathlib.Path("/state") / org_id / "agents"
    if not agents_dir.exists():
        _info(f"{org_id}: no agents directory — skipping seed")
        return

    for entry in sorted(p for p in agents_dir.iterdir() if p.is_dir()):
        name = entry.name
        cert_path = entry / "agent.pem"
        key_path = entry / "agent-key.pem"
        if not cert_path.exists() or not key_path.exists():
            _warn(f"{org_id}::{name}: missing agent.pem/agent-key.pem — skipping")
            continue
        cert_pem = cert_path.read_text()
        key_pem = key_path.read_text()
        r = client.post(
            f"{proxy_url}/v1/admin/agents",
            headers={"X-Admin-Secret": admin_secret},
            json={
                "agent_name": name,
                "display_name": name,
                "capabilities": [],  # assigned later by admin via PATCH
                "federated": True,
                "cert_pem": cert_pem,
                "private_key_pem": key_pem,
            },
            timeout=10.0,
        )
        if r.status_code == 201:
            _ok(f"{org_id}::{name}: seeded on Mastio (federated=True)")
        elif r.status_code == 409:
            _info(f"{org_id}::{name}: already on Mastio — skipping")
        else:
            _fail(
                f"{org_id}::{name}: seed failed "
                f"HTTP {r.status_code} {r.text[:200]}"
            )


def main() -> int:
    print(
        f"\n{BOLD}{CYAN}═══ Post-proxy-boot — mastio_pubkey + agent seeding "
        f"{'═' * 10}{RESET}\n",
        flush=True,
    )
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

            _info(f"seeding agents on Mastio {BOLD}{org_id}{RESET}")
            _seed_agents_on_mastio(
                client, cfg["proxy_url"], cfg["admin_secret"], org_id,
            )

    print(
        f"\n{BOLD}{GREEN}"
        f"✓ mastio identities pinned + agents seeded "
        f"(publisher will propagate to Court){RESET}\n",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
