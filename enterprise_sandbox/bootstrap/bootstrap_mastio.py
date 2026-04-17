"""ADR-009 Phase 2 — pin each proxy's mastio_pubkey on the Court.

Runs **after** the proxies have booted and generated their Mastio CA +
leaf identity (lifespan hook in ``mcp_proxy/main.py``). The main
bootstrap container ran before the proxies, so it couldn't know the
mastio pubkey yet — this is a second-phase one-shot that closes that
loop, enabling the Court's counter-signature enforcement on every
subsequent ``/v1/auth/token`` call.

Flow per proxy:
  1. poll ``GET /v1/admin/mastio-pubkey`` on the proxy (with X-Admin-Secret)
     until it returns a non-null PEM (first boot may still be finalizing)
  2. ``PATCH /v1/admin/orgs/{org_id}/mastio-pubkey`` on the Court with
     the PEM — pin it under the admin secret.

Idempotent: re-running the container just re-PATCHes the same pubkey.
"""
from __future__ import annotations

import os
import sys
import time

import httpx


BROKER_URL   = os.environ.get("BROKER_URL", "http://broker:8000")
ADMIN_SECRET = os.environ["ADMIN_SECRET"]

# Per-org proxy URL + proxy admin secret. Sandbox uses the broker's
# admin secret for simplicity — in prod each proxy carries its own.
PROXIES = [
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


def main() -> int:
    print(
        f"\n{BOLD}{CYAN}═══ ADR-009 Phase 2 — pin mastio_pubkey on Court "
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

    print(f"\n{BOLD}{GREEN}✓ ADR-009 mastio identities pinned on Court{RESET}\n",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
