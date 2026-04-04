"""
Agent Trust Network — Interactive Admin

Polls for pending join requests and asks for approval interactively.
Run this in a dedicated terminal while orgs are joining.

Usage:
  python admin.py
  python admin.py --broker http://localhost:8000 --secret trustlink-admin-2026
"""
import argparse
import sys
import time

import httpx

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
RED    = "\033[31m"
GRAY   = "\033[90m"


def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET}  {msg}")
def err(msg):  print(f"  {RED}✗{RESET}  {msg}", file=sys.stderr)


def _headers(secret: str) -> dict:
    return {"x-admin-secret": secret}


def get_pending(broker_url: str, secret: str) -> list[dict]:
    resp = httpx.get(f"{broker_url}/admin/orgs/pending",
                     headers=_headers(secret), timeout=5)
    resp.raise_for_status()
    return resp.json()


def approve(broker_url: str, secret: str, org_id: str) -> None:
    resp = httpx.post(f"{broker_url}/admin/orgs/{org_id}/approve",
                      headers=_headers(secret), timeout=5)
    resp.raise_for_status()
    ok(f"'{org_id}' approved")


def reject(broker_url: str, secret: str, org_id: str) -> None:
    resp = httpx.post(f"{broker_url}/admin/orgs/{org_id}/reject",
                      headers=_headers(secret), timeout=5)
    resp.raise_for_status()
    warn(f"'{org_id}' rejected")


def main():
    parser = argparse.ArgumentParser(description="Agent Trust Network — Interactive Admin")
    parser.add_argument("--broker", default="http://localhost:8000")
    parser.add_argument("--secret", default="change-me-in-production")
    parser.add_argument("--interval", type=int, default=3,
                        help="Polling interval in seconds (default: 3)")
    args = parser.parse_args()

    broker_url = args.broker.rstrip("/")
    secret     = args.secret

    print(f"\n{BOLD}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   Agent Trust Network — Admin Console    ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════╝{RESET}")
    print(f"  {GRAY}Broker:  {broker_url}{RESET}")
    print(f"  {GRAY}Polling every {args.interval}s for pending join requests...{RESET}")
    print(f"  {GRAY}Press Ctrl+C to exit.{RESET}\n")

    # Track already-seen orgs to avoid asking twice
    seen: set[str] = set()

    while True:
        try:
            pending = get_pending(broker_url, secret)
        except httpx.HTTPStatusError as e:
            err(f"Auth failed ({e.response.status_code}) — check --secret")
            sys.exit(1)
        except Exception:
            # Broker not yet up — keep waiting silently
            time.sleep(args.interval)
            continue

        for org in pending:
            org_id = org["org_id"]
            if org_id in seen:
                continue

            seen.add(org_id)
            print(f"\n{BOLD}{YELLOW}► Join request from: {org_id}{RESET}")
            print(f"  Display name: {org['display_name']}")
            if org.get("contact_email"):
                print(f"  Contact:      {org['contact_email']}")
            print(f"  Requested at: {org['registered_at']}")

            try:
                answer = input(f"\n  {CYAN}Approve '{org_id}'?{RESET} {GRAY}[y/N]{RESET}: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting.")
                sys.exit(0)

            if answer in ("y", "yes", "s", "si", "sì"):
                try:
                    approve(broker_url, secret, org_id)
                except Exception as e:
                    err(f"Approval failed: {e}")
            else:
                try:
                    reject(broker_url, secret, org_id)
                except Exception as e:
                    err(f"Rejection failed: {e}")

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
