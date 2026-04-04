"""
Agent Trust Network — Policy Manager (interactive)

Creates org session policies that control which orgs can talk to each other.

Usage:
  python policy.py
  python policy.py --broker http://localhost:8000
"""
import argparse
import sys

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


def _ask(label: str, default: str = "") -> str:
    prompt = f"  {CYAN}{label}{RESET}"
    if default:
        prompt += f" {GRAY}[{default}]{RESET}"
    prompt += ": "
    value = input(prompt).strip()
    return value if value else default


def main():
    parser = argparse.ArgumentParser(description="Agent Trust Network — Policy Manager")
    parser.add_argument("--broker", default="http://localhost:8000")
    args = parser.parse_args()
    broker_url = args.broker.rstrip("/")

    print(f"\n{BOLD}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   Agent Trust Network — Policy Manager   ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════╝{RESET}\n")

    print(f"  {GRAY}Session policies define which orgs can communicate.{RESET}")
    print(f"  {GRAY}Default-deny: without a policy, no session is allowed.{RESET}\n")

    org_id     = _ask("Your Org ID")
    org_secret = _ask("Your Org Secret")

    # Verify broker connection
    try:
        httpx.get(f"{broker_url}/health", timeout=5).raise_for_status()
    except Exception as e:
        err(f"Broker unreachable: {e}")
        sys.exit(1)

    hdrs = {"x-org-id": org_id, "x-org-secret": org_secret}

    while True:
        print(f"\n  {BOLD}Available actions:{RESET}")
        print(f"    {CYAN}1{RESET}  Create session policy (allow org to talk to another org)")
        print(f"    {CYAN}2{RESET}  List existing policies")
        print(f"    {CYAN}q{RESET}  Quit")

        choice = input(f"\n  {CYAN}Choice{RESET}: ").strip().lower()

        if choice in ("q", "quit", "exit"):
            break

        elif choice == "1":
            print()
            target_org    = _ask("Target org ID (who you want to talk to)")
            caps_input    = _ask("Allowed capabilities (empty = all)", "")
            capabilities  = [c.strip() for c in caps_input.split(",") if c.strip()] if caps_input else []
            max_s_str     = _ask("Max active sessions (empty = unlimited)", "")
            max_sessions  = int(max_s_str) if max_s_str.isdigit() else None

            policy_id = f"{org_id}::session-{target_org}-v1"
            policy_id = _ask("Policy ID", policy_id)

            conditions: dict = {"target_org_id": [target_org]}
            if capabilities:
                conditions["capabilities"] = capabilities
            if max_sessions is not None:
                conditions["max_active_sessions"] = max_sessions

            resp = httpx.post(
                f"{broker_url}/policy/rules",
                json={
                    "policy_id": policy_id,
                    "org_id": org_id,
                    "policy_type": "session",
                    "rules": {"effect": "allow", "conditions": conditions},
                },
                headers=hdrs,
                timeout=10,
            )
            if resp.status_code in (200, 201):
                ok(f"Policy created: {org_id} → {target_org}")
            elif resp.status_code == 409:
                ok(f"Policy already exists: {policy_id}")
            else:
                err(f"Error ({resp.status_code}): {resp.text}")

        elif choice == "2":
            resp = httpx.get(
                f"{broker_url}/policy/rules",
                params={"org_id": org_id},
                headers=hdrs,
                timeout=10,
            )
            if resp.status_code != 200:
                err(f"Error ({resp.status_code}): {resp.text}")
                continue
            policies = resp.json()
            if not policies:
                warn(f"No policies for {org_id}")
            else:
                print(f"\n  {GRAY}Policies for {org_id}:{RESET}")
                for p in policies:
                    conds = p.get("rules", {}).get("conditions", {})
                    targets = conds.get("target_org_id", [])
                    caps = ", ".join(conds.get("capabilities", [])) or "(all)"
                    status_str = f"{GREEN}active{RESET}" if p["is_active"] else f"{RED}inactive{RESET}"
                    print(f"    {CYAN}{p['policy_id']}{RESET}  →  {', '.join(targets)}  [{caps}]  {status_str}")
        else:
            warn("Invalid choice.")

    print(f"\n{GREEN}{BOLD}Done.{RESET}\n")


if __name__ == "__main__":
    main()
