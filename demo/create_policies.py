"""
Create session policies for the demo.

Policies define which orgs can talk to each other. Default is deny.
Each org must create a policy allowing sessions with the other.

Usage:
  python demo/create_policies.py
"""
import sys
from pathlib import Path

import httpx

RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[32m"
RED   = "\033[31m"

BROKER_URL = "http://localhost:8000"

POLICIES = [
    {
        "org_id": "electrostore",
        "org_secret": "electrostore",
        "policy_id": "electrostore::session-chipfactory-v1",
        "target_org": "chipfactory",
        "capabilities": ["order.read", "order.write"],
    },
    {
        "org_id": "chipfactory",
        "org_secret": "chipfactory",
        "policy_id": "chipfactory::session-electrostore-v1",
        "target_org": "electrostore",
        "capabilities": ["order.read", "order.write"],
    },
]


def main():
    print(f"\n{BOLD}Creating session policies{RESET}\n")

    for p in POLICIES:
        resp = httpx.post(
            f"{BROKER_URL}/policy/rules",
            headers={"X-Org-Id": p["org_id"], "X-Org-Secret": p["org_secret"]},
            json={
                "policy_id": p["policy_id"],
                "org_id": p["org_id"],
                "policy_type": "session",
                "rules": {
                    "effect": "allow",
                    "conditions": {
                        "target_org_id": [p["target_org"]],
                        "capabilities": p["capabilities"],
                    },
                },
            },
            timeout=10,
        )
        if resp.status_code in (200, 201):
            print(f"  {GREEN}✓{RESET}  {p['org_id']} → {p['target_org']}  [{', '.join(p['capabilities'])}]")
        elif resp.status_code == 409:
            print(f"  {GREEN}✓{RESET}  {p['policy_id']} (already exists)")
        else:
            print(f"  {RED}✗{RESET}  {p['policy_id']} — HTTP {resp.status_code}: {resp.text}")
            sys.exit(1)

    print(f"\n{GREEN}{BOLD}Done.{RESET} Both orgs can now open sessions with each other.\n")


if __name__ == "__main__":
    main()
