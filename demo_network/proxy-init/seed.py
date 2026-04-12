"""
Seed an MCP proxy's SQLite config DB so it boots pre-configured.

Normally the setup wizard in the proxy dashboard writes these rows after
the admin pastes an invite token. For non-interactive smoke runs we just
insert them directly, using the org CA + secret that bootstrap.py already
generated on the shared /state volume.

Env inputs:
  ORG_ID          e.g. "demo-org-a"
  BROKER_URL      e.g. "https://broker.cullis.test:8443"
  PROXY_PUBLIC_URL e.g. "https://proxy-a.cullis.test:8443"
  PROXY_DB_PATH   e.g. "/data/mcp_proxy.db"
  STATE_DIR       e.g. "/state"
"""
from __future__ import annotations

import asyncio
import os
import pathlib
import sys

import aiosqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS proxy_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

async def main() -> int:
    org_id         = os.environ["ORG_ID"]
    broker_url     = os.environ["BROKER_URL"]
    proxy_public   = os.environ["PROXY_PUBLIC_URL"]
    db_path        = os.environ.get("PROXY_DB_PATH", "/data/mcp_proxy.db")
    state          = pathlib.Path(os.environ.get("STATE_DIR", "/state"))

    org_dir = state / org_id
    ca_cert = (org_dir / "ca.pem").read_text()
    ca_key  = (org_dir / "ca-key.pem").read_text()
    secret  = (org_dir / "org_secret").read_text().strip()
    display = (org_dir / "display_name").read_text().strip()

    db_file = pathlib.Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(str(db_file)) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.executescript(_SCHEMA)

        rows = {
            "broker_url":    broker_url,
            "org_id":        org_id,
            "org_secret":    secret,
            "org_ca_cert":   ca_cert,
            "org_ca_key":    ca_key,
            "display_name":  display,
            "contact_email": f"admin@{org_id}.test",
            "webhook_url":   f"{proxy_public}/pdp/policy",
            "org_status":    "active",
        }

        # Optional PDP policy rules — passed as JSON via POLICY_RULES env var
        # so each proxy can have a different ruleset. Smoke configures
        # proxy-b with a blocked_agents list so the DENY branch of the
        # webhook path is exercised every run.
        policy_rules = os.environ.get("POLICY_RULES", "").strip()
        if policy_rules:
            rows["policy_rules"] = policy_rules
        for k, v in rows.items():
            await db.execute(
                "INSERT INTO proxy_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, v),
            )
        await db.commit()

    # Ensure proxyuser (uid varies but typically not root) can read the file.
    db_file.chmod(0o666)
    print(f"proxy-init: seeded {db_path} for {org_id} (keys: {', '.join(rows.keys())})")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
