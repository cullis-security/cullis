"""Seed an MCP proxy's SQLite config DB for the enterprise sandbox.

Runs Alembic migrations first (so ADR-007 tables exist), then seeds
proxy_config rows + optional MCP resources with agent bindings.

Env inputs:
  ORG_ID, BROKER_URL, PROXY_PUBLIC_URL, PROXY_DB_PATH, STATE_DIR
  OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET  (optional)
  POLICY_RULES                                           (optional JSON)

  SEED_MCP_RESOURCES       "1" to enable MCP resource seeding
  SEED_MCP_0_NAME          resource name, e.g. "catalog"
  SEED_MCP_0_ENDPOINT      endpoint URL, e.g. "http://mcp-catalog:9300/"
  SEED_MCP_0_AGENTS        comma-separated agent_ids to bind
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

_ALEMBIC_INI = pathlib.Path("/app/mcp_proxy/alembic.ini")


def _run_alembic_upgrade(db_url: str) -> None:
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")


async def _seed_proxy_config(db_url: str, org_id: str) -> None:
    broker_url = os.environ["BROKER_URL"]
    proxy_public = os.environ["PROXY_PUBLIC_URL"]
    state = pathlib.Path(os.environ.get("STATE_DIR", "/state"))
    org_dir = state / org_id
    ca_cert = (org_dir / "ca.pem").read_text()
    ca_key = (org_dir / "ca-key.pem").read_text()
    secret = (org_dir / "org_secret").read_text().strip()
    display = (org_dir / "display_name").read_text().strip()

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
    policy_rules = os.environ.get("POLICY_RULES", "").strip()
    if policy_rules:
        rows["policy_rules"] = policy_rules

    oidc_issuer = os.environ.get("OIDC_ISSUER_URL", "").strip()
    oidc_client = os.environ.get("OIDC_CLIENT_ID", "").strip()
    oidc_secret = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
    if oidc_issuer and oidc_client:
        rows["oidc_issuer_url"] = oidc_issuer
        rows["oidc_client_id"] = oidc_client
        if oidc_secret:
            rows["oidc_client_secret"] = oidc_secret

    engine = create_async_engine(db_url)
    try:
        async with engine.begin() as conn:
            for k, v in rows.items():
                await conn.execute(
                    text(
                        "INSERT INTO proxy_config (key, value) "
                        "VALUES (:k, :v) "
                        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
                    ),
                    {"k": k, "v": v},
                )
    finally:
        await engine.dispose()
    print(f"proxy-init: seeded proxy_config for {org_id}", flush=True)


async def _seed_mcp_resources(db_url: str, org_id: str) -> None:
    """Seed numbered MCP resources from SEED_MCP_N_* env vars."""
    now = datetime.now(timezone.utc).isoformat()
    engine = create_async_engine(db_url)
    try:
        idx = 0
        while True:
            name = os.environ.get(f"SEED_MCP_{idx}_NAME", "").strip()
            endpoint = os.environ.get(f"SEED_MCP_{idx}_ENDPOINT", "").strip()
            agents_csv = os.environ.get(f"SEED_MCP_{idx}_AGENTS", "").strip()
            if not name or not endpoint:
                break

            host = urlparse(endpoint).hostname or name
            allowed = json.dumps([host], separators=(",", ":"))

            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        """
                        INSERT INTO local_mcp_resources (
                            resource_id, org_id, name, description, endpoint_url,
                            auth_type, auth_secret_ref, required_capability,
                            allowed_domains, enabled, created_at, updated_at
                        ) VALUES (
                            :rid, :org, :name, :desc, :endpoint,
                            'none', NULL, NULL, :allowed, 1, :now, :now
                        )
                        ON CONFLICT (org_id, name) DO UPDATE SET
                            endpoint_url    = EXCLUDED.endpoint_url,
                            allowed_domains = EXCLUDED.allowed_domains,
                            enabled         = 1,
                            updated_at      = EXCLUDED.updated_at
                        """
                    ),
                    {
                        "rid": str(uuid.uuid4()),
                        "org": org_id,
                        "name": name,
                        "desc": f"Enterprise sandbox MCP server: {name}",
                        "endpoint": endpoint,
                        "allowed": allowed,
                        "now": now,
                    },
                )
                row = (await conn.execute(
                    text(
                        "SELECT resource_id FROM local_mcp_resources "
                        "WHERE org_id = :org AND name = :name"
                    ),
                    {"org": org_id, "name": name},
                )).first()
                if row is None:
                    raise RuntimeError(f"failed to locate resource {name}")
                resource_id = row[0]

                for agent_id in agents_csv.split(","):
                    agent_id = agent_id.strip()
                    if not agent_id:
                        continue
                    await conn.execute(
                        text(
                            """
                            INSERT INTO local_agent_resource_bindings (
                                binding_id, agent_id, resource_id, org_id,
                                granted_by, granted_at, revoked_at
                            ) VALUES (
                                :bid, :aid, :rid, :org,
                                'proxy-init-seed', :now, NULL
                            )
                            ON CONFLICT (agent_id, resource_id) DO UPDATE SET
                                revoked_at = NULL
                            """
                        ),
                        {
                            "bid": str(uuid.uuid4()),
                            "aid": agent_id,
                            "rid": resource_id,
                            "org": org_id,
                            "now": now,
                        },
                    )
                    print(
                        f"proxy-init: bound MCP resource {name} → {agent_id}",
                        flush=True,
                    )
            idx += 1
    finally:
        await engine.dispose()


async def _seed_internal_agents(db_url: str, org_id: str) -> None:
    """Populate ``internal_agents`` so the Mastio dashboard shows the
    SPIRE/BYOCA workloads that live in this org.

    Production agents hit the Mastio via the Connector enrollment flow,
    which writes an ``api_key_hash`` row here. Sandbox SPIRE/BYOCA
    agents bypass the Connector — they authenticate to the Court
    directly through the reverse-proxy with their own cert — so their
    ``internal_agents`` row stays empty and the Mastio dashboard looks
    broken. Seed them from ``/state/{org}/{agent_name}.pem`` (persisted
    by bootstrap phase 4) so the dashboard matches the reality of
    who lives on this org.
    """
    state = pathlib.Path(os.environ.get("STATE_DIR", "/state"))
    agents_dir = state / org_id / "agents"
    if not agents_dir.exists():
        return

    now = datetime.now(timezone.utc).isoformat()
    engine = create_async_engine(db_url)
    try:
        # Bootstrap writes ``{org}/agents/{agent}/agent.pem`` per phase 4.
        for agent_subdir in sorted(p for p in agents_dir.iterdir() if p.is_dir()):
            cert_path = agent_subdir / "agent.pem"
            if not cert_path.exists():
                continue
            agent_name = agent_subdir.name
            agent_id = f"{org_id}::{agent_name}"
            cert_pem = cert_path.read_text()
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        """
                        INSERT INTO internal_agents (
                            agent_id, display_name, capabilities,
                            api_key_hash, cert_pem, created_at, is_active
                        ) VALUES (
                            :aid, :name, :caps, :hash, :cert, :now, 1
                        )
                        ON CONFLICT (agent_id) DO UPDATE SET
                            cert_pem   = EXCLUDED.cert_pem,
                            is_active  = 1
                        """
                    ),
                    {
                        "aid": agent_id,
                        "name": agent_name,
                        "caps": json.dumps([]),
                        # Unreachable bcrypt hash — these agents don't use
                        # API keys (they auth via cert through the
                        # reverse-proxy). Column is NOT NULL so we still
                        # store a placeholder that no plaintext can match.
                        "hash": "$2b$12$sandbox.placeholder.no.api.key.enrolled."
                                "aaaaaaaaaaaaaaaaaaaaaaa",
                        "cert": cert_pem,
                        "now": now,
                    },
                )
            print(
                f"proxy-init: seeded internal_agents row for {agent_id}",
                flush=True,
            )
    finally:
        await engine.dispose()


async def _async_main(db_url: str, org_id: str) -> int:
    await _seed_proxy_config(db_url, org_id)
    if os.environ.get("SEED_MCP_RESOURCES") == "1":
        await _seed_mcp_resources(db_url, org_id)
    await _seed_internal_agents(db_url, org_id)
    return 0


def main() -> int:
    org_id = os.environ["ORG_ID"]
    db_path = os.environ.get("PROXY_DB_PATH", "/data/mcp_proxy.db")

    db_file = pathlib.Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    db_url = os.environ.get("PROXY_DB_URL") or f"sqlite+aiosqlite:///{db_path}"
    _run_alembic_upgrade(db_url)

    rc = asyncio.run(_async_main(db_url, org_id))

    if db_url.startswith("sqlite"):
        db_file.chmod(0o666)

    print(f"proxy-init: done ({org_id})", flush=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
