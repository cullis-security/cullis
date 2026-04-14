"""Manual cert-based connection tool (Phase 1 transitional).

This mirrors the legacy ``cullis_sdk.mcp_server.cullis_connect`` tool so users
on the existing flow keep working while we build the Phase 2 device-code
enrollment. Once Phase 2 lands the connector will load identity automatically
from ``~/.cullis/identity/`` and this tool will be removed.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING

from cullis_connector._logging import get_logger
from cullis_connector.state import get_state

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_log = get_logger("tools.connect")


def register(mcp: "FastMCP") -> None:
    @mcp.tool()
    def connect(
        broker_url: str = "",
        agent_id: str = "",
        org_id: str = "",
        cert_path: str = "",
        key_path: str = "",
    ) -> str:
        """Connect to the Cullis network using a pre-issued certificate.

        Phase 1 transitional tool. Reads from CLI args, then env vars
        (BROKER_URL, AGENT_ID, ORG_ID, AGENT_CERT_PATH, AGENT_KEY_PATH),
        then site_url from the connector configuration.
        """
        from cullis_sdk import CullisClient  # imported lazily for test isolation

        state = get_state()

        broker = broker_url or os.environ.get("BROKER_URL", "")
        if not broker and state.config is not None:
            broker = state.config.site_url
        aid = agent_id or os.environ.get("AGENT_ID", "")
        oid = org_id or os.environ.get("ORG_ID", "")
        cp = cert_path or os.environ.get("AGENT_CERT_PATH", "")
        kp = key_path or os.environ.get("AGENT_KEY_PATH", "")

        if not broker:
            return "Error: broker_url or site_url is required"
        if not aid:
            return "Error: agent_id is required (or set AGENT_ID env var)"
        if not oid:
            return "Error: org_id is required (or set ORG_ID env var)"

        verify_tls = state.config.verify_tls if state.config is not None else True
        client = CullisClient(broker, verify_tls=verify_tls)

        try:
            vault_addr = os.environ.get("VAULT_ADDR", "")
            vault_token = os.environ.get("VAULT_TOKEN", "")
            if vault_addr and vault_token and not cp:
                import httpx

                resp = httpx.get(
                    f"{vault_addr}/v1/secret/data/agent",
                    headers={"X-Vault-Token": vault_token},
                    timeout=state.config.request_timeout_s if state.config else 10.0,
                )
                resp.raise_for_status()
                data = resp.json()["data"]["data"]
                client.login_from_pem(aid, oid, data["cert_pem"], data["private_key_pem"])
            elif cp and kp:
                client.login(aid, oid, cp, kp)
            else:
                return "Error: provide cert_path+key_path or VAULT_ADDR+VAULT_TOKEN"
        except Exception as exc:  # noqa: BLE001 - surface to LLM
            _log.warning("connect failed", extra={"agent_id": aid, "error": str(exc)})
            return f"Connection failed: {exc}"

        state.client = client
        state.agent_id = aid
        _log.info("connect ok", extra={"agent_id": aid, "org_id": oid, "broker": broker})
        return f"Connected as {aid} ({oid}) to {broker}"
