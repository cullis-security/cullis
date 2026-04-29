"""Diagnostic MCP tools that do not require an enrolled identity.

These tools are safe to call before Phase 2 enrollment lands: they let an
operator (or a curious LLM) verify that the connector can reach the
configured Site URL and read its health response.
"""
from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import httpx

from cullis_connector._logging import get_logger
from cullis_connector.state import get_state

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_log = get_logger("tools.diagnostic")


def register(mcp: "FastMCP") -> None:
    """Register diagnostic tools on the given FastMCP instance."""

    @mcp.tool()
    def hello_site() -> str:
        """Probe the configured Cullis Site for basic health.

        Use this to verify reachability and TLS configuration before
        attempting authenticated calls. Returns site status, version,
        and round-trip latency in milliseconds. No identity required.
        """
        cfg = get_state().config
        if cfg is None or not cfg.site_url:
            return (
                "Error: Cullis Site URL is not configured. "
                "Pass --site-url, set CULLIS_SITE_URL, or write site_url "
                "into ~/.cullis/config.yaml."
            )

        url = f"{cfg.site_url}/health"
        started = time.perf_counter()
        try:
            response = httpx.get(
                url,
                verify=cfg.verify_arg,
                timeout=cfg.request_timeout_s,
            )
        except httpx.HTTPError as exc:
            _log.warning("hello_site request failed", extra={"url": url, "error": str(exc)})
            return f"Site unreachable at {cfg.site_url}: {exc}"

        latency_ms = round((time.perf_counter() - started) * 1000, 1)

        if response.status_code != 200:
            return (
                f"Site responded with HTTP {response.status_code} at {url} "
                f"(latency {latency_ms} ms). Body: {response.text[:200]}"
            )

        try:
            payload = response.json()
        except json.JSONDecodeError:
            payload = {"raw": response.text[:200]}

        result = {
            "site_url": cfg.site_url,
            "site_status": payload.get("status", "unknown"),
            "site_version": payload.get("version", "unknown"),
            "latency_ms": latency_ms,
            "tls_verified": cfg.verify_arg is not False,
        }
        _log.info("hello_site ok", extra=result)
        return json.dumps(result, ensure_ascii=False)
