"""MCP tool modules for cullis-connector.

Tools are grouped by domain:
    diagnostic — health/version probes (no identity required)
    connect    — manual cert-based login (Phase 1 transitional, removed
                 once device-code enrollment lands in Phase 2)
    discovery  — discover_agents
    session    — session lifecycle: open, send, accept, close, list, etc.

The ``register_all`` helper wires every group to a FastMCP instance so the
server module stays a thin assembly point.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from cullis_connector.tools import connect, diagnostic, discovery, session

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def register_all(mcp: "FastMCP") -> None:
    diagnostic.register(mcp)
    connect.register(mcp)
    discovery.register(mcp)
    session.register(mcp)


__all__ = ["register_all"]
