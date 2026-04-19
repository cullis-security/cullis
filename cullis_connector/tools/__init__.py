"""MCP tool modules for cullis-connector.

Tools are grouped by domain:
    diagnostic — health/version probes (no identity required)
    discovery  — discover_agents
    session    — session lifecycle: open, send, accept, close, list, etc.
    oneshot    — sessionless send/receive (ADR-008 / ADR-011 Phase 4b)

The ``register_all`` helper wires every group to a FastMCP instance so the
server module stays a thin assembly point. Identity is loaded by the CLI
before the server starts — tools receive a live ``CullisClient`` from
``cullis_connector.state``; the legacy ``connect`` tool from Phase 1 was
removed once the enrollment flow landed.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from cullis_connector.tools import diagnostic, discovery, high_level, oneshot, session

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def register_all(mcp: "FastMCP") -> None:
    diagnostic.register(mcp)
    discovery.register(mcp)
    session.register(mcp)
    oneshot.register(mcp)
    high_level.register(mcp)


__all__ = ["register_all"]
