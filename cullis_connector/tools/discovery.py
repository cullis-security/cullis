"""Discovery tools for finding agents on the Cullis network."""
from __future__ import annotations

from typing import TYPE_CHECKING

from cullis_connector.state import get_state

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def _require_client():
    state = get_state()
    if state.client is None or state.client.token is None:
        raise RuntimeError("Not connected. Use the connect tool first.")
    return state.client


def register(mcp: "FastMCP") -> None:
    @mcp.tool()
    def discover_agents(
        q: str = "",
        capabilities: str = "",
        org_id: str = "",
        pattern: str = "",
    ) -> str:
        """Search for agents reachable on the Cullis network.

        Args:
            q: Free-text search across name, description, org, agent_id.
               Use '*' to list all agents the caller is authorized to see.
            capabilities: Comma-separated capabilities filter
                          (e.g. 'order.write,manufacturing').
            org_id: Filter to a specific organization.
            pattern: Glob on agent_id (e.g. 'chipfactory::*').
        """
        client = _require_client()
        caps = (
            [c.strip() for c in capabilities.split(",") if c.strip()]
            if capabilities
            else None
        )
        agents = client.discover(
            capabilities=caps,
            org_id=org_id or None,
            pattern=pattern or None,
            q=q or None,
        )
        if not agents:
            return "No agents found matching the search criteria."
        lines = []
        for agent in agents:
            line = f"- {agent.display_name} ({agent.agent_id}) org={agent.org_id}"
            if agent.description:
                line += f" — {agent.description}"
            if agent.capabilities:
                line += f" [caps: {', '.join(agent.capabilities)}]"
            lines.append(line)
        return f"Found {len(agents)} agent(s):\n" + "\n".join(lines)
