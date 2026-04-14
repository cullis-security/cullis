"""FastMCP server assembly for cullis-connector."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from cullis_connector import __version__
from cullis_connector.config import ConnectorConfig
from cullis_connector.state import get_state
from cullis_connector.tools import register_all

_INSTRUCTIONS = (
    "Cullis Connector: bridge to the Cullis federated agent trust network. "
    "Use hello_site to verify reachability of the configured Cullis Site, "
    "then connect with credentials, discover agents on the network, open "
    "secure E2E-encrypted sessions, and exchange messages. "
    "Phase 1 build (v{version}) — device-code enrollment lands in Phase 2."
)


def build_server(config: ConnectorConfig) -> FastMCP:
    """Construct a fully-wired MCP server bound to the provided configuration."""
    state = get_state()
    state.config = config

    mcp = FastMCP(
        "Cullis",
        instructions=_INSTRUCTIONS.format(version=__version__),
    )
    register_all(mcp)
    return mcp
