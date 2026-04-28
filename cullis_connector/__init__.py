"""
cullis-connector — MCP server bridging local MCP clients to the Cullis network.

Cullis Connector is the user-side component of the Cullis architecture (alongside
Cullis Site and Cullis Broker). It runs on the user's machine inside any MCP
client (Claude Code, Cursor, Claude Desktop, ToolHive, etc.) and exposes
network operations as MCP tools.

Run standalone::

    python -m cullis_connector --site-url https://cullis-site.acme.local

Or configure in your MCP client of choice. See README for examples.
"""

__version__ = "0.3.4"
__all__ = ["__version__"]
