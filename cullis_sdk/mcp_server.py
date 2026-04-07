"""
Cullis MCP Server — connect any MCP-compatible LLM to the Cullis network.

Run standalone:
    python -m cullis_sdk.mcp_server

Or configure in Claude Desktop / Claude Code as an MCP server.

Environment variables:
    BROKER_URL       — Broker address (required)
    AGENT_ID         — Agent identifier (required)
    ORG_ID           — Organization identifier (required)
    AGENT_CERT_PATH  — Path to PEM certificate (required unless using Vault)
    AGENT_KEY_PATH   — Path to PEM private key (required unless using Vault)
    VAULT_ADDR       — Vault address (optional, for credential loading)
    VAULT_TOKEN      — Vault token (optional)
"""
from __future__ import annotations

import json
import os
import sys

from mcp.server.fastmcp import FastMCP

from cullis_sdk import CullisClient

# ── MCP Server ────────────────────────────────────────────────────────────

mcp = FastMCP(
    "Cullis",
    instructions="Connect to the Cullis federated agent trust network. "
    "Discover agents, open secure sessions, exchange E2E-encrypted messages.",
)

# Global client — initialized by connect tool or at startup
_client: CullisClient | None = None
_agent_id: str = ""
_active_session: str | None = None
_active_peer: str | None = None


def _get_client() -> CullisClient:
    if _client is None or _client.token is None:
        raise RuntimeError("Not connected. Use the cullis_connect tool first.")
    return _client


# ── Tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def cullis_connect(
    broker_url: str = "",
    agent_id: str = "",
    org_id: str = "",
    cert_path: str = "",
    key_path: str = "",
) -> str:
    """Connect to the Cullis broker. Uses environment variables as defaults.
    Call this first before using other Cullis tools."""
    global _client, _agent_id

    broker = broker_url or os.environ.get("BROKER_URL", "")
    aid = agent_id or os.environ.get("AGENT_ID", "")
    oid = org_id or os.environ.get("ORG_ID", "")
    cp = cert_path or os.environ.get("AGENT_CERT_PATH", "")
    kp = key_path or os.environ.get("AGENT_KEY_PATH", "")

    if not broker:
        return "Error: broker_url is required (or set BROKER_URL env var)"
    if not aid:
        return "Error: agent_id is required (or set AGENT_ID env var)"
    if not oid:
        return "Error: org_id is required (or set ORG_ID env var)"

    try:
        client = CullisClient(broker, verify_tls=False)

        # Try Vault first if configured
        vault_addr = os.environ.get("VAULT_ADDR", "")
        vault_token = os.environ.get("VAULT_TOKEN", "")
        if vault_addr and vault_token and not cp:
            import httpx
            resp = httpx.get(
                f"{vault_addr}/v1/secret/data/agent",
                headers={"X-Vault-Token": vault_token},
            )
            resp.raise_for_status()
            data = resp.json()["data"]["data"]
            client.login_from_pem(aid, oid, data["cert_pem"], data["private_key_pem"])
        elif cp and kp:
            client.login(aid, oid, cp, kp)
        else:
            return "Error: provide cert_path+key_path or configure VAULT_ADDR+VAULT_TOKEN"

        _client = client
        _agent_id = aid
        return f"Connected as {aid} ({oid}) to {broker}"
    except Exception as e:
        return f"Connection failed: {e}"


@mcp.tool()
def cullis_discover(
    q: str = "",
    capabilities: str = "",
    org_id: str = "",
    pattern: str = "",
) -> str:
    """Search for agents in the Cullis network.

    Args:
        q: Free-text search across agent name, description, org, agent_id. Use '*' to list all.
        capabilities: Comma-separated capabilities filter, e.g. 'order.write,manufacturing'
        org_id: Filter by organization ID
        pattern: Glob pattern on agent_id, e.g. 'chipfactory::*'
    """
    client = _get_client()
    caps = [c.strip() for c in capabilities.split(",") if c.strip()] if capabilities else None
    agents = client.discover(
        capabilities=caps,
        org_id=org_id or None,
        pattern=pattern or None,
        q=q or None,
    )
    if not agents:
        return "No agents found matching the search criteria."
    lines = []
    for a in agents:
        line = f"- {a.display_name} ({a.agent_id}) org={a.org_id}"
        if a.description:
            line += f" — {a.description}"
        if a.capabilities:
            line += f" [caps: {', '.join(a.capabilities)}]"
        lines.append(line)
    return f"Found {len(agents)} agent(s):\n" + "\n".join(lines)


@mcp.tool()
def cullis_open_session(
    target_agent_id: str,
    target_org_id: str,
    capabilities: str = "chat",
) -> str:
    """Open a secure session with another agent on the Cullis network.

    Args:
        target_agent_id: The agent to connect to (e.g. 'chipfactory::sales')
        target_org_id: The agent's organization (e.g. 'chipfactory')
        capabilities: Comma-separated capabilities for this session
    """
    global _active_session, _active_peer
    client = _get_client()
    caps = [c.strip() for c in capabilities.split(",")]
    try:
        session_id = client.open_session(target_agent_id, target_org_id, caps)
        _active_session = session_id
        _active_peer = target_agent_id

        # Wait for acceptance (up to 30s)
        import time
        for _ in range(15):
            sessions = client.list_sessions()
            s = next((x for x in sessions if x.session_id == session_id), None)
            if s and s.status == "active":
                return f"Session {session_id[:12]}... active with {target_agent_id}"
            time.sleep(2)

        return f"Session {session_id[:12]}... created but not yet accepted. Use cullis_check_responses to poll."
    except Exception as e:
        return f"Failed to open session: {e}"


@mcp.tool()
def cullis_send(message: str) -> str:
    """Send an E2E-encrypted message in the active session.

    Args:
        message: The message text to send
    """
    client = _get_client()
    if not _active_session or not _active_peer:
        return "No active session. Use cullis_open_session first."
    try:
        client.send(
            _active_session, _agent_id,
            {"type": "message", "text": message},
            recipient_agent_id=_active_peer,
        )
        return f"Message sent to {_active_peer}."
    except Exception as e:
        return f"Failed to send: {e}"


@mcp.tool()
def cullis_check_responses() -> str:
    """Check for new messages from the peer agent in the active session."""
    client = _get_client()
    if not _active_session:
        return "No active session."
    try:
        messages = client.poll(_active_session)
        if not messages:
            return "No new messages."
        lines = []
        for m in messages:
            text = m.payload.get("text", json.dumps(m.payload))
            lines.append(f"[{m.sender_agent_id}]: {text}")
        return "\n".join(lines)
    except Exception as e:
        return f"Failed to poll: {e}"


@mcp.tool()
def cullis_check_pending() -> str:
    """Check for incoming session requests from other agents."""
    client = _get_client()
    try:
        sessions = client.list_sessions(status="pending")
        pending = [s for s in sessions if s.target_agent_id == _agent_id]
        if not pending:
            return "No pending session requests."
        lines = []
        for s in pending:
            lines.append(f"- Session {s.session_id[:12]}... from {s.initiator_agent_id} ({s.initiator_org_id})")
        return f"{len(pending)} pending request(s):\n" + "\n".join(lines)
    except Exception as e:
        return f"Failed to check: {e}"


@mcp.tool()
def cullis_accept_session(session_id: str) -> str:
    """Accept an incoming session request.

    Args:
        session_id: The session ID to accept (can be partial, will match prefix)
    """
    global _active_session, _active_peer
    client = _get_client()
    try:
        # Support partial session IDs
        if len(session_id) < 36:
            sessions = client.list_sessions(status="pending")
            match = next((s for s in sessions if s.session_id.startswith(session_id)), None)
            if not match:
                return f"No pending session matching '{session_id}'"
            session_id = match.session_id

        client.accept_session(session_id)

        # Find the peer
        sessions = client.list_sessions()
        s = next((x for x in sessions if x.session_id == session_id), None)
        if s:
            _active_session = session_id
            _active_peer = s.initiator_agent_id
            return f"Session accepted. Now active with {s.initiator_agent_id} ({s.initiator_org_id})"
        _active_session = session_id
        return f"Session {session_id[:12]}... accepted."
    except Exception as e:
        return f"Failed to accept: {e}"


@mcp.tool()
def cullis_close_session() -> str:
    """Close the active session."""
    global _active_session, _active_peer
    client = _get_client()
    if not _active_session:
        return "No active session."
    try:
        client.close_session(_active_session)
        peer = _active_peer
        _active_session = None
        _active_peer = None
        return f"Session with {peer} closed."
    except Exception as e:
        return f"Failed to close: {e}"


@mcp.tool()
def cullis_list_sessions() -> str:
    """List all sessions (active, pending, closed)."""
    client = _get_client()
    try:
        sessions = client.list_sessions()
        if not sessions:
            return "No sessions."
        lines = []
        for s in sessions:
            peer = s.target_agent_id if s.initiator_agent_id == _agent_id else s.initiator_agent_id
            marker = " ← active" if s.session_id == _active_session else ""
            lines.append(f"- [{s.status}] {s.session_id[:12]}... with {peer}{marker}")
        return "\n".join(lines)
    except Exception as e:
        return f"Failed to list: {e}"


@mcp.tool()
def cullis_select_session(session_id: str) -> str:
    """Switch the active session.

    Args:
        session_id: The session ID to switch to (can be partial)
    """
    global _active_session, _active_peer
    client = _get_client()
    try:
        sessions = client.list_sessions()
        match = next((s for s in sessions if s.session_id.startswith(session_id)), None)
        if not match:
            return f"No session matching '{session_id}'"
        _active_session = match.session_id
        peer = match.target_agent_id if match.initiator_agent_id == _agent_id else match.initiator_agent_id
        _active_peer = peer
        return f"Switched to session {match.session_id[:12]}... with {peer} [{match.status}]"
    except Exception as e:
        return f"Failed to switch: {e}"


# ── Entry point ───────────────────────────────────────────────────────────

def main():
    """Run the MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
