"""Session lifecycle tools: open, send, receive, accept, close, list, switch."""
from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

from cullis_connector._logging import get_logger
from cullis_connector.state import get_state

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_log = get_logger("tools.session")


def _require_client():
    """Return a client with a valid broker JWT, minting one if absent.

    Device-code enrollment leaves the agent private key on the user's
    machine, so ``login_via_proxy()`` 404s ("agent credentials not
    available on proxy") when the Mastio tries to sign the assertion
    on the agent's behalf. We still call it because BYOCA/Mastio-held-key
    deployments work fine and we don't want to hard-code that split;
    callers see the same user-visible error regardless.
    """
    state = get_state()
    if state.client is None:
        raise RuntimeError(
            "Connector client not initialized — identity missing or unreadable. "
            "Re-run enrollment via the Connector dashboard."
        )
    if state.client.token is None:
        try:
            state.client.login_via_proxy()
        except Exception as exc:  # noqa: BLE001
            _log.warning("lazy login_via_proxy failed: %s", exc)
            raise RuntimeError(
                f"Session tools require a broker JWT, but login_via_proxy failed: "
                f"{exc}. If you enrolled via the dashboard (device-code), the "
                f"Mastio doesn't hold your private key so this path 404s — use "
                f"send_oneshot for fire-and-forget messages instead."
            ) from exc
    return state.client


def _require_oneshot_client():
    """Client for API-key + DPoP + local-signature one-shot sends.

    Does *not* need a broker JWT — ``send_oneshot`` talks to the local
    Mastio's egress API with API-key/DPoP only, and signs the inner +
    outer envelope locally with ``_signing_key_pem``.
    """
    state = get_state()
    if state.client is None:
        raise RuntimeError(
            "Connector client not initialized — identity missing or unreadable. "
            "Re-run enrollment via the Connector dashboard."
        )
    if not getattr(state.client, "_signing_key_pem", None):
        raise RuntimeError(
            "Agent signing key not loaded — send_oneshot needs the private key "
            "at ~/.cullis/identity/agent.key. Re-run enrollment if missing."
        )
    return state.client


def register(mcp: "FastMCP") -> None:
    @mcp.tool()
    def open_session(
        target_agent_id: str,
        target_org_id: str,
        capabilities: str = "chat",
    ) -> str:
        """Open a secure E2E-encrypted session with another agent.

        Args:
            target_agent_id: Target agent (e.g. 'chipfactory::sales').
            target_org_id: Target organization (e.g. 'chipfactory').
            capabilities: Comma-separated capabilities scoped to this session.
        """
        state = get_state()
        client = _require_client()
        caps = [c.strip() for c in capabilities.split(",") if c.strip()]
        try:
            session_id = client.open_session(target_agent_id, target_org_id, caps)
            state.active_session = session_id
            state.active_peer = target_agent_id

            for _ in range(15):
                sessions = client.list_sessions()
                match = next((x for x in sessions if x.session_id == session_id), None)
                if match and match.status == "active":
                    return f"Session {session_id[:12]}... active with {target_agent_id}"
                time.sleep(2)

            return (
                f"Session {session_id[:12]}... created but not yet accepted. "
                "Use check_responses to poll."
            )
        except Exception as exc:  # noqa: BLE001
            return f"Failed to open session: {exc}"

    @mcp.tool()
    def send_message(message: str) -> str:
        """Send an E2E-encrypted message in the active session.

        Args:
            message: Plain-text payload to send to the active peer.
        """
        state = get_state()
        client = _require_client()
        if not state.active_session or not state.active_peer:
            return "No active session. Use open_session first."
        try:
            client.send(
                state.active_session,
                state.agent_id,
                {"type": "message", "text": message},
                recipient_agent_id=state.active_peer,
            )
        except Exception as exc:  # noqa: BLE001
            return f"Failed to send: {exc}"
        return f"Message sent to {state.active_peer}."

    @mcp.tool()
    def check_responses() -> str:
        """Poll for new messages from the peer in the active session."""
        state = get_state()
        client = _require_client()
        if not state.active_session:
            return "No active session."
        try:
            messages = client.poll(state.active_session)
        except Exception as exc:  # noqa: BLE001
            return f"Failed to poll: {exc}"
        if not messages:
            return "No new messages."
        lines = []
        for message in messages:
            text = message.payload.get("text", json.dumps(message.payload))
            lines.append(f"[{message.sender_agent_id}]: {text}")
        return "\n".join(lines)

    @mcp.tool()
    def list_pending_sessions() -> str:
        """List inbound session requests awaiting acceptance."""
        state = get_state()
        client = _require_client()
        try:
            sessions = client.list_sessions(status="pending")
        except Exception as exc:  # noqa: BLE001
            return f"Failed to check: {exc}"
        pending = [s for s in sessions if s.target_agent_id == state.agent_id]
        if not pending:
            return "No pending session requests."
        lines = [
            f"- Session {s.session_id[:12]}... from {s.initiator_agent_id} ({s.initiator_org_id})"
            for s in pending
        ]
        return f"{len(pending)} pending request(s):\n" + "\n".join(lines)

    @mcp.tool()
    def accept_session(session_id: str) -> str:
        """Accept an incoming session request.

        Args:
            session_id: Full or prefix match of the session ID to accept.
        """
        state = get_state()
        client = _require_client()
        try:
            if len(session_id) < 36:
                pendings = client.list_sessions(status="pending")
                match = next((s for s in pendings if s.session_id.startswith(session_id)), None)
                if not match:
                    return f"No pending session matching '{session_id}'"
                session_id = match.session_id
            client.accept_session(session_id)
            sessions = client.list_sessions()
            match = next((x for x in sessions if x.session_id == session_id), None)
            if match:
                state.active_session = session_id
                state.active_peer = match.initiator_agent_id
                return (
                    f"Session accepted. Now active with "
                    f"{match.initiator_agent_id} ({match.initiator_org_id})"
                )
            state.active_session = session_id
            return f"Session {session_id[:12]}... accepted."
        except Exception as exc:  # noqa: BLE001
            return f"Failed to accept: {exc}"

    @mcp.tool()
    def close_session() -> str:
        """Close the currently active session."""
        state = get_state()
        client = _require_client()
        if not state.active_session:
            return "No active session."
        try:
            client.close_session(state.active_session)
        except Exception as exc:  # noqa: BLE001
            return f"Failed to close: {exc}"
        peer = state.active_peer
        state.active_session = None
        state.active_peer = None
        return f"Session with {peer} closed."

    @mcp.tool()
    def list_sessions() -> str:
        """List all sessions (active, pending, closed) for this agent."""
        state = get_state()
        client = _require_client()
        try:
            sessions = client.list_sessions()
        except Exception as exc:  # noqa: BLE001
            return f"Failed to list: {exc}"
        if not sessions:
            return "No sessions."
        lines = []
        for sess in sessions:
            peer = (
                sess.target_agent_id
                if sess.initiator_agent_id == state.agent_id
                else sess.initiator_agent_id
            )
            marker = " ← active" if sess.session_id == state.active_session else ""
            lines.append(f"- [{sess.status}] {sess.session_id[:12]}... with {peer}{marker}")
        return "\n".join(lines)

    @mcp.tool()
    def select_session(session_id: str) -> str:
        """Switch the active session to another existing session.

        Args:
            session_id: Full or prefix match of the session to select.
        """
        state = get_state()
        client = _require_client()
        try:
            sessions = client.list_sessions()
        except Exception as exc:  # noqa: BLE001
            return f"Failed to switch: {exc}"
        match = next((s for s in sessions if s.session_id.startswith(session_id)), None)
        if not match:
            return f"No session matching '{session_id}'"
        state.active_session = match.session_id
        peer = (
            match.target_agent_id
            if match.initiator_agent_id == state.agent_id
            else match.initiator_agent_id
        )
        state.active_peer = peer
        return f"Switched to session {match.session_id[:12]}... with {peer} [{match.status}]"
