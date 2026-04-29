"""High-level wrapper tools layered on top of the session primitives.

These three tools exist because driving an LLM through the explicit
open/send/poll/close dance is noisy and error-prone. The primitives in
``cullis_connector.tools.session`` are kept for power users and
debugging; these wrappers are the ones most agents should reach for.

* ``send_to_agent``    — one-shot open + send + optionally await + close
* ``await_response``   — poll a specific session for replies (does NOT
                         mutate the global ``active_session`` state)
* ``get_audit_trail``  — pull the server-side audit trail for a session

Design notes
------------

Unlike the primitives, ``send_to_agent`` and ``await_response`` do not
read from ``state.active_session`` for their core operation. They take
explicit session/peer identifiers so the LLM can fire-and-forget
exchanges without worrying about stomping on an ongoing conversation.

``get_audit_trail`` uses the Connector's enrolled proxy credentials
(TLS client cert at the handshake, ADR-014) to hit the Site's audit
read API.
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

_log = get_logger("tools.high_level")

# Shared tunables — kept small-but-not-tiny so humans running the tool
# from an LLM chat still see reasonable latency ceilings.
_ACCEPT_POLL_INTERVAL_S = 2.0
_ACCEPT_TIMEOUT_S = 15.0
_RESPONSE_POLL_INTERVAL_S = 2.0


def _require_client():
    state = get_state()
    if state.client is None or state.client.token is None:
        raise RuntimeError("Not connected. Use the connect tool first.")
    return state.client


def _wait_for_active(client, session_id: str, timeout_s: float) -> bool:
    """Poll list_sessions until ``session_id`` becomes active or the
    timeout elapses. Returns True on success, False on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        sessions = client.list_sessions()
        match = next((s for s in sessions if s.session_id == session_id), None)
        if match and match.status == "active":
            return True
        time.sleep(_ACCEPT_POLL_INTERVAL_S)
    return False


def _format_audit_entries(entries: list[dict]) -> str:
    if not entries:
        return "No audit entries for this session."
    lines = []
    for entry in entries:
        ts = entry.get("timestamp", "?")
        agent = entry.get("agent_id", "?")
        action = entry.get("action", "?")
        tool = entry.get("tool_name")
        stat = entry.get("status", "?")
        detail = entry.get("detail")
        dur = entry.get("duration_ms")

        parts = [f"[{ts}]", agent, action]
        if tool:
            parts.append(f"tool={tool}")
        parts.append(f"status={stat}")
        if dur is not None:
            parts.append(f"{dur:.1f}ms")
        if detail:
            parts.append(f"— {detail}")
        lines.append(" ".join(parts))
    return "\n".join(lines)


def register(mcp: "FastMCP") -> None:
    """Register high-level wrapper tools on the given FastMCP instance."""

    @mcp.tool()
    def send_to_agent(
        target_agent_id: str,
        target_org_id: str,
        capability: str,
        message: str,
        await_response: bool = True,
        timeout_s: int = 30,
    ) -> str:
        """Open a session, send a message, optionally wait for the first
        reply, and close. One-shot high-level wrapper for simple exchanges.

        Args:
            target_agent_id: Peer agent ID (e.g. ``chipfactory::sales``).
            target_org_id:   Peer organization ID.
            capability:      Single capability scoped to this session.
            message:         Plain-text payload to send.
            await_response:  If True (default), block for ``timeout_s`` waiting
                             for the first inbound message before closing.
            timeout_s:       Seconds to wait for the peer's first reply.

        Returns a human-readable summary with the session_id and (if
        await_response is True) the first response payload.
        """
        state = get_state()
        try:
            client = _require_client()
        except RuntimeError as exc:
            return f"Not connected: {exc}"

        caps = [capability] if capability else []

        # 1. Open the session.
        try:
            session_id = client.open_session(target_agent_id, target_org_id, caps)
        except Exception as exc:  # noqa: BLE001
            return f"Failed to open session: {exc}"

        # 2. Wait for peer to accept. If they don't accept inside the
        # acceptance window, close the session and return a clean error
        # instead of dangling the pending session forever.
        if not _wait_for_active(client, session_id, _ACCEPT_TIMEOUT_S):
            try:
                client.close_session(session_id)
            except Exception:  # noqa: BLE001
                pass
            return (
                f"Peer {target_agent_id} did not accept session "
                f"{session_id[:12]}... within {int(_ACCEPT_TIMEOUT_S)}s."
            )

        # 3. Send the message.
        try:
            client.send(
                session_id,
                state.agent_id,
                {"type": "message", "text": message},
                recipient_agent_id=target_agent_id,
            )
        except Exception as exc:  # noqa: BLE001
            try:
                client.close_session(session_id)
            except Exception:  # noqa: BLE001
                pass
            return f"Failed to send message on session {session_id[:12]}...: {exc}"

        # 4. Optionally wait for the first inbound reply.
        reply_summary = ""
        if await_response:
            deadline = time.monotonic() + max(1, int(timeout_s))
            replies: list = []
            while time.monotonic() < deadline:
                try:
                    messages = client.poll(session_id)
                except Exception as exc:  # noqa: BLE001
                    reply_summary = f"poll error: {exc}"
                    break
                if messages:
                    replies = messages
                    break
                time.sleep(_RESPONSE_POLL_INTERVAL_S)
            if replies:
                chunks = []
                for m in replies:
                    text_val = m.payload.get("text", json.dumps(m.payload))
                    chunks.append(f"[{m.sender_agent_id}]: {text_val}")
                reply_summary = "\n".join(chunks)
            elif not reply_summary:
                reply_summary = f"No reply within {int(timeout_s)}s."

        # 5. Close — always close, regardless of reply.
        try:
            client.close_session(session_id)
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "send_to_agent: close_session failed",
                extra={"session_id": session_id, "error": str(exc)},
            )

        header = f"Session {session_id[:12]}... exchange complete with {target_agent_id}."
        if reply_summary:
            return f"{header}\n{reply_summary}"
        return header

    @mcp.tool()
    def await_response(session_id: str, timeout_s: int = 30) -> str:
        """Poll a specific session for new incoming messages until one
        arrives or the timeout elapses. Does NOT change the active_session
        state — useful for checking on a background session without
        disturbing the current conversation.

        Args:
            session_id: Full session ID to poll.
            timeout_s:  Maximum seconds to wait.
        """
        try:
            client = _require_client()
        except RuntimeError as exc:
            return f"Not connected: {exc}"

        deadline = time.monotonic() + max(1, int(timeout_s))
        while time.monotonic() < deadline:
            try:
                messages = client.poll(session_id)
            except Exception as exc:  # noqa: BLE001
                return f"Failed to poll session {session_id[:12]}...: {exc}"
            if messages:
                lines = []
                for m in messages:
                    text_val = m.payload.get("text", json.dumps(m.payload))
                    lines.append(f"[{m.sender_agent_id}]: {text_val}")
                return "\n".join(lines)
            time.sleep(_RESPONSE_POLL_INTERVAL_S)

        return f"No response within {int(timeout_s)}s."

    @mcp.tool()
    def get_audit_trail(session_id: str) -> str:
        """Fetch the audit trail for a session from the Site. Returns
        timestamps, actions, and status for each step — useful for
        debugging failed exchanges or producing a compliance summary.

        Args:
            session_id: Session ID to audit.
        """
        state = get_state()
        cfg = state.config
        if cfg is None or not cfg.site_url:
            return (
                "Site URL is not configured. Pass --site-url or set "
                "CULLIS_SITE_URL before starting the connector."
            )

        try:
            client = _require_client()
        except RuntimeError as exc:
            return f"Not connected: {exc}"

        try:
            headers = client.proxy_headers()
        except RuntimeError as exc:
            return (
                "Audit fetch requires proxy enrollment (API key) but the "
                f"current client has none: {exc}"
            )

        url = f"{cfg.site_url}/v1/audit/session/{session_id}"
        try:
            resp = httpx.get(
                url,
                headers=headers,
                verify=cfg.verify_arg,
                timeout=cfg.request_timeout_s,
            )
        except httpx.HTTPError as exc:
            return f"Site unreachable at {cfg.site_url}: {exc}"

        if resp.status_code == 404:
            return f"No audit trail found for session {session_id[:12]}..."
        if resp.status_code == 403:
            return (
                f"Not authorized to read audit for session {session_id[:12]}..."
                " (you must be a peer of the session)."
            )
        if resp.status_code != 200:
            return (
                f"Audit API error HTTP {resp.status_code} at {url}: "
                f"{resp.text[:200]}"
            )

        try:
            entries = resp.json()
        except json.JSONDecodeError:
            return f"Audit API returned non-JSON body: {resp.text[:200]}"
        if not isinstance(entries, list):
            return f"Audit API returned unexpected shape: {type(entries).__name__}"

        header = (
            f"Audit trail for session {session_id[:12]}... "
            f"({len(entries)} entries):"
        )
        return header + "\n" + _format_audit_entries(entries)
