"""Sessionless one-shot tools (ADR-008 / ADR-011 Phase 4b).

These tools bypass the broker JWT path: API-key + DPoP authenticates
to the local Mastio's egress API, and the inner + outer envelope
signatures are produced locally from ``agent.key``. They work even
when ``login_via_proxy`` doesn't — for example after device-code
enrollment, where the private key never leaves the user's machine.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from cullis_connector._logging import get_logger
from cullis_connector.state import get_state
from cullis_connector.tools._identity import canonical_recipient
from cullis_connector.tools.session import _require_oneshot_client

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_log = get_logger("tools.oneshot")


# Backwards-compat aliases — earlier callers in this module imported the
# private helpers under their original underscore names.
_canonical_recipient = canonical_recipient


def register(mcp: "FastMCP") -> None:
    @mcp.tool()
    def send_oneshot(
        recipient_id: str,
        message: str,
        reply_to: str = "",
        correlation_id: str = "",
        ttl_seconds: int = 300,
        capabilities: str = "",
    ) -> str:
        """Send a fire-and-forget message to another agent — no session, no accept.

        Intra-org → signed plaintext (``mtls-only``). Cross-org → end-to-end
        encrypted envelope with inner + outer signatures. The local Mastio
        resolves the target and routes the message; the recipient picks it
        up via ``receive_oneshot``.

        Args:
            recipient_id: Fully-qualified target (e.g. ``chipfactory::sales``).
                Bare names resolve inside the sender's org.
            message: Plain-text body wrapped as ``{"type": "message",
                "text": message}`` — pass structured payloads via the SDK
                directly if you need a richer shape.
            reply_to: Inbox ``msg_id`` from a previously received one-shot
                — turns this send into a reply that the peer can correlate.
            correlation_id: Override the generated UUID (rare; use when the
                peer needs to tie this send to work it already started).
            ttl_seconds: Server-side expiry before the message is dropped
                if still undelivered. Default 300.
            capabilities: Comma-separated capabilities to tag on the
                envelope (informational; RBAC lives elsewhere).
        """
        client = _require_oneshot_client()
        state = get_state()
        caps = [c.strip() for c in capabilities.split(",") if c.strip()]
        canonical = _canonical_recipient(recipient_id)
        try:
            result = client.send_oneshot(
                canonical,
                {"type": "message", "text": message},
                correlation_id=correlation_id or None,
                reply_to=reply_to or None,
                ttl_seconds=ttl_seconds,
                capabilities=caps or None,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("send_oneshot to %s failed: %s", canonical, exc)
            return f"Failed to send one-shot to {canonical}: {exc}"

        state.last_correlation_id = result.get("correlation_id")
        return (
            f"One-shot {result.get('status', 'sent')} to {canonical} "
            f"(correlation_id={result.get('correlation_id')}, "
            f"msg_id={result.get('msg_id')})"
        )

    @mcp.tool()
    def receive_oneshot() -> str:
        """Pull and decrypt pending one-shot messages from the local inbox.

        Each entry includes the sender, correlation_id (for replies) and
        the decrypted payload. The inbox is non-destructive on the server
        side — callers are responsible for application-level dedup via
        ``correlation_id`` if they want at-most-once semantics.
        """
        client = _require_oneshot_client()
        try:
            rows = client.receive_oneshot()
        except Exception as exc:  # noqa: BLE001
            _log.warning("receive_oneshot failed: %s", exc)
            return f"Failed to fetch one-shot inbox: {exc}"
        if not rows:
            return "No one-shot messages."

        lines: list[str] = []
        state = get_state()
        last_decoded_sender: str | None = None
        last_decoded_msg_id: str | None = None
        for row in rows:
            sender = row.get("sender_agent_id", "?")
            corr = row.get("correlation_id", "?")
            reply_to = row.get("reply_to") or "—"
            msg_id = row.get("msg_id")
            try:
                decoded = client.decrypt_oneshot(
                    row, pubkey_fetcher=client.get_agent_public_key_via_egress,
                )
                payload = decoded.get("payload", {})
                if isinstance(payload, dict) and "text" in payload:
                    text = payload["text"]
                else:
                    text = json.dumps(payload)
                lines.append(
                    f"- [{sender}] corr={corr[:8]} reply_to={reply_to}: {text}"
                )
                # Threading hint for the intent-level reply() tool.
                # Track the LAST successfully decoded row — that's what
                # the user just read and will most plausibly want to
                # answer. Failed-decrypt rows don't update the cursor.
                if msg_id:
                    last_decoded_sender = (
                        sender if "::" in sender
                        else _canonical_recipient(sender)
                    )
                    last_decoded_msg_id = msg_id
            except Exception as exc:  # noqa: BLE001
                lines.append(
                    f"- [{sender}] corr={corr[:8]} reply_to={reply_to}: "
                    f"<decrypt failed: {exc}>"
                )

        if last_decoded_sender:
            state.last_peer_resolved = last_decoded_sender
            state.last_reply_to = last_decoded_msg_id

        return f"{len(rows)} one-shot message(s):\n" + "\n".join(lines)
