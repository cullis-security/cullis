"""Sessionless one-shot tools (ADR-008 / ADR-011 Phase 4b).

These tools bypass the broker JWT path: API-key + DPoP authenticates
to the local Mastio's egress API, and the inner + outer envelope
signatures are produced locally from ``agent.key``. They work even
when ``login_via_proxy`` doesn't — for example after device-code
enrollment, where the private key never leaves the user's machine.
"""
from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

from cryptography import x509

from cullis_connector._logging import get_logger
from cullis_connector.state import get_state
from cullis_connector.tools.session import _require_oneshot_client

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_log = get_logger("tools.oneshot")


def _own_org_id() -> str | None:
    """Return the sender's org_id from the loaded identity's cert subject.

    The Mastio's ``/v1/egress/resolve`` rejects bare recipient names —
    it needs ``org::agent``. Enrollment writes the agent's cert with
    ``O=<org_id>`` so we can recover the sender's org even when
    ``metadata.json`` stored only the short agent_id.
    """
    state = get_state()
    identity = state.extra.get("identity")
    cert = getattr(identity, "cert", None)
    if cert is None:
        return None
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if not attrs:
        return None
    return attrs[0].value or None


def _canonical_recipient(recipient_id: str) -> str:
    """Prefix the sender's org when the caller gave a bare agent name."""
    if "::" in recipient_id:
        return recipient_id
    org = _own_org_id()
    if not org:
        return recipient_id
    return f"{org}::{recipient_id}"


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
        for row in rows:
            sender = row.get("sender_agent_id", "?")
            corr = row.get("correlation_id", "?")
            reply_to = row.get("reply_to") or "—"
            try:
                _prime_sender_pubkey_cache(client, sender)
                decoded = client.decrypt_oneshot(row)
                payload = decoded.get("payload", {})
                if isinstance(payload, dict) and "text" in payload:
                    text = payload["text"]
                else:
                    text = json.dumps(payload)
                lines.append(
                    f"- [{sender}] corr={corr[:8]} reply_to={reply_to}: {text}"
                )
            except Exception as exc:  # noqa: BLE001
                lines.append(
                    f"- [{sender}] corr={corr[:8]} reply_to={reply_to}: "
                    f"<decrypt failed: {exc}>"
                )
        return f"{len(rows)} one-shot message(s):\n" + "\n".join(lines)


def _prime_sender_pubkey_cache(client, sender: str) -> None:
    """Seed the SDK's pubkey cache with the sender's cert via the proxy's
    resolve endpoint.

    ``CullisClient.decrypt_oneshot`` looks up the sender's cert through
    ``get_agent_public_key``, which defaults to hitting the Court's
    federation API — that path needs a broker JWT we don't have under
    device-code enrollment. The local Mastio already knows the cert
    (it just served it to ``send_oneshot``), so we ask ``/v1/egress/resolve``
    for the same row and populate the cache directly. No-op on cache
    hit, and failures are swallowed so ``decrypt_oneshot`` still runs
    (and surfaces the clearer downstream error if it genuinely can't
    verify).
    """
    canonical = sender if "::" in sender else _canonical_recipient(sender)
    cache = getattr(client, "_pubkey_cache", None)
    if cache is None or canonical in cache:
        return
    try:
        resp = client._egress_http(
            "post",
            "/v1/egress/resolve",
            json={"recipient_id": canonical},
        )
        resp.raise_for_status()
        cert = resp.json().get("target_cert_pem")
    except Exception as exc:  # noqa: BLE001
        _log.debug("pubkey cache prime for %s failed: %s", canonical, exc)
        return
    if cert:
        cache[canonical] = (cert, time.time())
        # The SDK keys ``_pubkey_cache`` by the same id passed to
        # ``get_agent_public_key``; decrypt_oneshot uses the raw
        # ``sender`` from the inbox row, so mirror the entry under
        # the bare handle too when the two differ.
        if sender != canonical:
            cache[sender] = (cert, time.time())
