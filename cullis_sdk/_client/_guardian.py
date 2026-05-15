"""Guardian inspection support extracted from :mod:`cullis_sdk.client`.

Single public symbol:

* :class:`_GuardianMixin` — mixin folded into ``CullisClient`` that
  implements the ADR-016 Phase 3 cooperation hook. The SDK calls the
  local Mastio's ``/v1/guardian/inspect`` before encrypting on send and
  after decrypting on deliver. NO-OP unless ``CULLIS_GUARDIAN_ENABLED=1``.

Movement only — no behavior change. The mixin assumes the host class
exposes ``_egress_http`` (i.e. the existing ``CullisClient`` method).
"""
from __future__ import annotations

import json
import os

from cullis_sdk.guardian.client import (
    InspectionDecision,
    _build_body as _guardian_build_body,
    _enabled as _guardian_enabled,
    _no_op_decision as _guardian_no_op,
    _parse_response as _guardian_parse_response,
)


class _GuardianMixin:
    """ADR-016 Phase 3 Guardian cooperation hook on ``CullisClient``.

    The SDK calls the local Mastio's ``/v1/guardian/inspect`` before
    encrypting on send and after decrypting on deliver. NO-OP unless
    ``CULLIS_GUARDIAN_ENABLED=1`` (existing deployments unaffected).
    Routed through ``_egress_http`` so DPoP + mTLS are reused; the
    guardian endpoint sits behind the same auth dep as ``/v1/egress/*``.
    """

    def _guardian_inspect(
        self,
        *,
        direction: str,
        payload_bytes: bytes,
        peer_agent_id: str,
        msg_id: str,
        content_type: str = "application/json+a2a-payload",
    ) -> InspectionDecision:
        if not _guardian_enabled():
            return _guardian_no_op()
        body = _guardian_build_body(
            direction=direction,
            payload=payload_bytes,
            peer_agent_id=peer_agent_id,
            msg_id=msg_id,
            content_type=content_type,
        )
        resp = self._egress_http(
            "post", "/v1/guardian/inspect", json=body,
        )
        try:
            json_body = resp.json()
        except ValueError:
            json_body = None
        return _guardian_parse_response(
            status_code=resp.status_code,
            text=getattr(resp, "text", "") or "",
            json_body=json_body,
            direction=direction,
            peer_agent_id=peer_agent_id,
            msg_id=msg_id,
        )

    def _guardian_inspect_send(
        self, *, payload: dict, peer_agent_id: str, msg_id: str,
    ) -> InspectionDecision:
        """Hook called from outbound A2A primitives BEFORE encryption.

        Serialises the application payload to canonical JSON bytes,
        ships it to ``/v1/guardian/inspect`` with direction=out. On
        decision=block raises GuardianBlocked (caller never sends).
        On decision=redact carries the redacted bytes back so the
        caller substitutes them before encrypt.
        """
        payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return self._guardian_inspect(
            direction="out",
            payload_bytes=payload_bytes,
            peer_agent_id=peer_agent_id,
            msg_id=msg_id,
        )

    def _guardian_inspect_deliver(
        self, *, payload: dict, peer_agent_id: str, msg_id: str,
    ) -> InspectionDecision:
        """Hook called from inbound A2A primitives AFTER decryption.

        Same shape as ``_guardian_inspect_send`` but direction=in.
        """
        payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return self._guardian_inspect(
            direction="in",
            payload_bytes=payload_bytes,
            peer_agent_id=peer_agent_id,
            msg_id=msg_id,
        )

    def _apply_guardian_deliver(
        self, *, payload: dict, sender_agent_id: str, msg_id: str,
    ) -> dict:
        """Apply Guardian inspection on a freshly-decrypted message.

        Returns the (possibly redacted) payload to deliver, or raises
        GuardianBlocked if Mastio refused. NO-OP when guardian is
        disabled. When ``CULLIS_GUARDIAN_TICKET_KEY`` is set in the
        SDK env we additionally verify the ticket signature locally
        as a defense-in-depth check: a tampered SDK that returned a
        synthetic ``pass`` without contacting Mastio fails this gate.
        """
        decision = self._guardian_inspect_deliver(
            payload=payload,
            peer_agent_id=sender_agent_id,
            msg_id=msg_id,
        )
        if decision.ticket and os.environ.get("CULLIS_GUARDIAN_TICKET_KEY"):
            from cullis_sdk.guardian.client import verify_ticket
            try:
                verify_ticket(
                    token=decision.ticket,
                    key=os.environ["CULLIS_GUARDIAN_TICKET_KEY"],
                    expected_msg_id=msg_id,
                )
            except ValueError as exc:
                raise RuntimeError(
                    f"guardian_ticket_verify_failed: {exc}"
                ) from exc
        if decision.redacted_payload is not None:
            try:
                return json.loads(
                    decision.redacted_payload.decode("utf-8"),
                )
            except (ValueError, UnicodeDecodeError) as exc:
                raise RuntimeError(
                    f"guardian returned malformed redacted_payload: {exc}"
                ) from exc
        return payload
