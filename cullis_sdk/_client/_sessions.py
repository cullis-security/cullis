"""Session lifecycle support extracted from :mod:`cullis_sdk.client`.

Single public symbol:

* :class:`_SessionsMixin` — mixin folded into ``CullisClient`` that
  exposes the five A2A session lifecycle calls: ``open_session``,
  ``accept_session``, ``reject_session``, ``close_session`` and
  ``list_sessions``. Each one routes to ``/v1/egress/sessions`` when
  the client is proxy-bound (``from_connector`` /
  ``from_enrollment`` / ``from_identity_dir``) and to
  ``/v1/broker/sessions`` for direct-broker clients.

Movement only — no behavior change. The mixin assumes the host class
exposes ``_authed_request``, ``_egress_http`` and the boolean
``_use_egress_for_sessions`` flag.
"""
from __future__ import annotations

import warnings

from cullis_sdk.types import SessionInfo


# Sunset target shared by every session lifecycle method. ADR-008 makes
# the oneshot fire-and-forget flow the canonical A2A surface (memory:
# ``oneshot_only_for_demo``); these classical session helpers stay
# around for one more minor before removal.
_SUNSET = "Will be removed in cullis-sdk v0.5 (~2026-08-15)."


class _SessionsMixin:
    """A2A session lifecycle on ``CullisClient``."""

    def open_session(self, target_agent_id: str, target_org_id: str,
                     capabilities: list[str]) -> str:
        """Open a new session with a target agent. Returns session_id.

        Proxy-bound clients (``from_connector``, ``from_enrollment``,
        ``from_identity_dir``) route through ``/v1/egress/sessions`` —
        the proxy's local mini-broker handles intra-org and falls
        through to the broker bridge for cross-org. Direct-broker
        clients keep using ``/v1/broker/sessions``.

        .. deprecated:: 0.4.x
           Use :meth:`send_oneshot` instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.open_session() is deprecated. Use send_oneshot(...) "
            f"instead for the canonical A2A surface. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        if self._use_egress_for_sessions:
            resp = self._egress_http("post", "/v1/egress/sessions", json={
                "target_agent_id": target_agent_id,
                "target_org_id": target_org_id,
                "capabilities": capabilities,
            })
            resp.raise_for_status()
            return resp.json()["session_id"]
        path = "/v1/broker/sessions"
        resp = self._authed_request("POST", path, json={
            "target_agent_id": target_agent_id,
            "target_org_id": target_org_id,
            "requested_capabilities": capabilities,
        })
        resp.raise_for_status()
        return resp.json()["session_id"]

    def accept_session(self, session_id: str) -> None:
        """Accept a pending session.

        .. deprecated:: 0.4.x
           Use an oneshot-based flow (``send_oneshot`` / ``receive_oneshot``)
           instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.accept_session() is deprecated. Use an oneshot-based "
            f"flow (send_oneshot/receive_oneshot) instead. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        if self._use_egress_for_sessions:
            resp = self._egress_http(
                "post", f"/v1/egress/sessions/{session_id}/accept"
            )
            resp.raise_for_status()
            return
        path = f"/v1/broker/sessions/{session_id}/accept"
        resp = self._authed_request("POST", path)
        resp.raise_for_status()

    def reject_session(self, session_id: str) -> None:
        """Reject a pending session.

        The egress router has no dedicated reject endpoint — it folds
        rejection into ``/close`` (the local store treats both as a
        terminal state with the same semantics for the initiator).
        Direct-broker clients still get the reject path so the broker
        can distinguish 'rejected by target' from 'closed'.

        .. deprecated:: 0.4.x
           Use :meth:`send_oneshot` (sessionless) instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.reject_session() is deprecated. Use send_oneshot(...) "
            f"(sessionless) instead. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        if self._use_egress_for_sessions:
            resp = self._egress_http(
                "post", f"/v1/egress/sessions/{session_id}/close"
            )
            resp.raise_for_status()
            return
        path = f"/v1/broker/sessions/{session_id}/reject"
        resp = self._authed_request("POST", path)
        resp.raise_for_status()

    def close_session(self, session_id: str) -> None:
        """Close an active session.

        .. deprecated:: 0.4.x
           Use an oneshot-based flow (``send_oneshot`` / ``receive_oneshot``)
           instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.close_session() is deprecated. Use an oneshot-based "
            f"flow (send_oneshot/receive_oneshot) instead. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        if self._use_egress_for_sessions:
            resp = self._egress_http(
                "post", f"/v1/egress/sessions/{session_id}/close"
            )
            resp.raise_for_status()
            return
        path = f"/v1/broker/sessions/{session_id}/close"
        resp = self._authed_request("POST", path)
        resp.raise_for_status()

    def list_sessions(self, status: str | None = None) -> list[SessionInfo]:
        """List sessions, optionally filtered by status.

        The egress shape wraps the list in ``{"sessions": [...]}`` and
        the broker shape returns a flat list — unwrap on the egress
        side so callers see the same return type.

        .. deprecated:: 0.4.x
           Use discovery + ``send_oneshot`` instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.list_sessions() is deprecated. Use discovery + "
            f"send_oneshot(...) instead. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        params = {}
        if status:
            params["status"] = status
        if self._use_egress_for_sessions:
            resp = self._egress_http("get", "/v1/egress/sessions", params=params)
            resp.raise_for_status()
            body = resp.json()
            sessions = body.get("sessions", []) if isinstance(body, dict) else body
            return [SessionInfo.from_dict(s) for s in sessions]
        path = "/v1/broker/sessions"
        resp = self._authed_request("GET", path, params=params)
        resp.raise_for_status()
        return [SessionInfo.from_dict(s) for s in resp.json()]
