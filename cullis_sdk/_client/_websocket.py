"""WebSocket support extracted from :mod:`cullis_sdk.client`.

Two public symbols:

* :class:`WebSocketConnection` — authenticated WS connection with
  heartbeat, auto-reconnect, session resume and gap detection.
* :class:`_WebSocketMixin` — mixin folded into ``CullisClient`` that
  exposes :meth:`connect_websocket` and the internal :meth:`_ws_url`
  helper.

Movement only — no behavior change. The mixin assumes the host class
exposes ``base``, ``token``, ``_verify_tls`` and ``_dpop_proof`` (i.e.
the existing ``CullisClient`` attributes).
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cullis_sdk.client import CullisClient


class _WebSocketMixin:
    """WebSocket-related methods on ``CullisClient``."""

    def _ws_url(self) -> str:
        return self.base.replace("https://", "wss://").replace("http://", "ws://")

    def connect_websocket(
        self,
        *,
        auto_ack: bool = True,
        auto_reconnect: bool = True,
    ) -> "WebSocketConnection":
        """
        Open an authenticated WebSocket connection for real-time events.

        Returns a WebSocketConnection that yields parsed event dicts.
        The connection handles auth handshake and DPoP automatically.

        M3.5 — ``auto_ack`` (default True) makes the connection auto-POST
        ``/messages/{msg_id}/ack`` whenever a ``new_message`` frame
        carries ``queued: true``. Pass ``auto_ack=False`` if the
        application needs process-then-ack semantics (call
        :meth:`ack_message` manually).

        .. deprecated:: 0.4.x
           Use :meth:`poll_oneshot_inbox` for polling, or implement a native
           WebSocket consumer against the broker. Will be removed in v0.5.
        """
        import warnings
        warnings.warn(
            "CullisClient.connect_websocket() is deprecated. Use "
            "poll_oneshot_inbox(...) for polling, or implement a native WS "
            "consumer against the broker. "
            "Will be removed in cullis-sdk v0.5 (~2026-08-15).",
            DeprecationWarning,
            stacklevel=2,
        )
        return WebSocketConnection(
            self,
            auto_ack=auto_ack,
            auto_reconnect=auto_reconnect,
        )


class WebSocketConnection:
    """Authenticated WebSocket connection with heartbeat + auto-reconnect (M2).

    Features added for the reliability layer:
      - Auto-responds to server ``{"type":"ping"}`` with ``{"type":"pong"}``
        so the M2.1 server heartbeat does not flag the client as dead.
      - Auto-reconnect with exponential backoff (1s/3s/10s/30s, max 5
        attempts by default) on any recv error, unless ``auto_reconnect=False``.
      - Session resume (M2.2): for every session whose messages the caller
        has observed, the SDK remembers the highest ``seq`` it received.
        On reconnect it sends ``{"type":"resume", "session_id":.., "last_seq": N}``
        for each tracked session and transparently drains the replay.
      - Gap detection (M2.4): if a ``new_message`` arrives with a
        non-contiguous ``seq``, the yielded event carries an extra
        ``gap_detected`` dict ``{expected, got}`` so the caller can react
        (log, re-fetch, raise) without silently ignoring the reorder.

    Usage::

        ws = client.connect_websocket()
        for event in ws:
            if event.get("gap_detected"):
                print("seq gap:", event["gap_detected"])
            if event["type"] == "new_message":
                msg = client.decrypt_payload(event["message"], session_id=event["session_id"])
                print(msg["payload"])
            elif event["type"] == "session_pending":
                client.accept_session(event["session_id"])
        ws.close()
    """

    _RECONNECT_BACKOFF_SECONDS = (1, 3, 10, 30, 30)

    def __init__(
        self,
        client: "CullisClient",
        *,
        auto_reconnect: bool = True,
        auto_ack: bool = True,
        max_reconnect_attempts: int | None = None,
    ) -> None:
        self._client = client
        self._ws = None
        self._auto_reconnect = auto_reconnect
        self._auto_ack = auto_ack
        self._max_reconnect_attempts = (
            max_reconnect_attempts
            if max_reconnect_attempts is not None
            else len(self._RECONNECT_BACKOFF_SECONDS)
        )
        # session_id → last seq observed (for resume + gap detection)
        self._last_seq: dict[str, int] = {}
        self._closed = False
        self._connect()

    def _connect(self) -> None:
        import ssl as _ssl
        from websockets.sync.client import connect as ws_connect

        ws_url = self._client._ws_url() + "/v1/broker/ws"
        ws_kwargs: dict = {"open_timeout": 5}
        if ws_url.startswith("wss://") and not self._client._verify_tls:
            ssl_ctx = _ssl.create_default_context()
            # Python's ssl module raises ValueError if check_hostname=True
            # is combined with verify_mode=CERT_NONE. The order below
            # (clear check_hostname FIRST, then lower verify_mode) is
            # required, not redundant. _check_insecure_tls in the client
            # constructor already warned/refused; here we just mirror
            # the HTTP-path opt-out to the WS path.
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = _ssl.CERT_NONE
            ws_kwargs["ssl"] = ssl_ctx
        self._ws = ws_connect(ws_url, **ws_kwargs)

        # Auth handshake with DPoP proof
        http_htu = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        dpop_proof = self._client._dpop_proof("GET", http_htu, self._client.token)

        self._ws.send(json.dumps({
            "type": "auth",
            "token": self._client.token,
            "dpop_proof": dpop_proof,
        }))
        resp = json.loads(self._ws.recv())
        if resp.get("type") != "auth_ok":
            self._ws.close()
            raise ConnectionError(f"WebSocket auth failed: {resp}")

        # M2.2 — ask the server to replay anything missed for every
        # session we had been tracking before the drop.
        for session_id, last_seq in list(self._last_seq.items()):
            self._ws.send(json.dumps({
                "type": "resume",
                "session_id": session_id,
                "last_seq": last_seq,
            }))

    def _reconnect(self) -> bool:
        """Try to re-establish the connection with exponential backoff."""
        import time as _time

        for attempt in range(self._max_reconnect_attempts):
            delay = self._RECONNECT_BACKOFF_SECONDS[
                min(attempt, len(self._RECONNECT_BACKOFF_SECONDS) - 1)
            ]
            _time.sleep(delay)
            try:
                self._connect()
                return True
            except Exception:
                continue
        return False

    def __iter__(self) -> "WebSocketConnection":
        return self

    def __next__(self) -> dict:
        if self._closed or self._ws is None:
            raise StopIteration
        while True:
            try:
                raw = self._ws.recv()
                event = json.loads(raw)
            except Exception:
                if self._auto_reconnect and self._reconnect():
                    continue
                self.close()
                raise StopIteration

            etype = event.get("type")

            # Server heartbeat — reply and keep reading.
            if etype == "ping":
                try:
                    self._ws.send(json.dumps({"type": "pong"}))
                except Exception:
                    pass
                continue

            # Track inbound seq per session for resume + gap detection.
            if etype == "new_message":
                sid = event.get("session_id")
                msg = event.get("message") or {}
                seq = msg.get("seq")
                if isinstance(sid, str) and isinstance(seq, int):
                    prev = self._last_seq.get(sid)
                    if (
                        prev is not None
                        and seq != prev + 1
                        and not event.get("replayed")
                    ):
                        event["gap_detected"] = {"expected": prev + 1, "got": seq}
                    self._last_seq[sid] = (
                        max(seq, prev) if prev is not None else seq
                    )

                # M3.5 — auto-ack queued offline messages before yielding.
                # Best-effort: failures don't drop the event, the broker
                # will redeliver on next reconnect.
                if self._auto_ack and event.get("queued") and event.get("msg_id"):
                    try:
                        self._client.ack_message(sid, event["msg_id"])
                    except Exception:
                        pass

            return event

    def close(self) -> None:
        """Close the WebSocket connection."""
        self._closed = True
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None
