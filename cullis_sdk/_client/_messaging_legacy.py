"""Legacy session-based messaging primitives extracted from
:mod:`cullis_sdk.client`.

Single public symbol:

* :class:`_MessagingLegacyMixin` — mixin folded into ``CullisClient``
  that exposes the eight A2A session-based messaging primitives that
  pre-date the oneshot fire-and-forget surface:

    ``send``                — encrypt + double-sign → broker / proxy egress.
    ``send_via_proxy``      — ADR-001 §10 resolve + mtls-only egress send.
    ``receive_via_proxy``   — pull pending session frames from the proxy
                              and verify mtls-only signatures.
    ``poll``                — long-poll a session's inbox, return decrypted
                              :class:`InboxMessage` rows.
    ``ack_via_proxy``       — ack a proxy-queued message.
    ``ack_message``         — public ack entry point (routes to
                              ``ack_via_proxy`` or broker).
    ``decrypt_payload``     — E2E-decrypt an inbox row in place.
    ``_unwrap_egress_message`` (staticmethod) — translate an egress
                              poll-response row into the broker shape
                              ``decrypt_payload`` already understands.

Movement only — no behavior change. The crypto path is preserved
byte-identically:

* ``send``: ``sign_message(inner) → encrypt_for_agent → sign_message(outer)
  → POST envelope``. The egress vs broker branch (``_use_egress_for_sessions``)
  and the 3-attempt connect-retry loop with ``time.sleep(2)`` reconnect
  delay are intact.
* ``receive_via_proxy``: ``verify_signature`` BEFORE handing the row
  back; on failure raises ``ValueError`` rather than silently dropping
  (so callers choose ack / audit / abort).
* ``decrypt_payload``: ``decrypt_from_agent`` on the inner payload only
  when ``self._signing_key_pem`` is set and the row is in envelope shape.
  Any decrypt failure logs ``RED`` and raises ``ValueError`` to fail
  closed (integrity violation).
* ``_unwrap_egress_message``: the JSON-string ``payload_ciphertext`` is
  re-parsed back to a dict so ``decrypt_payload`` keeps seeing the
  broker shape. ``mtls-only`` rows pass through untouched. The
  ``json`` import stays lazy inside the function body to keep the
  module-level import surface unchanged.

The mixin assumes the host class exposes ``base``, ``_label``,
``_signing_key_pem``, ``_client_seq``, ``_use_egress_for_sessions``,
``_pubkey_cache``, ``_authed_request``, ``_egress_http``,
``get_agent_public_key`` (``_DiscoveryMixin``) and
``_resolve_trust_anchors``.

NB: these methods are candidates for deprecation under the
``send_oneshot``-only direction (memory: ``oneshot_only_for_demo``),
but the ``@deprecated`` decorator deliberately is NOT added here —
that lands in a dedicated PR after the SDK split is complete.
"""
from __future__ import annotations

import time
import uuid
import warnings
from typing import Any

import httpx

from cullis_sdk._logging import RED, log
from cullis_sdk.crypto.e2e import decrypt_from_agent, encrypt_for_agent
from cullis_sdk.crypto.message_signer import sign_message, verify_signature
from cullis_sdk.types import InboxMessage


# Sunset target shared by every legacy session-based messaging method.
# ADR-008 makes the oneshot fire-and-forget surface canonical (memory:
# ``oneshot_only_for_demo``); these helpers stay around for one more
# minor before removal.
_SUNSET = "Will be removed in cullis-sdk v0.5 (~2026-08-15)."


class _MessagingLegacyMixin:
    """Session-based A2A messaging primitives on ``CullisClient``."""

    def send(self, session_id: str, sender_agent_id: str, payload: dict,
             recipient_agent_id: str,
             ttl_seconds: int | None = None,
             idempotency_key: str | None = None) -> dict:
        """
        Send an E2E encrypted, signed message through a session.

        The message is encrypted with the recipient's public key and signed
        with the sender's private key. The broker cannot read the content.

        M3.4 — optional queue parameters for offline delivery:
          - ``ttl_seconds``: broker-side TTL for the queued copy when the
            recipient is offline (default server-side: 300s, max 86400).
          - ``idempotency_key``: when provided, a retry with the same
            ``(recipient_agent_id, idempotency_key)`` collapses to a
            single queued message.

        Returns the broker's response body as a dict, e.g.
          ``{"status": "accepted", "session_id": ...}``  (direct push)
          ``{"status": "queued",   "msg_id": ..., "deduped": False, "session_id": ...}``
        so the caller can react to queued deliveries.

        .. deprecated:: 0.4.x
           Use :meth:`send_oneshot` instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.send() is deprecated. Use send_oneshot(...) instead "
            f"for the canonical A2A surface. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        if not self._signing_key_pem:
            raise RuntimeError("Signing key not available — call login() first")

        nonce = str(uuid.uuid4())
        timestamp = int(time.time())

        # Client-side sequence number for E2E ordering integrity
        client_seq = self._client_seq.get(session_id, 0)
        self._client_seq[session_id] = client_seq + 1

        # Inner signature on plaintext (non-repudiation for the recipient)
        inner_sig = sign_message(
            self._signing_key_pem, session_id, sender_agent_id,
            nonce, timestamp, payload, client_seq=client_seq,
        )
        # Encrypt payload + inner signature with recipient's public key
        recipient_pubkey = self.get_agent_public_key(recipient_agent_id)
        cipher_blob = encrypt_for_agent(
            recipient_pubkey, payload, inner_sig,
            session_id, sender_agent_id, client_seq=client_seq,
        )
        # Outer signature on ciphertext (transport integrity for the broker)
        outer_sig = sign_message(
            self._signing_key_pem, session_id, sender_agent_id,
            nonce, timestamp, cipher_blob, client_seq=client_seq,
        )

        if self._use_egress_for_sessions:
            # Egress envelope mode: cert-as-identity, no outer signature
            # (mTLS provides transport integrity to the proxy; the
            # ``inner_sig`` baked into ``cipher_blob`` provides E2E
            # non-repudiation for the recipient).
            body: dict[str, Any] = {
                "session_id": session_id,
                "payload": cipher_blob,
                "recipient_agent_id": recipient_agent_id,
                "mode": "envelope",
            }
            if ttl_seconds is not None:
                body["ttl_seconds"] = ttl_seconds
            if idempotency_key is not None:
                body["idempotency_key"] = idempotency_key
            for attempt in range(3):
                try:
                    resp = self._egress_http("post", "/v1/egress/send", json=body)
                    resp.raise_for_status()
                    try:
                        return resp.json()
                    except Exception:
                        return {"status": "accepted", "session_id": session_id}
                except (httpx.ConnectError, httpx.TimeoutException):
                    if attempt < 2:
                        print(f"[{self._label}] Proxy unreachable — retry in 2s...", flush=True)
                        time.sleep(2)
                    else:
                        raise ConnectionError(f"[{self._label}] Proxy unreachable after 3 attempts.")
            raise ConnectionError(f"[{self._label}] Proxy send failed unexpectedly.")

        envelope = {
            "session_id": session_id,
            "sender_agent_id": sender_agent_id,
            "payload": cipher_blob,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": outer_sig,
            "client_seq": client_seq,
        }
        path = f"/v1/broker/sessions/{session_id}/messages"
        query: dict[str, str | int] = {}
        if ttl_seconds is not None:
            query["ttl_seconds"] = ttl_seconds
        if idempotency_key is not None:
            query["idempotency_key"] = idempotency_key

        for attempt in range(3):
            try:
                resp = self._authed_request(
                    "POST", path, json=envelope,
                    params=query if query else None,
                )
                resp.raise_for_status()
                try:
                    return resp.json()
                except Exception:
                    return {"status": "accepted", "session_id": session_id}
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt < 2:
                    print(f"[{self._label}] Broker unreachable — retry in 2s...", flush=True)
                    time.sleep(2)
                else:
                    raise ConnectionError(f"[{self._label}] Broker unreachable after 3 attempts.")
        # Unreachable — loop above either returns or raises.
        raise ConnectionError(f"[{self._label}] Broker send failed unexpectedly.")

    def send_via_proxy(
        self,
        session_id: str,
        payload: dict,
        recipient_id: str,
        *,
        ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """Send a message through the local proxy (ADR-001 §10).

        Queries ``/v1/egress/resolve`` first, then sends via
        ``/v1/egress/send`` using the transport the proxy advertised.

        - ``transport=mtls-only`` (intra-org): signs the plaintext with the
          agent's private key and posts it as-is. The proxy verifies the
          signature and enqueues for the recipient.
        - ``transport=envelope`` (cross-org): raises ``NotImplementedError``
          in this revision — envelope-via-proxy wiring lands in a follow-up.

        ``recipient_id`` may be a SPIFFE URI (``spiffe://td/org/agent``) or
        the internal ``org::agent`` form.

        Requires proxy credentials from :meth:`from_enrollment` or
        :meth:`from_api_key_file` (API key) AND a signing key — either
        populated by :meth:`login` / :meth:`login_from_pem` (cert + key
        bundle) or assigned manually to ``_signing_key_pem`` after
        :meth:`from_api_key_file` — when the resolver picks
        ``mtls-only``.

        .. deprecated:: 0.4.x
           Use :meth:`send_oneshot` instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.send_via_proxy() is deprecated. Use send_oneshot(...) "
            f"instead. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        resolve_resp = self._egress_http(
            "post",
            "/v1/egress/resolve",
            json={"recipient_id": recipient_id},
        )
        resolve_resp.raise_for_status()
        decision = resolve_resp.json()
        transport = decision["transport"]
        # Resolve strips the org prefix from ``target_agent_id`` (returns
        # just ``byoca-bot``), but every downstream handler keys on
        # ``<org>::<agent>``. Reassemble so ``/v1/egress/message/send``'s
        # ``decide_route`` classifies the recipient intra vs cross
        # correctly — otherwise intra-org sends are mis-routed to the
        # broker bridge and 404 on the Court side.
        # ADR-020 — typed principals (``user::alice`` / ``workload::x``)
        # already carry ``::`` from the principal-type prefix; the old
        # heuristic (``"::" not in _raw_target``) wrongly skipped the
        # org prefix for them and made ``decide_route`` parse ``user``
        # as the org, denying every U2U send at the reach gate. Pin to
        # ``startswith("<org>::")`` instead.
        _resolved_org = decision.get("target_org_id")
        _raw_target = decision["target_agent_id"]
        target_agent_id = (
            f"{_resolved_org}::{_raw_target}"
            if _resolved_org and not _raw_target.startswith(f"{_resolved_org}::")
            else _raw_target
        )

        sender_agent_id = getattr(self, "_proxy_agent_id", None) or self._label
        client_seq = self._client_seq.get(session_id, 0)
        self._client_seq[session_id] = client_seq + 1

        if transport == "mtls-only":
            if not self._signing_key_pem:
                raise RuntimeError(
                    "mtls-only transport requires a signing key — "
                    "populate it via login() (cert+key bundle) or assign "
                    "_signing_key_pem after from_api_key_file()"
                )
            nonce = str(uuid.uuid4())
            timestamp = int(time.time())
            signature = sign_message(
                self._signing_key_pem,
                session_id,
                sender_agent_id,
                nonce,
                timestamp,
                payload,
                client_seq=client_seq,
            )
            body: dict[str, Any] = {
                "session_id": session_id,
                "payload": payload,
                "recipient_agent_id": target_agent_id,
                "mode": "mtls-only",
                "signature": signature,
                "nonce": nonce,
                "timestamp": timestamp,
                "sender_seq": client_seq,
            }
        else:
            raise NotImplementedError(
                "envelope transport through the proxy is not wired in this "
                "revision — use send() against the broker for cross-org until "
                "the follow-up PR lands"
            )

        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key

        resp = self._egress_http(
            "post",
            "/v1/egress/send",
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    def receive_via_proxy(self, session_id: str) -> list[dict]:
        """Poll the proxy for pending messages in ``session_id`` (ADR-001 §10).

        Returns the verified plaintext payloads. For ``mtls-only`` frames the
        signature is verified against the sender cert the proxy bundled in
        the response; a frame that fails verification raises
        ``ValueError`` rather than being silently dropped, so the caller
        chooses whether to ack it, audit it, or abort.

        Each returned dict has:
          - ``msg_id`` (str)
          - ``session_id`` (str)
          - ``sender_agent_id`` (str)
          - ``mode`` (``"mtls-only"`` | ``"envelope"``)
          - ``payload`` (dict, plaintext — populated for mtls-only only)
          - ``payload_ciphertext`` (str, populated for envelope only —
            caller still decrypts with its own key)
          - ``enqueued_at`` (ISO-8601)

        ``envelope`` messages are handed back untouched; the existing
        ``decrypt_from_agent`` helper remains the caller's responsibility
        until the envelope-via-proxy pass-through lands in a follow-up.

        .. deprecated:: 0.4.x
           Use :meth:`receive_oneshot` / :meth:`poll_oneshot_inbox` instead.
           Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.receive_via_proxy() is deprecated. Use "
            "receive_oneshot(...) or poll_oneshot_inbox(...) instead. "
            f"{_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        resp = self._egress_http(
            "get",
            f"/v1/egress/messages/{session_id}",
        )
        resp.raise_for_status()
        data = resp.json()

        out: list[dict] = []
        for m in data.get("messages", []):
            if m.get("mode") == "mtls-only":
                cert_pem = m.get("sender_cert_pem")
                if not cert_pem:
                    raise ValueError(
                        f"msg {m.get('msg_id')}: mtls-only frame missing sender_cert_pem"
                    )
                ok = verify_signature(
                    cert_pem,
                    m["signature"],
                    session_id,
                    m["sender_agent_id"],
                    m["nonce"],
                    m["timestamp"],
                    m["payload"],
                    client_seq=m.get("sender_seq"),
                    trust_anchors_pem=self._resolve_trust_anchors(),
                )
                if not ok:
                    raise ValueError(
                        f"msg {m.get('msg_id')}: signature verification failed"
                    )
                out.append({
                    "msg_id": m["msg_id"],
                    "session_id": m["session_id"],
                    "sender_agent_id": m["sender_agent_id"],
                    "mode": "mtls-only",
                    "payload": m["payload"],
                    "enqueued_at": m.get("enqueued_at"),
                })
            else:
                out.append({
                    "msg_id": m["msg_id"],
                    "session_id": m["session_id"],
                    "sender_agent_id": m["sender_agent_id"],
                    "mode": "envelope",
                    "payload_ciphertext": m.get("payload_ciphertext"),
                    "enqueued_at": m.get("enqueued_at"),
                })
        return out

    def ack_via_proxy(self, session_id: str, msg_id: str) -> bool:
        """Acknowledge a local-queue message to the proxy (at-least-once)."""
        resp = self._egress_http(
            "post",
            f"/v1/egress/sessions/{session_id}/messages/{msg_id}/ack",
        )
        if resp.status_code == 204:
            return True
        if resp.status_code in (404, 409):
            return False
        resp.raise_for_status()
        return True

    def ack_message(self, session_id: str, msg_id: str) -> bool:
        """Acknowledge a queued offline message (M3.5).

        Called by the WS drain loop when a ``new_message`` frame carries
        ``queued: True`` and a ``msg_id``. Also usable directly by the
        application when ``manual_ack=True`` was passed to
        :meth:`connect_websocket`.

        Returns ``True`` on 204, ``False`` on 404/409 (terminal state —
        safe to continue; the broker has already moved on). Raises on
        transport failures so the caller can retry.

        .. deprecated:: 0.4.x
           Use :meth:`ack_oneshot` instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.ack_message() is deprecated. Use ack_oneshot(...) "
            f"instead. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        if self._use_egress_for_sessions:
            return self.ack_via_proxy(session_id, msg_id)
        path = f"/v1/broker/sessions/{session_id}/messages/{msg_id}/ack"
        resp = self._authed_request("POST", path)
        if resp.status_code == 204:
            return True
        if resp.status_code in (404, 409):
            return False
        resp.raise_for_status()
        return False

    def decrypt_payload(self, msg: dict, session_id: str | None = None) -> dict:
        """
        Decrypt the payload of a received message.

        Returns the message dict with the payload replaced by the decrypted plaintext.
        Raises ValueError if decryption fails (integrity violation).

        .. deprecated:: 0.4.x
           Use :meth:`decrypt_oneshot` instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.decrypt_payload() is deprecated. Use decrypt_oneshot(...) "
            f"instead. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        if not self._signing_key_pem:
            return msg
        p = msg.get("payload", {})
        if not isinstance(p, dict) or "ciphertext" not in p:
            return msg
        sid = session_id or msg.get("session_id", "")
        if not sid:
            return msg
        try:
            sender_agent_id = msg.get("sender_agent_id", "")
            client_seq = msg.get("client_seq")
            plaintext_dict, _inner_sig = decrypt_from_agent(
                self._signing_key_pem, p, sid, sender_agent_id, client_seq=client_seq,
            )
            msg = dict(msg)
            msg["payload"] = plaintext_dict
        except Exception as exc:
            log("sdk", f"E2E decryption failed for session {sid} — message rejected", RED)
            raise ValueError("E2E decryption failed: message integrity cannot be verified") from exc
        return msg

    def poll(self, session_id: str, after: int = -1, poll_interval: int = 2) -> list[InboxMessage]:
        """Poll for new messages in a session. Returns decrypted messages.

        Egress poll wraps the list in ``{"messages": [...], "count": N,
        "scope": ...}`` and, in envelope mode, serialises the cipher
        blob to a JSON string under ``payload_ciphertext``. Reverse
        both shape diffs so callers see the same ``list[InboxMessage]``
        as the broker path.

        .. deprecated:: 0.4.x
           Use :meth:`poll_oneshot_inbox` instead. Will be removed in v0.5.
        """
        warnings.warn(
            "CullisClient.poll() is deprecated. Use poll_oneshot_inbox(...) "
            f"instead. {_SUNSET}",
            DeprecationWarning,
            stacklevel=2,
        )
        if self._use_egress_for_sessions:
            for attempt in range(5):
                try:
                    resp = self._egress_http(
                        "get", f"/v1/egress/messages/{session_id}",
                        params={"after": after},
                    )
                    resp.raise_for_status()
                    body = resp.json()
                    raw = body.get("messages", []) if isinstance(body, dict) else body
                    result: list[InboxMessage] = []
                    for m in raw:
                        unwrapped = self._unwrap_egress_message(m, session_id)
                        decrypted = self.decrypt_payload(unwrapped, session_id=session_id)
                        result.append(InboxMessage.from_dict(decrypted))
                    return result
                except httpx.HTTPStatusError:
                    raise
                except (httpx.ConnectError, httpx.TimeoutException):
                    if attempt < 4:
                        time.sleep(poll_interval)
                    else:
                        raise ConnectionError(f"[{self._label}] Proxy unreachable.")
            return []

        path = f"/v1/broker/sessions/{session_id}/messages"
        for attempt in range(5):
            try:
                resp = self._authed_request("GET", path, params={"after": after})
                resp.raise_for_status()
                messages = resp.json()
                result = []
                for m in messages:
                    decrypted = self.decrypt_payload(m, session_id=session_id)
                    result.append(InboxMessage.from_dict(decrypted))
                return result
            except httpx.HTTPStatusError as exc:
                # Propagate 409 (session closed) so callers can handle it
                raise
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt < 4:
                    time.sleep(poll_interval)
                else:
                    raise ConnectionError(f"[{self._label}] Broker unreachable.")
        return []

    @staticmethod
    def _unwrap_egress_message(m: dict, session_id: str) -> dict:
        """Translate an egress poll-response row into the broker shape
        ``decrypt_payload`` already understands.

        Egress envelope rows carry the cipher dict serialised as JSON
        under ``payload_ciphertext``; broker rows carry it as a dict
        under ``payload``. mtls-only rows already have ``payload`` as
        a dict — leave those alone, they decrypt as plaintext.
        """
        out = dict(m)
        out.setdefault("session_id", session_id)
        if out.get("mode") == "envelope" and "payload_ciphertext" in out:
            try:
                import json as _json
                out["payload"] = _json.loads(out["payload_ciphertext"])
            except (ValueError, TypeError):
                # Leave as-is — decrypt_payload will fail closed if it
                # can't parse the structure, which is the right outcome
                # for a malformed wire frame.
                pass
            out.pop("payload_ciphertext", None)
        return out
