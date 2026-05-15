"""Messaging oneshot primitives extracted from :mod:`cullis_sdk.client`.

Single public symbol:

* :class:`_MessagingOneshotMixin` — mixin folded into ``CullisClient``
  that exposes the nine A2A oneshot/fire-and-forget primitives:

    send_oneshot, reply_oneshot, receive_oneshot, decrypt_oneshot
        ADR-008 Phase 1 — sessionless one-shot
    send_to_inbox, send_oneshot_and_wait
        ADR-020 Phase 4 — user inbox send + request/response wrapper
    forward_oneshot, poll_oneshot_inbox, ack_oneshot
        Broker one-shot forwarding (used by proxy BrokerBridge)

Movement only — no behavior change. Crypto path (encrypt → sign on
send, verify → decrypt → guardian on deliver) is preserved
byte-identically. Lazy imports inside method bodies are kept lazy.

The mixin assumes the host class exposes ``_egress_http``,
``_authed_request``, ``_label``, ``_signing_key_pem``,
``_guardian_inspect_send`` and ``_apply_guardian_deliver`` (via
:class:`cullis_sdk._client._guardian._GuardianMixin`),
``_fetch_pubkey_proxy_then_broker`` (via
:class:`cullis_sdk._client._discovery._DiscoveryMixin`),
``_resolve_trust_anchors`` and the optional attributes
``_proxy_agent_id`` / ``_proxy_org_id`` / ``_inbox_path_via_broker``.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from cullis_sdk.crypto.e2e import decrypt_from_agent, encrypt_for_agent
from cullis_sdk.crypto.message_signer import (
    ONESHOT_ENVELOPE_PROTO_VERSION,
    sign_message,
    sign_oneshot_envelope,
    verify_oneshot_envelope_signature,
)


class _MessagingOneshotMixin:
    """A2A oneshot / fire-and-forget primitives on ``CullisClient``."""

    # ── ADR-008 Phase 1 — sessionless one-shot ─────────────────────

    def send_oneshot(
        self,
        recipient_id: str,
        payload: dict,
        *,
        correlation_id: str | None = None,
        reply_to: str | None = None,
        ttl_seconds: int = 300,
        capabilities: list[str] | None = None,
    ) -> dict:
        """Send a sessionless one-shot message via the local proxy.

        Intra-org resolves to ``mtls-only`` (signed plaintext); cross-org
        resolves to ``envelope`` (AES-256-GCM + RSA-OAEP/ECDH key wrap,
        signed outer by the sender, inner signature carried inside the
        cipher_blob for recipient non-repudiation).

        ``correlation_id`` defaults to a new UUID; pass the original
        request's correlation_id plus ``reply_to`` to send a reply.

        Returns the proxy's response dict with ``correlation_id``,
        ``msg_id`` and ``status`` (``enqueued`` or ``duplicate``).
        """
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

        if transport not in ("mtls-only", "envelope"):
            raise NotImplementedError(
                f"one-shot transport '{transport}' not supported"
            )

        if not self._signing_key_pem:
            raise RuntimeError(
                "one-shot send requires a signing key — populate it via "
                "login() (cert+key bundle) or assign _signing_key_pem "
                "after from_api_key_file()"
            )

        corr_id = correlation_id or str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        timestamp = int(time.time())
        sender_agent_id = getattr(self, "_proxy_agent_id", None) or self._label

        # ADR-016 Phase 3 — Guardian inspection BEFORE the message is
        # signed or encrypted. NO-OP when CULLIS_GUARDIAN_ENABLED=0.
        # On decision=block: GuardianBlocked propagates and the caller
        # never spends bytes on encryption + DPoP. On decision=redact:
        # substitute the payload before signing so the inner signature
        # binds the redacted (sanitized) form, not the original.
        guardian_decision = self._guardian_inspect_send(
            payload=payload,
            peer_agent_id=target_agent_id,
            msg_id=corr_id,
        )
        if guardian_decision.redacted_payload is not None:
            try:
                payload = json.loads(
                    guardian_decision.redacted_payload.decode("utf-8"),
                )
            except (ValueError, UnicodeDecodeError) as exc:
                raise RuntimeError(
                    f"guardian returned malformed redacted_payload: {exc}"
                ) from exc

        # Domain separation: signature binding substitutes the session_id
        # slot with 'oneshot:<correlation_id>' so a session signature
        # cannot be replayed as a one-shot signature and vice versa.
        inner_signature = sign_message(
            self._signing_key_pem,
            f"oneshot:{corr_id}",
            sender_agent_id,
            nonce,
            timestamp,
            payload,
            client_seq=0,
        )

        if transport == "envelope":
            # ADR-008 Phase 1 PR #3 — cross-org: encrypt with recipient pubkey.
            # The broker sees only the cipher_blob and verifies the outer
            # envelope signature (audit F-A-3: full envelope, not just
            # payload). The recipient decrypts and verifies the inner
            # signature for non-repudiation on plaintext.
            recipient_pubkey = decision.get("target_cert_pem")
            if not recipient_pubkey:
                raise RuntimeError(
                    "cross-org one-shot requires a recipient public key — "
                    "proxy /resolve did not return target_cert_pem"
                )
            cipher_blob = encrypt_for_agent(
                recipient_pubkey, payload, inner_signature,
                f"oneshot:{corr_id}", sender_agent_id, client_seq=0,
            )
            wire_payload: dict[str, Any] = cipher_blob
        else:
            wire_payload = payload

        # v2 outer envelope signature — covers mode, reply_to, correlation_id,
        # timestamp, nonce and wire payload. Broker and recipient both verify
        # over this exact canonical form (see audit F-A-1 / F-A-3).
        wire_signature = sign_oneshot_envelope(
            self._signing_key_pem,
            correlation_id=corr_id,
            sender_agent_id=sender_agent_id,
            nonce=nonce,
            timestamp=timestamp,
            mode=transport,
            reply_to=reply_to,
            payload=wire_payload,
        )

        body: dict[str, Any] = {
            "recipient_id": target_agent_id,
            "payload": wire_payload,
            "correlation_id": corr_id,
            "reply_to": reply_to,
            "mode": transport,
            "signature": wire_signature,
            "nonce": nonce,
            "timestamp": timestamp,
            "ttl_seconds": ttl_seconds,
            "capabilities": capabilities or [],
            "v": ONESHOT_ENVELOPE_PROTO_VERSION,
        }
        resp = self._egress_http(
            "post",
            "/v1/egress/message/send",
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    def reply_oneshot(
        self,
        recipient_id: str,
        payload: dict,
        reply_to: str,
        **kwargs,
    ) -> dict:
        """Convenience wrapper over ``send_oneshot`` with ``reply_to`` set."""
        return self.send_oneshot(
            recipient_id,
            payload,
            reply_to=reply_to,
            **kwargs,
        )

    def receive_oneshot(self) -> list[dict]:
        """Poll the proxy's one-shot inbox for this agent.

        Returns a list of envelope dicts with ``msg_id``,
        ``correlation_id``, ``reply_to``, ``sender_agent_id``,
        ``payload_ciphertext`` (the envelope as stored), and the
        delivery metadata. The caller is expected to parse the
        envelope (same shape session /send produces) to retrieve the
        application payload.
        """
        resp = self._egress_http(
            "get",
            "/v1/egress/message/inbox",
        )
        resp.raise_for_status()
        return resp.json().get("messages", [])

    def decrypt_oneshot(
        self,
        inbox_row: dict,
        *,
        pubkey_fetcher: Callable[[str], str] | None = None,
    ) -> dict:
        """Decrypt and authenticate a one-shot envelope row returned by
        :meth:`receive_oneshot`.

        Audit F-A-1 / F-A-3 fix: the envelope signature now covers the
        full envelope (mode, reply_to, correlation_id, nonce, timestamp,
        payload), not just ``payload``. Verification is unconditional —
        both ``mtls-only`` and ``envelope`` modes require a valid sender
        signature over the v2 canonical form. ``mtls-only`` describes
        key-wrap, not auth scope, so an unsigned envelope is always
        rejected.

        Rejects v1 (pre-fix) envelopes with a clear error: envelopes and
        recipients must upgrade together since the broker and proxy store
        the wire envelope verbatim.

        For ``envelope`` rows: also AES-GCM decrypt with the caller's
        private key and verify the inner signature against the sender's
        cert from the broker registry. Raises ``ValueError`` on any
        cryptographic failure.

        :param pubkey_fetcher: optional callable ``(sender_agent_id) -> pem``
            used to look up the sender's cert. When ``None`` (default),
            uses :meth:`_fetch_pubkey_proxy_then_broker` — proxy first,
            broker as fallback only on 404 / 501 / cert_pem=null (see
            that method's docstring). Callers that want to pin a single
            path (Connector device-code: proxy only; debug: broker only)
            pass the explicit helper (:meth:`get_agent_public_key_via_egress`
            or :meth:`get_agent_public_key`) here.

        Returns ``{"payload": <plaintext_dict>, "sender_verified": True,
        "mode": "mtls-only" | "envelope"}``.
        """
        import json as _json
        from cullis_sdk.crypto.e2e import verify_inner_signature

        envelope = _json.loads(inbox_row["payload_ciphertext"])

        # Protocol version gate — v1 envelopes are hard-rejected. The
        # product ships broker+SDK in lockstep; there's no mixed fleet.
        v = envelope.get("v")
        if v != ONESHOT_ENVELOPE_PROTO_VERSION:
            raise ValueError(
                f"Unsupported one-shot envelope version {v!r}; "
                f"expected v={ONESHOT_ENVELOPE_PROTO_VERSION}. "
                "Upgrade the sender's SDK/proxy."
            )

        # Required envelope identity fields. ``mode`` is NEVER defaulted —
        # a missing mode is an authentication failure (see audit F-A-1).
        if "mode" not in envelope:
            raise ValueError("One-shot envelope missing 'mode' — rejected")
        mode = envelope["mode"]
        if mode not in ("mtls-only", "envelope"):
            raise ValueError(f"One-shot envelope has unknown mode {mode!r}")
        for required in ("signature", "nonce", "timestamp", "payload"):
            if envelope.get(required) in (None, ""):
                raise ValueError(
                    f"One-shot envelope missing required field {required!r}"
                )

        sender = inbox_row["sender_agent_id"]
        corr = inbox_row["correlation_id"]

        # Cross-check: the envelope-embedded correlation_id must match the
        # row's. If they disagree, some store rewrote one of them and we
        # cannot trust either side.
        env_corr = envelope.get("correlation_id")
        if env_corr and env_corr != corr:
            raise ValueError(
                "One-shot envelope correlation_id does not match inbox row"
            )

        # Verify the v2 outer envelope signature against the sender's cert.
        fetch = (
            pubkey_fetcher if pubkey_fetcher is not None
            else self._fetch_pubkey_proxy_then_broker
        )
        sender_cert_pem = fetch(sender)
        # Issue #459 — trust anchor scope is intra-org only. The local
        # ``_ca_chain_path`` only holds the receiver's own Org CA; a
        # cross-org sender's cert chains to the *sender's* Org CA, not
        # ours. Court already verified that chain at federation publish
        # time (see ``app/federation/publish.py::_verify_cert_chain``)
        # before persisting the cert in the federated registry, so for
        # cross-org we delegate the chain check to Court and pass
        # ``None`` here. ``cert_binds_agent_id`` (inside
        # ``verify_cert_for_sender``) still runs and rejects forged
        # SAN/CN. Threat-model rationale: spoofing a cross-org sender
        # additionally requires the sender's *private* key (envelope
        # signing fails otherwise), which lives on the agent endpoint
        # and is never on Court or Mastio in BYOCA-Vault deploys —
        # see ``imp/troubleshooting-cross-org.md``.
        sender_org_id = sender.split("::", 1)[0] if "::" in sender else None
        local_org_id = getattr(self, "_proxy_org_id", None)
        is_intra_org = (
            sender_org_id is not None
            and local_org_id is not None
            and sender_org_id == local_org_id
        )
        trust_anchors = self._resolve_trust_anchors() if is_intra_org else None
        ok = verify_oneshot_envelope_signature(
            sender_cert_pem,
            envelope["signature"],
            correlation_id=corr,
            sender_agent_id=sender,
            nonce=envelope["nonce"],
            timestamp=envelope["timestamp"],
            mode=mode,
            reply_to=envelope.get("reply_to"),
            payload=envelope["payload"],
            trust_anchors_pem=trust_anchors,
        )
        if not ok:
            raise ValueError(
                "One-shot envelope signature verification failed — "
                "envelope may have been tampered with post-send"
            )

        if mode == "mtls-only":
            delivered_payload = self._apply_guardian_deliver(
                payload=envelope["payload"],
                sender_agent_id=sender,
                msg_id=corr,
            )
            return {
                "payload": delivered_payload,
                "sender_verified": True,
                "mode": mode,
            }

        if not self._signing_key_pem:
            raise RuntimeError(
                "envelope decrypt requires a private signing key — "
                "populate it via login() (cert+key bundle) or assign "
                "_signing_key_pem after from_api_key_file()"
            )

        cipher_blob = envelope["payload"]
        plaintext, inner_sig = decrypt_from_agent(
            self._signing_key_pem, cipher_blob,
            f"oneshot:{corr}", sender, client_seq=0,
        )

        verify_inner_signature(
            sender_cert_pem, inner_sig,
            f"oneshot:{corr}", sender,
            envelope["nonce"], envelope["timestamp"], plaintext,
            client_seq=0,
            trust_anchors_pem=trust_anchors,
        )
        delivered_payload = self._apply_guardian_deliver(
            payload=plaintext,
            sender_agent_id=sender,
            msg_id=corr,
        )
        return {
            "payload": delivered_payload,
            "sender_verified": True,
            "mode": mode,
        }

    # ── ADR-020 Phase 4 — user inbox send ────────────────────────────

    def send_to_inbox(
        self,
        *,
        recipient_org_id: str,
        recipient_principal_type: str,
        recipient_name: str,
        body: dict | str,
        subject: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """Send a message to a user / agent / workload principal's inbox.

        This is the ADR-020 / Phase 4 delivery path — distinct from
        :meth:`send_oneshot` which encrypts an envelope for agent ↔
        agent E2E. The inbox path is plaintext-at-rest within the
        broker (the broker is the trust boundary the user signed up
        for) and reach-policy gated.

        Default route is the Mastio-mediated path
        (``POST /v1/egress/inbox/send`` → ``BrokerBridge`` →
        ``POST /v1/inbox/send`` on the broker). When ``self.base`` is a
        broker URL — i.e. the SDK is run from inside the proxy via
        ``BrokerBridge.get_client()`` — set ``via_broker=True`` on the
        instance to skip the egress prefix.

        ``body`` is JSON-serialised when it arrives as a dict; pass a
        plain string to send pre-serialised content.

        Returns ``{"msg_id", "inserted", "quadrant"}`` on success.
        Raises :class:`PermissionError` on a 403 from reach-policy.
        """
        import json as _json
        if isinstance(body, dict):
            body_str = _json.dumps(body)
        else:
            body_str = body
        payload: dict[str, Any] = {
            "recipient_org_id":          recipient_org_id,
            "recipient_principal_type":  recipient_principal_type,
            "recipient_name":            recipient_name,
            "body":                      body_str,
        }
        if subject is not None:
            payload["subject"] = subject
        if idempotency_key is not None:
            payload["idempotency_key"] = idempotency_key
        # Hop selector: BrokerBridge sets ``_inbox_path_via_broker=True``
        # on the per-agent broker client so the same SDK method works on
        # both sides of the Mastio. Default is the mastio-mediated path
        # (egress prefix), which is what every external SDK caller uses.
        path = (
            "/v1/inbox/send"
            if getattr(self, "_inbox_path_via_broker", False)
            else "/v1/egress/inbox/send"
        )
        resp = self._authed_request("POST", path, json=payload)
        if resp.status_code == 403:
            raise PermissionError(
                f"inbox send denied (reach policy): {resp.text}",
            )
        resp.raise_for_status()
        return resp.json()

    def send_oneshot_and_wait(
        self,
        recipient_id: str,
        payload: dict,
        *,
        timeout: float = 30.0,
        poll_interval: float = 1.0,
        ttl_seconds: int = 300,
    ) -> dict:
        """Request-response convenience: send a one-shot, block until a
        reply tagged with the same ``correlation_id`` is in the caller's
        inbox, or ``TimeoutError`` after ``timeout`` seconds.

        Audit F-A-1 fix: ``decrypt_oneshot`` always verifies the sender's
        signature, so ``sender_verified`` is always ``True`` on success.
        If a non-verifying row ever slips through this method raises
        ``ValueError``.

        Returns ``{"correlation_id", "msg_id", "reply_to", "reply",
        "sender", "mode", "sender_verified"}``.
        """
        import json as _json

        sent = self.send_oneshot(
            recipient_id, payload, ttl_seconds=ttl_seconds,
        )
        corr = sent["correlation_id"]
        deadline = time.time() + timeout
        while time.time() < deadline:
            inbox = self.receive_oneshot()
            for row in inbox:
                envelope = _json.loads(row["payload_ciphertext"])
                if envelope.get("reply_to") != corr:
                    continue
                decoded = self.decrypt_oneshot(row)
                if not decoded["sender_verified"]:
                    raise ValueError(
                        "Reply for correlation_id "
                        f"{corr} could not be verified — refusing to "
                        "return unauthenticated plaintext."
                    )
                return {
                    "correlation_id": row["correlation_id"],
                    "msg_id": row["msg_id"],
                    "reply_to": corr,
                    "reply": decoded["payload"],
                    "sender": row["sender_agent_id"],
                    "mode": decoded["mode"],
                    "sender_verified": decoded["sender_verified"],
                }
            time.sleep(poll_interval)
        raise TimeoutError(
            f"no reply for correlation_id={corr} within {timeout:.1f}s"
        )

    # ── Broker one-shot forwarding (used by proxy BrokerBridge) ────

    def forward_oneshot(
        self,
        *,
        recipient_agent_id: str,
        correlation_id: str,
        reply_to_correlation_id: str | None,
        payload: dict,
        nonce: str,
        timestamp: int,
        signature: str,
        ttl_seconds: int = 300,
        capabilities: list[str] | None = None,
        mode: str = "mtls-only",
        v: int = ONESHOT_ENVELOPE_PROTO_VERSION,
    ) -> dict:
        """Forward a one-shot envelope to the broker's cross-org queue.

        Used by the sender proxy's ``BrokerBridge`` after it has already
        verified the local policy. The sending agent signs the v2
        canonical envelope form on its own key before calling this; the
        broker re-verifies and persists. ``mode`` is propagated verbatim
        so envelope-mode cipher_blobs ride through unchanged.
        """
        body = {
            "recipient_agent_id": recipient_agent_id,
            "correlation_id": correlation_id,
            "reply_to_correlation_id": reply_to_correlation_id,
            "payload": payload,
            "signature": signature,
            "nonce": nonce,
            "timestamp": timestamp,
            "mode": mode,
            "ttl_seconds": ttl_seconds,
            "capabilities": capabilities or [],
            "v": v,
        }
        resp = self._authed_request(
            "POST", "/v1/broker/oneshot/forward", json=body,
        )
        resp.raise_for_status()
        return resp.json()

    def poll_oneshot_inbox(self) -> list[dict]:
        """Drain pending cross-org one-shots addressed to this agent.

        The broker does NOT flip delivery status on read — the caller
        acks via :meth:`ack_oneshot` once the row has been mirrored
        locally. Returns the raw row dicts (see broker
        ``InboxOneShotItem``).
        """
        resp = self._authed_request("GET", "/v1/broker/oneshot/inbox")
        resp.raise_for_status()
        return resp.json().get("messages", [])

    def ack_oneshot(self, msg_id: str) -> bool:
        """Mark a broker one-shot row as delivered. Returns False on 404/409."""
        resp = self._authed_request(
            "POST", f"/v1/broker/oneshot/{msg_id}/ack",
        )
        if resp.status_code == 204:
            return True
        if resp.status_code in (404, 409):
            return False
        resp.raise_for_status()
        return False
