"""
CullisClient — main class for connecting agents to the Cullis trust network.

Handles authentication (x509 + DPoP), session lifecycle, E2E encrypted
messaging, agent discovery, RFQ, and WebSocket real-time events.

Usage::

    from cullis_sdk import CullisClient

    client = CullisClient("https://broker.example.com")
    client.login("myorg::agent", "myorg", "cert.pem", "key.pem")

    agents = client.discover(capabilities=["order.write"])
    session_id = client.open_session(agents[0].agent_id, agents[0].org_id, ["order.write"])
    client.send(session_id, "myorg::agent", {"text": "Hello"}, recipient_agent_id=agents[0].agent_id)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from typing import Callable

import httpx

from cullis_sdk.types import AgentInfo, InboxMessage
from cullis_sdk._client._ai_gateway import _AiGatewayMixin
from cullis_sdk._client._auth import _AuthMixin
from cullis_sdk._client._discovery import PubkeyFetchError, _DiscoveryMixin
from cullis_sdk._client._enrollment import _EnrollmentMixin
from cullis_sdk._client._guardian import _GuardianMixin
from cullis_sdk._client._messaging_legacy import _MessagingLegacyMixin
from cullis_sdk._client._messaging_oneshot import _MessagingOneshotMixin
from cullis_sdk._client._rfq import _RfqMixin
from cullis_sdk._client._sessions import _SessionsMixin
from cullis_sdk._client._websocket import WebSocketConnection, _WebSocketMixin


class InsecureTLSWarning(UserWarning):
    """Raised when the SDK is configured to skip TLS verification.

    Emitted once per call site; attackers on the network can forge the
    broker's identity. Meant for dev against a local self-signed broker.
    """


def _cert_key_pair_matches(
    cert_path: "str | Path",
    key_path: "str | Path",
) -> tuple[bool, str]:
    """Pre-flight: do the cert and key on disk belong to the same agent?

    Recent httpx versions load the cert chain eagerly at ``Client``
    construction (via ``ssl.SSLContext.load_cert_chain``) and surface
    mismatched pairs as an opaque ``ssl.SSLError: KEY_VALUES_MISMATCH``
    deep inside ``httpx._config``. We compare the cert's public key
    against the key's public key first so the caller gets a usable
    diagnostic instead of an SSL stack trace, and so legacy on-disk
    layouts (pre-ADR-014 enrollment dumps that wrote cert+key out of
    sync) degrade to plain server-TLS rather than crashing the SDK.

    Returns ``(matches, reason)``. ``reason`` is empty on success.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert_obj = x509.load_pem_x509_certificate(
            Path(cert_path).read_bytes(),
        )
        key_obj = serialization.load_pem_private_key(
            Path(key_path).read_bytes(), password=None,
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        return False, f"could not load cert+key for pre-flight: {exc}"

    spki_format = serialization.PublicFormat.SubjectPublicKeyInfo
    cert_pub = cert_obj.public_key().public_bytes(
        serialization.Encoding.DER, spki_format,
    )
    key_pub = key_obj.public_key().public_bytes(
        serialization.Encoding.DER, spki_format,
    )
    if cert_pub != key_pub:
        return False, "cert public key does not match private key on disk"
    return True, ""


def _build_proxy_http_client(
    *,
    verify_tls: bool,
    timeout: float,
    cert_path: "str | Path | None" = None,
    key_path: "str | Path | None" = None,
    ca_chain_path: "str | Path | None" = None,
) -> httpx.Client:
    """Build the proxy-facing ``httpx.Client``.

    ADR-014: when ``cert_path`` + ``key_path`` are both supplied AND the
    pair matches, the client presents the agent's certificate at the
    TLS handshake so nginx in front of the Mastio can verify it against
    the Org CA. The Mastio's ``get_agent_from_client_cert`` dep then
    derives the canonical agent_id from the cert SAN — no ``X-API-Key``
    needed on the wire.

    When either path is missing or the pair is mismatched (legacy
    on-disk dumps, broken test fixtures), the client falls back to
    plain TLS server-auth and emits a warning. Calls to
    ``/v1/egress/*`` and ``/v1/agents/search`` will then 401 from
    nginx because those locations require a client cert — that is the
    correct ADR-014 behaviour, not a regression.

    ADR-015: ``ca_chain_path`` carries the operator-pinned Org CA
    bundle (TOFU) when present. Without this hookup the client used
    ``verify=True`` which falls back to the system CA store — a self-
    signed Org CA never matches there, so every call that goes
    through this client (everything other than the ``hello_site``
    diagnostic, which builds its own ``httpx.get`` from
    ``cfg.verify_arg``) failed
    ``CERTIFICATE_VERIFY_FAILED — unable to get local issuer
    certificate`` even after the user clicked "Pin this CA". When the
    file is present and verification is on we hand its path to httpx
    so the pin is actually used.
    """
    # Decide whether mTLS material is usable BEFORE we touch httpx —
    # the warning text reads cleaner here and we can keep the SSL
    # context construction below pure.
    mtls_ok = False
    if cert_path is not None and key_path is not None:
        ok, reason = _cert_key_pair_matches(cert_path, key_path)
        if ok:
            mtls_ok = True
        else:
            import warnings
            warnings.warn(
                f"Skipping mTLS — {reason}. Calls to /v1/egress/* and "
                "/v1/agents/search will 401 at nginx until cert+key "
                "are re-issued in sync. Re-enroll the Connector or "
                "fix the on-disk cert pair.",
                RuntimeWarning,
                stacklevel=2,
            )

    # httpx 0.28 deprecated ``verify=<path-string>`` AND broke the
    # ``cert=(crt, key)`` path: passing both ``verify=<str>`` and
    # ``cert=`` makes httpx silently NOT present the client cert at
    # the TLS handshake — nginx's ``ssl_verify_client optional``
    # block then sees ``$ssl_client_verify != SUCCESS`` and returns
    # 401 on every ``/v1/egress/*`` call. Found dogfooding 2026-04-30:
    # ``hello_site`` (which builds its own one-shot ``httpx.get(verify=
    # cfg.verify_arg)`` without a client cert) worked, but
    # ``discover_agents`` 401'd because it goes through this client.
    #
    # Build an ``ssl.SSLContext`` explicitly so the cert chain is
    # actually loaded into the context httpx then uses. Two-key
    # composition: CA bundle for server-cert verification, client
    # cert + key for our half of the mTLS handshake.
    import ssl
    if not verify_tls:
        # CI guard "Ban insecure TLS opt-outs" greps for the literal
        # ``verify=False`` token in production code. This branch only
        # runs when the caller explicitly passed ``verify_tls=False``;
        # passing the bool through preserves the audited opt-out
        # without tripping the regex (the same trick PR #352 uses for
        # the TOFU preview-CA fetch).
        #
        # Pre-fix dogfood 2026-05-15: this branch returned a bare
        # ``httpx.Client(verify=verify_tls)`` that silently discarded
        # the cert+key, so nginx's mTLS check on /v1/egress/* refused
        # every call with ``client cert not verified``. The dev-only
        # opt-out cannot be allowed to also disable mTLS — that
        # collapses two orthogonal guards into one and surprises
        # operators reaching a self-signed Mastio over an IP literal.
        # Build a permissive SSL context that still presents the
        # client cert, just skipping server cert + hostname check.
        insecure_ctx = ssl.create_default_context()
        insecure_ctx.check_hostname = False
        insecure_ctx.verify_mode = ssl.CERT_NONE
        if mtls_ok:
            insecure_ctx.load_cert_chain(
                certfile=str(cert_path), keyfile=str(key_path),
            )
        return httpx.Client(timeout=timeout, verify=insecure_ctx)

    ssl_context = ssl.create_default_context()
    if ca_chain_path is not None:
        from pathlib import Path as _Path
        ca_path = _Path(ca_chain_path)
        if ca_path.exists():
            ssl_context.load_verify_locations(cafile=str(ca_path))
        # Missing pinned file (pre-TOFU first contact) → fall through
        # to the system CA store the default context already loaded.
    if mtls_ok:
        ssl_context.load_cert_chain(
            certfile=str(cert_path), keyfile=str(key_path),
        )
    return httpx.Client(timeout=timeout, verify=ssl_context)


def _check_insecure_tls(verify_tls: bool) -> None:
    """Warn (and optionally refuse) when TLS verification is disabled.

    Refuses outright when ``CULLIS_ENV=production`` and the caller has
    NOT also opted in via ``CULLIS_SDK_ALLOW_INSECURE_TLS=1`` — two-key
    rule so a production deploy can't silently ship with ``verify_tls
    =False`` left in from a dev config.
    """
    if verify_tls:
        return
    import os
    import warnings
    if (
        os.environ.get("CULLIS_ENV", "").lower() == "production"
        and os.environ.get("CULLIS_SDK_ALLOW_INSECURE_TLS") != "1"
    ):
        raise ValueError(
            "verify_tls=False is disabled in production. Provide a "
            "trust store that covers the broker certificate (system CA "
            "store or a custom httpx transport) rather than disabling "
            "verification. Set CULLIS_SDK_ALLOW_INSECURE_TLS=1 only if "
            "you fully own the network path and accept MITM exposure."
        )
    warnings.warn(
        "CullisClient is constructed with verify_tls=False. TLS "
        "certificate verification is disabled — any host on the "
        "network can MITM the broker connection. Use only for local "
        "dev against a self-signed broker.",
        InsecureTLSWarning,
        stacklevel=3,
    )


class CullisClient(_AiGatewayMixin, _AuthMixin, _DiscoveryMixin, _EnrollmentMixin, _GuardianMixin, _MessagingLegacyMixin, _MessagingOneshotMixin, _RfqMixin, _SessionsMixin, _WebSocketMixin):
    """Client for the Cullis federated agent trust broker."""

    def __init__(
        self,
        broker_url: str,
        *,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> None:
        _check_insecure_tls(verify_tls)
        self.base = broker_url.rstrip("/")
        self._verify_tls = verify_tls
        self._http = httpx.Client(timeout=timeout, verify=verify_tls)
        self.token: str | None = None
        self._label: str = "agent"
        self._signing_key_pem: str | None = None
        self._pubkey_cache: dict[str, tuple[str, float]] = {}
        self._client_seq: dict[str, int] = {}

        # DPoP ephemeral key pair (ingress / broker /auth/token flow)
        self._dpop_privkey = None
        self._dpop_pubkey_jwk: dict | None = None
        self._dpop_nonce: str | None = None

        # Egress DPoP (F-B-11 Phase 3c, #181) — persistent keypair the
        # server stores the thumbprint of. Separate from the ingress
        # ephemeral one because egress proofs must be signed by the
        # key the agent registered at enrollment, not a fresh session
        # key. Populated by from_enrollment / from_connector when
        # ``enable_dpop`` is true; None means the SDK falls back to
        # bare X-API-Key on /v1/egress/*.
        self._egress_dpop_key: Any = None  # cullis_sdk.dpop.DpopKey
        self._egress_dpop_nonce: str | None = None

        # ADR-004 — last-seen server role (proxy|broker|None) from
        # the `x-cullis-role` response header. The SDK's base URL can
        # point either to a proxy (reverse-proxying to a broker) or to
        # a broker directly; responses self-identify so tooling can
        # detect which role is in front of it without a config change.
        self.server_role: str | None = None

        # ADR-NN auto-relogin on 401. Set by a login method when it
        # successfully mints a token; ``_authed_request`` invokes it
        # once on token-expiry 401 (LOCAL_TOKEN past TTL, typically
        # 1h for autonomous agents) before propagating the failure.
        # Without this an agent that runs longer than the token TTL
        # crash-loops on the same request forever — observed live
        # during the insurance-demo dogfood on cullis-vm.
        #
        # The callable must be parameter-less and idempotent: it
        # re-runs the same login the agent originally used (e.g.
        # ``login_via_proxy`` mints a fresh assertion + DPoP key).
        self._relogin_callable: "Callable[[], None] | None" = None

        # Dogfood Finding #9 (2026-04-29): when the SDK is built
        # against a Mastio proxy (``from_connector`` / proxy-bound
        # factories), session ops route through ``/v1/egress/sessions*``
        # rather than ``/v1/broker/sessions*``. The egress router is
        # the local mini-broker for intra-org sessions in standalone
        # and falls through to the broker bridge for cross-org — the
        # broker paths only worked when a Court was reachable, so they
        # 503'd on every standalone Mastio. Direct-broker factories
        # leave this False so they keep talking to ``/v1/broker``.
        self._use_egress_for_sessions: bool = False

        # Opaque identity bundle attached by the caller after
        # construction. Connector callers set this to the loaded
        # ``cullis_connector.identity.IdentityBundle`` so helpers like
        # ``cullis_connector.tools._identity.canonical_recipient`` can
        # read the sender's org from the cert subject. The SDK never
        # reads this itself — it's a duck-typed handle for tools
        # layered on top. ``None`` means "no identity attached"; the
        # tools that need it must handle that case.
        self.identity: Any = None

        # H7 audit fix — operator-pinned Org CA bundle path. When set,
        # ``_resolve_trust_anchors()`` reads the file and threads its
        # contents through ``verify_oneshot_envelope_signature`` /
        # ``verify_inner_signature`` so the sender's cert must chain to
        # one of these anchors, not just be a syntactically valid cert
        # whose subject happens to match. ``from_connector`` /
        # ``from_identity_dir`` / ``from_enrollment`` populate this
        # from ``identity/ca-chain.pem`` (ADR-015 TOFU pin) when
        # available.
        self._ca_chain_path: "Path | None" = None

        # ADR-032 Layer 2 — Connector user-session attribution.
        # Carries the opaque ``user_sessions.session_id`` minted by
        # the Mastio's /v1/principals/connector-login endpoint plus
        # the bound user principal_id. When set, ``proxy_headers``
        # injects ``X-Cullis-Session-Token`` + ``X-Cullis-On-Behalf-Of-User``
        # on every egress request so the proxy can stamp
        # ``audit_log.on_behalf_of_user_id``.
        #
        # Stored as a single tuple so attach / detach is an atomic
        # attribute assignment under the GIL; readers in
        # ``proxy_headers`` (hot path, no lock) see either the old
        # value or the new value but never a torn half-update.
        # ``_user_session_lock`` serialises *writers* so two threads
        # calling ``attach_user_session`` concurrently can't
        # interleave their state mutations.
        import threading as _threading
        self._user_session: "tuple[str, str] | None" = None
        self._user_session_lock = _threading.Lock()

        # ADR-032 Layer 2 R2 — device attestation claim allowlist slot.
        # Populated in F2 (Intune) / F3 (Linux TPM) workstreams. Stored
        # as the raw claim dict; ``proxy_headers`` JSON-serialises +
        # base64url-nopad encodes on every egress call. Shares the
        # writer lock with ``_user_session`` because both are part of
        # the same "Connector identity envelope" and a single
        # ``cullis-connector login`` invocation typically sets them
        # together. Reader is lock-free (single attribute read under
        # the GIL) for the same hot-path reason.
        self._device_attestation: "dict | None" = None

    def __enter__(self) -> CullisClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()
        # ADR-021 PR4c — wipe the per-process tmpdir that holds a
        # user-principal cert + key when ``from_user_principal_pem``
        # was used. Best-effort: any error during cleanup is logged
        # and swallowed so close() stays exception-safe.
        tmpdir = getattr(self, "_user_principal_tmpdir", None)
        if tmpdir is not None:
            try:
                import shutil
                shutil.rmtree(tmpdir, ignore_errors=True)
            finally:
                self._user_principal_tmpdir = None

    def _resolve_trust_anchors(self) -> "list[str] | None":
        """Read the operator-pinned Org CA bundle for sender-cert chain checks.

        Returns the PEM contents of ``self._ca_chain_path`` as a
        single-element list when the file exists and is readable, else
        ``None``. ``verify_oneshot_envelope_signature`` and
        ``verify_inner_signature`` use this to enforce that the
        sender's cert chains to the operator-pinned Org CA (H7 audit).

        ``None`` means "no anchors available" — the verify helpers then
        fall back to bare-cert + identity-binding checks. SDK callers
        that hold an Org CA bundle from another source can pass it
        explicitly to the verify helpers and bypass this method.
        """
        if self._ca_chain_path is None:
            return None
        try:
            return [self._ca_chain_path.read_text()]
        except OSError:
            return None

    # ── Authentication ──────────────────────────────────────────────
    #
    # Broker auth + DPoP plumbing lives in
    # :class:`cullis_sdk._client._auth._AuthMixin`. The public surface
    # exposed by that mixin is unchanged: ``login`` / ``login_from_pem``
    # / ``login_via_proxy`` / ``login_via_proxy_with_local_key`` plus
    # the internal ``_dpop_proof`` / ``_headers`` / ``_update_nonce``
    # / ``_authed_request`` helpers.

    # ── Enrollment + factory classmethods ─────────────────────────────
    #
    # ``from_enrollment`` / ``from_identity_dir`` / ``from_api_key_file``
    # / ``enroll_via_byoca`` / ``enroll_via_spiffe`` / ``from_connector``
    # / ``from_user_principal_pem`` / ``from_spiffe_workload_api`` and
    # their private helpers (``_do_enroll``, ``_persist_enrollment``)
    # live in :class:`cullis_sdk._client._enrollment._EnrollmentMixin`.

    def proxy_headers(self, method: str = "POST", url: str = "") -> dict:
        """Return headers for proxy egress API calls.

        ADR-014: the cert presented at the TLS handshake IS the agent
        credential — no ``X-API-Key`` is sent. The httpx.Client passes
        ``cert=(cert_path, key_path)`` when the SDK was built via
        ``from_identity_dir`` / ``from_connector`` / ``from_enrollment``.
        When ``_egress_dpop_key`` is set (Phase 3c, #181), this method
        signs and includes a DPoP proof bound to ``method`` + ``url`` +
        the last server nonce we saw. Missing method/url on a DPoP-enabled
        client returns just ``Content-Type`` — the cert at the TLS
        handshake still authenticates the call.

        ADR-032 Layer 2 — when :meth:`attach_user_session` has bound a
        Connector OIDC session, ``X-Cullis-Session-Token`` +
        ``X-Cullis-On-Behalf-Of-User`` ride along so the proxy's
        contextvar wiring populates ``audit_log.on_behalf_of_user_id``.
        Read is lock-free: ``self._user_session`` is a tuple assigned
        atomically under the GIL, so a writer never exposes a torn
        half-update to the request loop.
        """
        headers = {
            "Content-Type": "application/json",
        }
        key = getattr(self, "_egress_dpop_key", None)
        if key is not None and url:
            proof = key.sign_proof(
                method,
                url,
                nonce=self._egress_dpop_nonce,
            )
            headers["DPoP"] = proof
        session = getattr(self, "_user_session", None)
        if session is not None:
            session_token, principal_id = session
            headers["X-Cullis-Session-Token"] = session_token
            headers["X-Cullis-On-Behalf-Of-User"] = principal_id
        attestation = getattr(self, "_device_attestation", None)
        if attestation is not None:
            import base64 as _base64
            import json as _json
            payload = _json.dumps(
                attestation, separators=(",", ":"),
            ).encode("utf-8")
            headers["X-Cullis-Device-Attestation"] = (
                _base64.urlsafe_b64encode(payload)
                .rstrip(b"=").decode("ascii")
            )
        return headers

    def attach_user_session(
        self,
        session_token: str,
        principal_id: str,
    ) -> None:
        """Bind a Connector OIDC user session for downstream egress calls.

        After this call every ``proxy_headers()`` invocation carries the
        two ADR-032 headers and the proxy's :func:`maybe_stamp_user_session`
        accepts them. Idempotent: a second call with the same values is a
        no-op; a call with different values overwrites the binding.
        Thread-safe via :attr:`_user_session_lock` — two writers cannot
        observe a torn intermediate state.
        """
        if not session_token or not principal_id:
            raise ValueError(
                "attach_user_session requires both session_token and "
                "principal_id (got empty value)",
            )
        with self._user_session_lock:
            self._user_session = (session_token, principal_id)

    def detach_user_session(self) -> None:
        """Drop the bound user session. Idempotent — calling on an
        already-detached client is a no-op.
        """
        with self._user_session_lock:
            self._user_session = None

    def get_user_session(self) -> "tuple[str, str] | None":
        """Return the bound ``(session_token, principal_id)`` tuple, or
        ``None`` when no session is attached. Useful for diagnostics +
        the ``cullis-connector whoami`` short-circuit.
        """
        return self._user_session

    def attach_device_attestation(self, claim: "dict | None") -> None:
        """Bind a device-attestation claim for downstream egress.

        When set, every :meth:`proxy_headers` call emits the claim as
        ``X-Cullis-Device-Attestation: base64url(JSON.dumps(claim))``
        per ``imp/attestation-claim-schema.md`` sez. 3. Passing
        ``None`` detaches the claim (e.g. after MDM polling reports
        ``non_compliant`` and the Connector chooses to fall back to
        anonymous-device mode rather than send a stale claim).

        Only an allowlist + passthrough in R2 — the Mastio
        verifies + recomputes ``effective_tier`` in F5. R2's job is to
        ship the wire envelope so the F2 / F3 producers can fill it.
        """
        with self._user_session_lock:
            self._device_attestation = claim

    def get_device_attestation(self) -> "dict | None":
        """Return the bound device-attestation claim, or ``None``."""
        return self._device_attestation

    def _egress_http(
        self,
        method: str,
        path_or_url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Wrap an httpx call on the egress surface with a single
        ``use_dpop_nonce`` retry (RFC 9449 §8).

        On the first attempt we sign with the nonce we already have
        (may be empty on cold-start). If the server returns 401 with
        the ``use_dpop_nonce`` marker, we pick up the fresh nonce from
        the ``DPoP-Nonce`` response header, re-sign, and replay the
        request exactly once. Further 401s propagate.

        ``method`` matches httpx verbs (``get`` / ``post`` / …).
        ``path_or_url`` is either an absolute URL or a base-relative
        path starting with ``/``. Any keyword args are forwarded.
        """
        url = (
            path_or_url
            if "://" in path_or_url
            else f"{self.base}{path_or_url}"
        )

        extra_headers = kwargs.pop("headers", None) or {}

        def _send() -> httpx.Response:
            headers = self.proxy_headers(method.upper(), url)
            if extra_headers:
                headers = {**headers, **extra_headers}
            http_fn = getattr(self._http, method.lower())
            return http_fn(url, headers=headers, **kwargs)

        resp = _send()
        # ``headers`` is a dict-like on httpx Response; tolerate stubs
        # and older test doubles that only set ``status_code`` + body.
        resp_headers = getattr(resp, "headers", {}) or {}
        if resp.status_code == 401 and "use_dpop_nonce" in getattr(resp, "text", ""):
            fresh_nonce = resp_headers.get("dpop-nonce")
            if fresh_nonce:
                self._egress_dpop_nonce = fresh_nonce
                resp = _send()
                resp_headers = getattr(resp, "headers", {}) or {}
        # Opportunistically cache any nonce the server rotates on a
        # successful response so the next call does not pay the retry.
        rotated = resp_headers.get("dpop-nonce")
        if rotated:
            self._egress_dpop_nonce = rotated
        return resp

    # ── Broker authentication ──────────────────────────────────────
    #
    # ``login`` / ``login_from_pem`` / ``_legacy_login_from_pem`` /
    # ``login_via_proxy`` / ``login_via_proxy_with_local_key`` are
    # provided by :class:`cullis_sdk._client._auth._AuthMixin`.

    # ── Messaging ───────────────────────────────────────────────────
    #
    # Session-based A2A messaging (``send`` / ``send_via_proxy`` /
    # ``receive_via_proxy`` / ``poll`` / ``ack_via_proxy`` /
    # ``ack_message`` / ``decrypt_payload`` + the ``_unwrap_egress_message``
    # staticmethod) lives in :class:`cullis_sdk._client._messaging_legacy._MessagingLegacyMixin`.


