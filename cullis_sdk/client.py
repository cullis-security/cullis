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

import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from typing import Callable, Optional

import httpx

from cullis_sdk.auth import generate_dpop_keypair, build_dpop_proof, build_client_assertion
from cullis_sdk.crypto.message_signer import (
    ONESHOT_ENVELOPE_PROTO_VERSION,
    sign_message,
    sign_oneshot_envelope,
    verify_oneshot_envelope_signature,
    verify_signature,
)
from cullis_sdk.crypto.e2e import encrypt_for_agent, decrypt_from_agent
from cullis_sdk.types import AgentInfo, SessionInfo, InboxMessage, RfqResult
from cullis_sdk._logging import log, RED

_PUBKEY_CACHE_TTL = 300  # seconds


class PubkeyFetchError(RuntimeError):
    """Raised by pubkey-fetch helpers (broker or egress) when the
    target agent's public key cannot be retrieved.

    Distinct from generic HTTP/network errors so callers — notably
    ``decrypt_oneshot`` consumers — can discriminate "couldn't verify
    sender, must skip" from "decrypt itself failed". The Connector's
    inbox poller catches this specifically and logs at ERROR (security
    relevant: an unverifiable sender means the message is dropped).
    """


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
    cert: "tuple[str, str] | None" = None
    if cert_path is not None and key_path is not None:
        ok, reason = _cert_key_pair_matches(cert_path, key_path)
        if ok:
            cert = (str(cert_path), str(key_path))
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

    # Resolve the actual ``verify=`` argument: pinned PEM path beats
    # the bool, but only when verification is on. ``verify_tls=False``
    # always wins (operator opt-out is opt-out — a stale pinned PEM
    # must not silently re-enable the verification they just disabled).
    verify_arg: "bool | str" = verify_tls
    if verify_tls and ca_chain_path is not None:
        from pathlib import Path as _Path
        ca_path = _Path(ca_chain_path)
        if ca_path.exists():
            verify_arg = str(ca_path)
    return httpx.Client(
        timeout=timeout, verify=verify_arg, cert=cert,
    )


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


class CullisClient:
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

    def __enter__(self) -> CullisClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    # ── Internal helpers ────────────────────────────────────────────

    def _dpop_proof(self, method: str, url: str, access_token: str | None = None) -> str:
        if self._dpop_privkey is None or self._dpop_pubkey_jwk is None:
            raise RuntimeError("DPoP key not initialized — call login() first")
        return build_dpop_proof(
            self._dpop_privkey, self._dpop_pubkey_jwk,
            method, url, access_token, self._dpop_nonce,
        )

    def _update_nonce(self, response: httpx.Response) -> None:
        nonce = response.headers.get("dpop-nonce")
        if nonce:
            self._dpop_nonce = nonce
        role = response.headers.get("x-cullis-role")
        if role:
            previous = self.server_role
            self.server_role = role
            if role == "broker" and previous != "broker":
                import warnings
                warnings.warn(
                    "CullisClient is connected directly to the broker. "
                    "ADR-004: agents should always reach the broker through "
                    "their local proxy (set broker_url=<proxy_url>). Direct "
                    "broker access is deprecated and will be removed in a "
                    "future release.",
                    DeprecationWarning,
                    stacklevel=3,
                )

    def _headers(self, method: str, path: str) -> dict:
        if not self.token:
            raise RuntimeError("Not authenticated — call login() first")
        url = f"{self.base}{path}"
        return {
            "Authorization": f"DPoP {self.token}",
            "DPoP": self._dpop_proof(method, url, self.token),
        }

    def _authed_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Make an authenticated request with automatic DPoP nonce retry."""
        resp = self._http.request(
            method, f"{self.base}{path}",
            headers=self._headers(method, path), **kwargs,
        )
        self._update_nonce(resp)
        if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
            resp = self._http.request(
                method, f"{self.base}{path}",
                headers=self._headers(method, path), **kwargs,
            )
            self._update_nonce(resp)
        return resp

    def _ws_url(self) -> str:
        return self.base.replace("https://", "wss://").replace("http://", "ws://")

    # ── Authentication ──────────────────────────────────────────────

    # ── Enrollment-based bootstrap ───────────────────────────────────

    @classmethod
    def from_enrollment(
        cls,
        enroll_url: str,
        *,
        save_config: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
        enable_dpop: bool = True,
        dpop_base_dir: "Path | None" = None,
    ) -> CullisClient:
        """Bootstrap a proxy-connected client from an enrollment URL.

        Calls the enrollment endpoint to receive API key and config, then
        returns a lightweight client pre-configured for the proxy egress API.

        Args:
            enroll_url: Full enrollment URL (e.g. https://proxy/v1/enroll/enroll_xxx)
            save_config: Optional file path to save the received config as .env
            verify_tls: Whether to verify TLS certificates
            timeout: HTTP request timeout in seconds

        Returns:
            A CullisClient configured with the proxy URL and API key.

        Example::

            client = CullisClient.from_enrollment("https://proxy.example.com/v1/enroll/enroll_buyer_abc123")
            agents = client.discover(capabilities=["order.read"])
        """
        _check_insecure_tls(verify_tls)
        http = httpx.Client(timeout=timeout, verify=verify_tls)
        try:
            resp = http.get(enroll_url)
            resp.raise_for_status()
            config = resp.json()
        except httpx.HTTPStatusError as e:
            raise PermissionError(
                f"Enrollment failed (HTTP {e.response.status_code}): {e.response.text}"
            ) from e
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise ConnectionError(f"Enrollment endpoint unreachable: {e}") from e
        finally:
            http.close()

        # Save config to .env file if requested
        if save_config:
            env_lines = [
                f"CULLIS_AGENT_ID={config['agent_id']}",
                f"CULLIS_PROXY_URL={config['proxy_url']}",
                f"CULLIS_ORG_ID={config['org_id']}",
            ]
            Path(save_config).write_text("\n".join(env_lines) + "\n")
            log("sdk", f"Config saved to {save_config}")

        # Build a proxy-oriented client. ADR-014: subsequent calls
        # authenticate by presenting the agent's TLS client cert at the
        # handshake — the caller is responsible for arranging cert+key
        # delivery (out-of-band, separate enrollment endpoint, etc.).
        instance = cls.__new__(cls)
        instance.base = config["proxy_url"].rstrip("/")
        instance._verify_tls = verify_tls
        instance._http = httpx.Client(timeout=timeout, verify=verify_tls)
        instance.token = None
        instance._label = config["agent_id"]
        instance._signing_key_pem = None
        instance._pubkey_cache = {}
        instance._client_seq = {}
        instance._dpop_privkey = None
        instance._dpop_pubkey_jwk = None
        instance._dpop_nonce = None
        instance._egress_dpop_key = None
        instance._egress_dpop_nonce = None
        instance._proxy_agent_id = config["agent_id"]
        instance._proxy_org_id = config["org_id"]
        # Dogfood Finding #9 — proxy-bound: see __init__.
        instance._use_egress_for_sessions = True
        # Mirror __init__: callers may attach the on-disk identity bundle
        # afterwards (see ``canonical_recipient`` in cullis_connector).
        instance.identity = None

        # F-B-11 Phase 3c (#181) — load or generate the persistent
        # DPoP keypair. The server stores the thumbprint in
        # ``internal_agents.dpop_jkt`` and refuses proofs signed by a
        # different key once the flag flips to ``required``. First-run
        # generates + persists, subsequent runs load from disk.
        if enable_dpop:
            from cullis_sdk.dpop import DpopKey
            try:
                instance._egress_dpop_key = DpopKey.load_or_generate(
                    config["agent_id"], base_dir=dpop_base_dir,
                )
                log("sdk", f"egress DPoP key ready (jkt={instance._egress_dpop_key.thumbprint()[:16]}…)")
            except OSError as exc:
                # Read-only containers, missing ``HOME``, etc. Fall
                # back to legacy bearer with a warning rather than
                # blowing up enrollment on a DPoP-first deploy.
                import warnings
                warnings.warn(
                    f"Could not persist egress DPoP key ({exc}); "
                    "falling back to legacy X-API-Key bearer. Set "
                    "dpop_base_dir to a writable directory or pass "
                    "enable_dpop=False to silence this warning.",
                    RuntimeWarning,
                    stacklevel=2,
                )

        log("sdk", f"Enrolled as {config['agent_id']} via proxy {config['proxy_url']}")
        return instance

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
        return headers

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

    # ── ADR-011 — unified enrollment + runtime auth ───────────────────

    @classmethod
    def from_identity_dir(
        cls,
        mastio_url: str,
        *,
        cert_path: "str | Path",
        key_path: "str | Path",
        dpop_key_path: "str | Path | None" = None,
        agent_id: str | None = None,
        org_id: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> "CullisClient":
        """Primary runtime constructor under ADR-014.

        Builds an httpx.Client that presents the agent's TLS client cert
        at the handshake — that IS the credential. The optional DPoP
        keypair signs each egress request when ``egress_dpop_mode`` is
        ``optional`` or ``required``.

        Args:
            mastio_url: base URL of the Mastio (``https://mastio.local:9443``).
            cert_path, key_path: ADR-014 mTLS material. Required —
                without them ``/v1/egress/*`` returns 401 from nginx.
            dpop_key_path: file holding the private DPoP JWK. Omit to
                run without DPoP binding — only accepted while the
                server's ``egress_dpop_mode`` is ``off`` or ``optional``.
            agent_id, org_id: optional identity metadata. Populated on
                the client instance; the Mastio doesn't require them on
                egress calls (the cert SAN is authoritative) but callers
                rely on them for logging.

        Example::

            client = CullisClient.from_identity_dir(
                "https://mastio.local:9443",
                cert_path="/etc/cullis/agent/cert.pem",
                key_path="/etc/cullis/agent/key.pem",
                dpop_key_path="/etc/cullis/agent/dpop.jwk",
            )
            client.send_oneshot("orgb::agent-b", {"hello": "world"})
        """
        instance = cls.__new__(cls)
        instance.base = mastio_url.rstrip("/")
        instance._verify_tls = verify_tls
        instance._http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            cert_path=cert_path,
            key_path=key_path,
        )
        instance.token = None
        instance._label = agent_id or "(client-cert-auth)"
        instance._signing_key_pem = None
        instance._pubkey_cache = {}
        instance._client_seq = {}
        instance._dpop_privkey = None
        instance._dpop_pubkey_jwk = None
        instance._dpop_nonce = None
        instance._egress_dpop_key = None
        instance._egress_dpop_nonce = None
        instance._proxy_agent_id = agent_id
        instance._proxy_org_id = org_id
        # Dogfood Finding #9 — proxy-bound: see __init__.
        instance._use_egress_for_sessions = True
        # ``_update_nonce`` reads ``self.server_role`` on every response;
        # since we skip ``__init__`` above (the ``cls.__new__(cls)`` route
        # that other factories also use), the attribute must exist.
        instance.server_role = None
        instance.identity = None

        if dpop_key_path is not None:
            from cullis_sdk.dpop import DpopKey
            instance._egress_dpop_key = DpopKey.load(Path(dpop_key_path))
            log("sdk", f"Loaded DPoP key from {dpop_key_path} "
                       f"(jkt={instance._egress_dpop_key.thumbprint()[:16]}…)")

        log("sdk", f"Runtime client ready (mastio={mastio_url}, "
                   f"agent={instance._label})")
        return instance

    # Backwards-compat alias — deprecated. Existing callers that pass
    # ``api_key_path`` get a clear deprecation warning. Prefer
    # ``from_identity_dir(cert_path=..., key_path=..., dpop_key_path=...)``.
    @classmethod
    def from_api_key_file(
        cls,
        mastio_url: str,
        *,
        api_key_path: "str | Path | None" = None,  # ignored, accepted for compat
        dpop_key_path: "str | Path | None" = None,
        cert_path: "str | Path | None" = None,
        key_path: "str | Path | None" = None,
        agent_id: str | None = None,
        org_id: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> "CullisClient":
        import warnings
        warnings.warn(
            "CullisClient.from_api_key_file is deprecated under ADR-014 — "
            "the api_key path is gone, the TLS client cert IS the agent "
            "credential. Use from_identity_dir(cert_path=, key_path=, "
            "dpop_key_path=) instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if cert_path is None or key_path is None:
            raise ValueError(
                "from_api_key_file (deprecated): cert_path and key_path are "
                "now required. Use from_identity_dir for the canonical entry "
                "point."
            )
        return cls.from_identity_dir(
            mastio_url,
            cert_path=cert_path,
            key_path=key_path,
            dpop_key_path=dpop_key_path,
            agent_id=agent_id,
            org_id=org_id,
            verify_tls=verify_tls,
            timeout=timeout,
        )

    @classmethod
    def enroll_via_byoca(
        cls,
        mastio_url: str,
        *,
        admin_secret: str,
        agent_name: str,
        cert_pem: str,
        private_key_pem: str,
        capabilities: list[str] | None = None,
        display_name: str = "",
        persist_to: "str | Path | None" = None,
        enable_dpop: bool = True,
        federated: bool = False,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> "CullisClient":
        """Operator-side helper: enroll an agent via BYOCA and return a
        runtime-ready client.

        Under ADR-011 BYOCA is an **enrollment** primitive, not a runtime
        auth path — the Mastio verifies the cert chains to its Org CA,
        emits an API key + pins an optional DPoP jkt. The returned client
        is configured with those credentials for the agent's runtime.

        Call this from provisioning code (Helm hook, Vault policy init,
        CI/CD step), not from the agent's runtime entry point. The
        agent itself should use :meth:`from_api_key_file` once the
        credentials are on disk.

        Persists to ``persist_to/{api-key, dpop.jwk, agent.json}`` when
        supplied (mode 0600); otherwise the credentials stay in memory.

        Requires admin access to the Mastio (``admin_secret``).
        """
        return cls._do_enroll(
            mastio_url=mastio_url,
            endpoint_path="/v1/admin/agents/enroll/byoca",
            admin_secret=admin_secret,
            body={
                "agent_name": agent_name,
                "display_name": display_name,
                "capabilities": list(capabilities or []),
                "cert_pem": cert_pem,
                "private_key_pem": private_key_pem,
                "federated": federated,
            },
            persist_to=persist_to,
            enable_dpop=enable_dpop,
            verify_tls=verify_tls,
            timeout=timeout,
        )

    @classmethod
    def enroll_via_spiffe(
        cls,
        mastio_url: str,
        *,
        admin_secret: str,
        agent_name: str,
        svid_pem: str,
        svid_key_pem: str,
        trust_bundle_pem: str | None = None,
        capabilities: list[str] | None = None,
        display_name: str = "",
        persist_to: "str | Path | None" = None,
        enable_dpop: bool = True,
        federated: bool = False,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> "CullisClient":
        """Operator-side helper: enroll an agent via SPIFFE SVID and
        return a runtime-ready client.

        The Mastio verifies the SVID against the SPIRE trust bundle
        (either the per-request ``trust_bundle_pem`` override or the
        operator-configured ``proxy_config.spire_trust_bundle``), pins
        the SPIFFE URI SAN as the agent's ``spiffe_id``, and emits the
        API key + DPoP jkt. See :meth:`enroll_via_byoca` for the
        persistence / runtime split.
        """
        body = {
            "agent_name": agent_name,
            "display_name": display_name,
            "capabilities": list(capabilities or []),
            "svid_pem": svid_pem,
            "svid_key_pem": svid_key_pem,
            "federated": federated,
        }
        if trust_bundle_pem is not None:
            body["trust_bundle_pem"] = trust_bundle_pem
        return cls._do_enroll(
            mastio_url=mastio_url,
            endpoint_path="/v1/admin/agents/enroll/spiffe",
            admin_secret=admin_secret,
            body=body,
            persist_to=persist_to,
            enable_dpop=enable_dpop,
            verify_tls=verify_tls,
            timeout=timeout,
        )

    @classmethod
    def _do_enroll(
        cls,
        *,
        mastio_url: str,
        endpoint_path: str,
        admin_secret: str,
        body: dict,
        persist_to: "str | Path | None",
        enable_dpop: bool,
        verify_tls: bool,
        timeout: float,
    ) -> "CullisClient":
        """Shared machinery for every ``enroll_via_*`` helper.

        Generates a DPoP keypair in memory, attaches its public JWK to
        the enrollment body, POSTs to the Mastio endpoint, persists the
        credentials and returns a runtime-ready client. Kept private —
        the public surface is ``enroll_via_byoca`` / ``enroll_via_spiffe``
        so the method names read as the user's intent, not as the
        underlying transport.
        """
        from cullis_sdk.dpop import DpopKey

        _check_insecure_tls(verify_tls)
        dpop_key: "DpopKey | None" = None
        if enable_dpop:
            dpop_key = DpopKey.generate(path=None)
            body = {**body, "dpop_jwk": dict(dpop_key.public_jwk)}

        url = f"{mastio_url.rstrip('/')}{endpoint_path}"
        headers = {
            "X-Admin-Secret": admin_secret,
            "Content-Type": "application/json",
        }

        http = httpx.Client(timeout=timeout, verify=verify_tls)
        try:
            resp = http.post(url, json=body, headers=headers)
        finally:
            http.close()
        if resp.status_code not in (200, 201):
            raise PermissionError(
                f"Enrollment failed (HTTP {resp.status_code}): {resp.text}"
            )
        enrolled = resp.json()
        agent_id = enrolled["agent_id"]
        org_id = agent_id.split("::", 1)[0] if "::" in agent_id else None

        # ADR-014: BYOCA agents bring their own cert+key (already in
        # ``body["cert_pem"]`` / ``body["private_key_pem"]``). SPIFFE
        # agents bring an SVID under different keys. We persist the
        # cert+key when the caller asked for disk persistence so the
        # runtime client can present them at the TLS handshake against
        # nginx — that cert IS the credential under PR-C.
        cert_pem_runtime = body.get("cert_pem") or body.get("svid_pem")
        key_pem_runtime = body.get("private_key_pem") or body.get("svid_key_pem")

        cert_path_runtime: "Path | None" = None
        key_path_runtime: "Path | None" = None
        if persist_to is not None:
            persist_dir = Path(persist_to)
            cls._persist_enrollment(
                persist_dir,
                agent_id=agent_id,
                org_id=org_id,
                mastio_url=mastio_url,
                dpop_key=dpop_key,
                cert_pem=cert_pem_runtime,
                private_key_pem=key_pem_runtime,
            )
            if cert_pem_runtime and key_pem_runtime:
                cert_path_runtime = persist_dir / "cert.pem"
                key_path_runtime = persist_dir / "key.pem"

        instance = cls.__new__(cls)
        instance.base = mastio_url.rstrip("/")
        instance._verify_tls = verify_tls
        instance._http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            cert_path=cert_path_runtime,
            key_path=key_path_runtime,
        )
        instance.token = None
        instance._label = agent_id
        instance._signing_key_pem = None
        instance._pubkey_cache = {}
        instance._client_seq = {}
        instance._dpop_privkey = None
        instance._dpop_pubkey_jwk = None
        instance._dpop_nonce = None
        instance._egress_dpop_key = dpop_key
        instance._egress_dpop_nonce = None
        instance._proxy_agent_id = agent_id
        instance._proxy_org_id = org_id
        # Dogfood Finding #9 — proxy-bound: see __init__.
        instance._use_egress_for_sessions = True
        instance.server_role = None
        instance.identity = None

        log("sdk", f"Enrolled {agent_id} via {endpoint_path}")
        return instance

    @staticmethod
    def _persist_enrollment(
        persist_to: "Path",
        *,
        agent_id: str,
        org_id: str | None,
        mastio_url: str,
        dpop_key,  # DpopKey | None
        cert_pem: str | None = None,
        private_key_pem: str | None = None,
    ) -> None:
        """Write enrollment credentials under ``persist_to/`` with 0600
        perms on secrets. Layout (ADR-014):

            persist_to/dpop.jwk       — private DPoP JWK (only if enabled)
            persist_to/agent.json     — {agent_id, org_id, mastio_url}
            persist_to/cert.pem       — leaf cert (mTLS, the credential)
            persist_to/key.pem        — private key (mTLS, the credential)
        """
        import json as _json
        import os as _os
        persist_to.mkdir(parents=True, exist_ok=True)

        (persist_to / "agent.json").write_text(_json.dumps({
            "agent_id": agent_id,
            "org_id": org_id,
            "mastio_url": mastio_url,
        }, indent=2))

        if dpop_key is not None:
            dpop_key.save(persist_to / "dpop.jwk")

        if cert_pem:
            (persist_to / "cert.pem").write_text(cert_pem)
        if private_key_pem:
            key_file = persist_to / "key.pem"
            key_file.write_text(private_key_pem)
            _os.chmod(key_file, 0o600)

    @classmethod
    def from_connector(
        cls,
        config_dir: str | Path | None = None,
        *,
        timeout: float = 10.0,
        enable_dpop: bool = True,
        verify_tls: bool | None = None,
    ) -> CullisClient:
        """Build a client from an enrolled Connector Desktop identity on disk.

        Reads ``~/.cullis/identity/`` (or a custom ``config_dir``) and
        returns a client pre-configured with the Mastio URL, agent_id,
        and API key. Call :meth:`login_via_proxy` afterwards to obtain a
        broker access token.

        Layout expected (written by the Connector at enrollment time):

            <config_dir>/identity/agent.crt       ← agent cert (PEM)
            <config_dir>/identity/agent.key       ← agent key (PEM)
            <config_dir>/identity/metadata.json   ← agent_id, site_url, ...

        ADR-014 PR-C: the cert is the credential — no api_key file is
        read. Earlier Connectors that wrote ``identity/api_key`` are
        compatible (the file is ignored).

        Raises ``FileNotFoundError`` if the identity hasn't been enrolled
        yet (user should open the Connector dashboard first).
        """
        import json as _json
        if config_dir is None:
            config_dir = Path.home() / ".cullis"
        else:
            config_dir = Path(config_dir)

        identity_dir = config_dir / "identity"
        metadata_path = identity_dir / "metadata.json"

        if not metadata_path.exists():
            raise FileNotFoundError(
                f"Connector identity not found at {identity_dir}. "
                "Open the Connector dashboard and complete enrollment first."
            )

        metadata = _json.loads(metadata_path.read_text())
        agent_id = metadata.get("agent_id")
        site_url = metadata.get("site_url")
        if not agent_id or not site_url:
            raise RuntimeError(
                f"metadata.json at {metadata_path} is missing agent_id or site_url"
            )

        org_id = agent_id.split("::", 1)[0] if "::" in agent_id else ""

        # verify_tls precedence: explicit caller arg > URL scheme default.
        # The Connector itself doesn't persist a TLS-verify preference, so
        # callers (the ``serve`` CLI when ``--no-verify-tls`` is set, or
        # tests pinning the dev path) override the URL-scheme default.
        if verify_tls is None:
            verify_tls = site_url.startswith("https://")

        instance = cls.__new__(cls)
        instance.base = site_url.rstrip("/")
        instance._verify_tls = verify_tls
        instance.token = None
        instance._label = agent_id
        instance.server_role = None
        # Load the on-disk signing key + cert eagerly so ``decrypt_oneshot``,
        # ``send_oneshot``, and ``login_via_proxy_with_local_key`` all
        # work out of the box without every caller having to read
        # ``identity/agent.key`` + ``identity/agent.crt`` themselves.
        # Absent key/cert (legacy layout or a Connector that never
        # completed enrollment) is not fatal — tools that need them
        # surface a clear error at call time.
        key_path = identity_dir / "agent.key"
        cert_path = identity_dir / "agent.crt"
        instance._signing_key_pem = key_path.read_text() if key_path.exists() else None
        instance._cert_pem = cert_path.read_text() if cert_path.exists() else None
        # ADR-014: present the agent cert at the TLS handshake when both
        # files exist on disk. nginx in front of the Mastio verifies the
        # cert chain to the Org CA and derives the agent identity for
        # ``/v1/egress/*``. Connectors that completed enrollment after
        # 0.3.x always have both files; the conditional only covers the
        # transitional case where a legacy dump shipped only the cert.
        _mtls_cert = cert_path if (cert_path.exists() and key_path.exists()) else None
        _mtls_key = key_path if _mtls_cert is not None else None
        # ADR-015 — TOFU-pinned Org CA. The Connector dashboard writes
        # ``identity/ca-chain.pem`` after the operator confirms the
        # SHA-256 fingerprint at first contact. When present, the
        # proxy-facing httpx client must verify the Mastio's cert
        # against this pin (not the system CA store).
        _pinned_ca = identity_dir / "ca-chain.pem"
        instance._http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            cert_path=_mtls_cert,
            key_path=_mtls_key,
            ca_chain_path=_pinned_ca if _pinned_ca.exists() else None,
        )
        instance._pubkey_cache = {}
        instance._client_seq = {}
        instance._dpop_privkey = None
        instance._dpop_pubkey_jwk = None
        instance._dpop_nonce = None
        instance._egress_dpop_key = None
        instance._egress_dpop_nonce = None
        instance._proxy_agent_id = agent_id
        instance._proxy_org_id = org_id
        # Dogfood Finding #9 — proxy-bound: route session ops through
        # /v1/egress/sessions* (handles intra-org locally, falls
        # through to broker bridge for cross-org).
        instance._use_egress_for_sessions = True
        # Mirror __init__: callers may attach the on-disk identity bundle
        # afterwards (see ``canonical_recipient`` in cullis_connector).
        instance.identity = None

        # F-B-11 Phase 3c + 3d — load the DPoP keypair alongside the
        # rest of the Connector identity. Phase 3d (#181) has the
        # Connector persist it at enrollment time as ``dpop.jwk``
        # next to ``agent.crt`` / ``agent.key``. For legacy Connectors
        # (pre-3d) that never persisted one, generate locally and
        # reuse on subsequent runs — but note the resulting thumbprint
        # is NOT bound server-side until the operator registers it
        # via the admin endpoint (#206) or re-enrolls.
        if enable_dpop:
            from cullis_sdk.dpop import DpopKey
            dpop_path = identity_dir / "dpop.jwk"
            try:
                if dpop_path.exists():
                    instance._egress_dpop_key = DpopKey.load(dpop_path)
                else:
                    instance._egress_dpop_key = DpopKey.generate(path=dpop_path)
            except (OSError, ValueError) as exc:
                import warnings
                warnings.warn(
                    f"Could not load or generate egress DPoP key at "
                    f"{dpop_path}: {exc}. Continuing without DPoP — the "
                    f"client cert at the TLS handshake still authenticates; "
                    f"pass enable_dpop=False to silence.",
                    RuntimeWarning,
                    stacklevel=2,
                )

        log("sdk", f"Loaded Connector identity {agent_id} from {identity_dir}")
        return instance

    # ── SPIFFE Workload API bootstrap ───────────────────────────────

    @classmethod
    def from_spiffe_workload_api(
        cls,
        broker_url: str,
        *,
        org_id: str,
        socket_path: str | None = None,
        agent_id: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> CullisClient:
        """**Deprecated under ADR-011.** SPIFFE→Court direct login.

        Under the unified model SPIFFE becomes an *enrollment* primitive:
        operators use :meth:`enroll_via_spiffe` once (at provisioning
        time) to exchange an SVID for an API key + DPoP jkt, then the
        agent runs with :meth:`from_api_key_file` at runtime. The
        Court's ``/v1/auth/token`` endpoint is sunset (see the
        ``Deprecation`` / ``Sunset`` headers the server returns). This
        method continues to work until the Court returns 410 Gone.

        Bootstrap a broker-connected client using a SPIFFE X.509-SVID.

        Fetches the workload's SVID from the local SPIFFE Workload API
        (typically a SPIRE agent Unix socket), then authenticates to the
        broker using that certificate. Requires the ``[spiffe]`` extra.
        """
        import warnings
        warnings.warn(
            "CullisClient.from_spiffe_workload_api is deprecated under "
            "ADR-011. Use CullisClient.enroll_via_spiffe(...) once at "
            "provisioning time, then CullisClient.from_api_key_file(...) "
            "at runtime. The Court's /v1/auth/token returns 410 Gone "
            "after sunset (~90d).",
            DeprecationWarning,
            stacklevel=2,
        )
        from cullis_sdk.spiffe import fetch_x509_svid, default_agent_id

        svid = fetch_x509_svid(socket_path)
        resolved_agent_id = agent_id or default_agent_id(svid.spiffe_id, org_id)

        instance = cls(broker_url, verify_tls=verify_tls, timeout=timeout)
        instance._legacy_login_from_pem(
            resolved_agent_id, org_id, svid.cert_pem, svid.key_pem,
        )
        log("sdk", f"Authenticated {resolved_agent_id} via SPIFFE ({svid.spiffe_id})")
        return instance

    # ── Broker authentication ──────────────────────────────────────

    def login(self, agent_id: str, org_id: str, cert_path: str, key_path: str,
              *,
              countersign_fn: Optional[Callable[[str], str]] = None) -> None:
        """Authenticate via x509 + DPoP, reading cert and key from file paths."""
        cert_pem = Path(cert_path).read_text()
        key_pem = Path(key_path).read_text()
        self.login_from_pem(
            agent_id, org_id, cert_pem, key_pem,
            countersign_fn=countersign_fn,
        )

    def login_from_pem(self, agent_id: str, org_id: str,
                       cert_pem: str, key_pem: str,
                       *,
                       countersign_fn: Optional[Callable[[str], str]] = None) -> None:
        """**Deprecated under ADR-011.** Direct BYOCA login to the Court.

        Under the unified model BYOCA is an enrollment primitive, not a
        runtime auth path: operators exchange cert+key for an API key +
        DPoP jkt via :meth:`enroll_via_byoca`, and agents authenticate
        with :meth:`from_api_key_file`. This method continues to work
        until the Court's ``/v1/auth/token`` returns 410 Gone.

        Authenticate via x509 + DPoP using PEM strings directly.

        Use this when loading credentials from a secret manager (Vault,
        AWS KMS, Azure Key Vault, etc.) instead of files on disk.

        ADR-009 Phase 1 — ``countersign_fn`` is an optional callback invoked
        with the raw client_assertion string; it must return a base64url
        ES256 signature (no padding). The SDK forwards it as
        ``X-Cullis-Mastio-Signature``. The mastio proxy is the typical
        caller that wires this.
        """
        import warnings
        warnings.warn(
            "CullisClient.login_from_pem is deprecated under ADR-011. "
            "Use CullisClient.enroll_via_byoca(...) once at provisioning "
            "time, then CullisClient.from_api_key_file(...) at runtime. "
            "The Court's /v1/auth/token returns 410 Gone after sunset "
            "(~90d).",
            DeprecationWarning,
            stacklevel=2,
        )
        self._legacy_login_from_pem(
            agent_id, org_id, cert_pem, key_pem,
            countersign_fn=countersign_fn,
        )

    def _legacy_login_from_pem(
        self, agent_id: str, org_id: str,
        cert_pem: str, key_pem: str,
        *,
        countersign_fn: Optional[Callable[[str], str]] = None,
    ) -> None:
        """Internal impl shared by the deprecated ``login_from_pem`` and
        ``from_spiffe_workload_api`` entry points. Kept around so the
        deprecation warning fires exactly once per user call (the public
        methods emit the warning before delegating here)."""
        self._label = agent_id
        try:
            self._signing_key_pem = key_pem
            assertion, _ = build_client_assertion(agent_id, cert_pem, key_pem)

            # Generate ephemeral DPoP key for this session
            self._dpop_privkey, self._dpop_pubkey_jwk = generate_dpop_keypair()
            token_url = f"{self.base}/v1/auth/token"

            extra_headers: dict[str, str] = {}
            if countersign_fn is not None:
                extra_headers["X-Cullis-Mastio-Signature"] = countersign_fn(assertion)

            dpop_proof = self._dpop_proof("POST", token_url, access_token=None)
            resp = self._http.post(
                token_url,
                json={"client_assertion": assertion},
                headers={"DPoP": dpop_proof, **extra_headers},
            )

            if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
                self._update_nonce(resp)
                dpop_proof = self._dpop_proof("POST", token_url, access_token=None)
                resp = self._http.post(
                    token_url,
                    json={"client_assertion": assertion},
                    headers={"DPoP": dpop_proof, **extra_headers},
                )

            resp.raise_for_status()
            self._update_nonce(resp)
            self.token = resp.json()["access_token"]
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise ConnectionError(f"[{agent_id}] Broker unreachable: {e}") from e
        except httpx.HTTPStatusError as e:
            raise PermissionError(
                f"[{agent_id}] Login failed (HTTP {e.response.status_code}): {e.response.text}"
            ) from e

    def login_via_proxy(self) -> None:
        """ADR-004 §2.4 — authenticate an enrolled agent via the local proxy.

        The cert + key stay on the proxy; this call asks the proxy to mint a
        short-lived client_assertion signed on the agent's behalf, then hands
        that assertion to the broker's ``/v1/auth/token`` (via the
        reverse-proxy) to receive a DPoP-bound access token.

        Requires :attr:`_proxy_agent_id` to be set and the underlying
        httpx.Client to carry the agent's TLS client cert (ADR-014) —
        typically via :meth:`from_enrollment` / :meth:`from_identity_dir`.
        After a successful call, :attr:`token` holds the broker access
        token and all subsequent ``_authed_request`` / ``discover`` /
        ``open_session`` / ``send`` calls work exactly like a cert-based
        login.
        """
        agent_id = getattr(self, "_proxy_agent_id", None)
        if not agent_id:
            raise RuntimeError(
                "login_via_proxy() requires proxy enrollment — "
                "use CullisClient.from_enrollment() first",
            )
        self._label = agent_id

        try:
            sign_resp = self._http.post(
                f"{self.base}/v1/auth/sign-assertion",
            )
            sign_resp.raise_for_status()
            self._update_nonce(sign_resp)
            sign_body = sign_resp.json()
            assertion = sign_body["client_assertion"]

            # ADR-009 Phase 2 — forward the proxy's counter-signature when
            # the proxy returned one. The Court enforces it against
            # organizations.mastio_pubkey; absence is fine for legacy orgs.
            mastio_headers: dict[str, str] = {}
            mastio_signature = sign_body.get("mastio_signature")
            if mastio_signature:
                mastio_headers["X-Cullis-Mastio-Signature"] = mastio_signature

            self._dpop_privkey, self._dpop_pubkey_jwk = generate_dpop_keypair()
            token_url = f"{self.base}/v1/auth/token"

            dpop_proof = self._dpop_proof("POST", token_url, access_token=None)
            resp = self._http.post(
                token_url,
                json={"client_assertion": assertion},
                headers={"DPoP": dpop_proof, **mastio_headers},
            )
            if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
                self._update_nonce(resp)
                dpop_proof = self._dpop_proof("POST", token_url, access_token=None)
                resp = self._http.post(
                    token_url,
                    json={"client_assertion": assertion},
                    headers={"DPoP": dpop_proof, **mastio_headers},
                )
            resp.raise_for_status()
            self._update_nonce(resp)
            self.token = resp.json()["access_token"]
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise ConnectionError(f"[{agent_id}] Proxy unreachable: {e}") from e
        except httpx.HTTPStatusError as e:
            raise PermissionError(
                f"[{agent_id}] login_via_proxy failed "
                f"(HTTP {e.response.status_code}): {e.response.text}"
            ) from e

    def login_via_proxy_with_local_key(self) -> None:
        """Tech-debt #2 — authenticate an enrolled agent to the broker
        using a client_assertion signed **locally** with the on-device
        private key.

        Companion to :meth:`login_via_proxy`. That method has the Mastio
        sign on the agent's behalf (requires the key to live server-side
        in Vault / ``proxy_config``). Device-code-enrolled Connectors
        hold the key on the user's machine — this method instead has
        the proxy issue a short-lived nonce, the client signs the
        assertion locally, and the proxy verifies + counter-signs it.

        Flow:
          1. ``POST /v1/auth/login-challenge`` → nonce + expires_in.
          2. Build ``client_assertion`` with :func:`build_client_assertion`
             using ``self._signing_key_pem``; embed the nonce as a claim.
          3. ``POST /v1/auth/sign-challenged-assertion`` → echoed
             assertion + optional ``mastio_signature`` (ADR-009 Phase 2).
          4. ``POST /v1/auth/token`` with assertion + DPoP proof + the
             mastio counter-sig header — identical to the legacy path
             from this point on.

        Requires :attr:`_proxy_agent_id`, :attr:`_signing_key_pem`,
        :attr:`_cert_pem`, and an httpx.Client carrying the TLS client
        cert (ADR-014) — populated via :meth:`from_connector` (or set
        manually). No fallback to :meth:`login_via_proxy` — if the new
        endpoint is absent the caller sees a clear error rather than a
        silent downgrade.
        """
        agent_id = getattr(self, "_proxy_agent_id", None)
        if not agent_id:
            raise RuntimeError(
                "login_via_proxy_with_local_key() requires proxy enrollment "
                "— use CullisClient.from_connector() or from_enrollment() first",
            )
        if not self._signing_key_pem:
            raise RuntimeError(
                "login_via_proxy_with_local_key() requires a local signing "
                "key — set CullisClient._signing_key_pem from identity/agent.key, "
                "or use login_via_proxy() for Mastio-held keys.",
            )
        cert_pem = getattr(self, "_cert_pem", None)
        if not cert_pem:
            raise RuntimeError(
                "login_via_proxy_with_local_key() requires the agent "
                "certificate PEM — set CullisClient._cert_pem explicitly "
                "or construct the client via from_connector() which loads "
                "identity/agent.crt automatically.",
            )

        self._label = agent_id

        try:
            # Step 1 — fetch nonce.
            ch_resp = self._http.post(
                f"{self.base}/v1/auth/login-challenge",
            )
            ch_resp.raise_for_status()
            self._update_nonce(ch_resp)
            ch_body = ch_resp.json()
            nonce = ch_body["nonce"]

            # Step 2 — build + sign client_assertion locally.
            from cullis_sdk.auth import build_client_assertion
            assertion, _alg = build_client_assertion(
                agent_id, cert_pem, self._signing_key_pem, nonce=nonce,
            )

            # Step 3 — ask Mastio to endorse it.
            sign_resp = self._http.post(
                f"{self.base}/v1/auth/sign-challenged-assertion",
                json={"client_assertion": assertion, "nonce": nonce},
            )
            sign_resp.raise_for_status()
            self._update_nonce(sign_resp)
            sign_body = sign_resp.json()
            # The endpoint echoes the assertion; use the echoed value so
            # any future server-side transformation (none today) is
            # honoured.
            endorsed_assertion = sign_body["client_assertion"]

            # Step 4 — exchange for a DPoP-bound access token (Court).
            mastio_headers: dict[str, str] = {}
            mastio_signature = sign_body.get("mastio_signature")
            if mastio_signature:
                mastio_headers["X-Cullis-Mastio-Signature"] = mastio_signature

            self._dpop_privkey, self._dpop_pubkey_jwk = generate_dpop_keypair()
            token_url = f"{self.base}/v1/auth/token"
            dpop_proof = self._dpop_proof("POST", token_url, access_token=None)
            resp = self._http.post(
                token_url,
                json={"client_assertion": endorsed_assertion},
                headers={"DPoP": dpop_proof, **mastio_headers},
            )
            if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
                self._update_nonce(resp)
                dpop_proof = self._dpop_proof("POST", token_url, access_token=None)
                resp = self._http.post(
                    token_url,
                    json={"client_assertion": endorsed_assertion},
                    headers={"DPoP": dpop_proof, **mastio_headers},
                )
            resp.raise_for_status()
            self._update_nonce(resp)
            self.token = resp.json()["access_token"]
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise ConnectionError(f"[{agent_id}] Proxy unreachable: {e}") from e
        except httpx.HTTPStatusError as e:
            raise PermissionError(
                f"[{agent_id}] login_via_proxy_with_local_key failed "
                f"(HTTP {e.response.status_code}): {e.response.text}"
            ) from e

    # ── Registry ────────────────────────────────────────────────────
    #
    # ADR-010 Phase 6a-4 — agent registration is no longer an SDK concern.
    # The Mastio admin API (``POST /v1/admin/agents`` on the proxy) is the
    # sole write path; the federation publisher propagates to the Court.
    # The former ``register()`` wrapper around the Court's
    # ``POST /v1/registry/agents`` has been removed.

    def discover(
        self,
        capabilities: list[str] | None = None,
        org_id: str | None = None,
        pattern: str | None = None,
        q: str | None = None,
    ) -> list[AgentInfo]:
        """Search for agents in the network.

        ADR-010 Phase 6a: reads from the ``/v1/federation/`` namespace,
        which is where the Court now serves cross-org discovery.
        """
        path = "/v1/federation/agents/search"
        params: list[tuple[str, str]] = []
        if capabilities:
            params.extend([("capability", c) for c in capabilities])
        if org_id:
            params.append(("org_id", org_id))
        if pattern:
            params.append(("pattern", pattern))
        if q:
            params.append(("q", q))
        if not params:
            params.append(("pattern", "*"))
        resp = self._authed_request("GET", path, params=params)
        resp.raise_for_status()
        return [AgentInfo.from_dict(a) for a in resp.json().get("agents", [])]

    def list_peers(
        self,
        q: str | None = None,
        limit: int = 50,
    ) -> list[AgentInfo]:
        """List peers reachable via the local Mastio's egress API.

        Hits ``GET /v1/egress/peers`` (API-key + DPoP authed — does NOT
        need a broker JWT, unlike :meth:`discover`). Returns intra-org
        agents from the Mastio's local registry plus any cross-org
        agents the federation cache currently holds.

        ``q`` is a server-side substring prefilter on ``agent_id`` /
        ``display_name``; the caller is expected to do the final
        ranking (e.g. with ``difflib``) since "best match" is UX-driven.
        """
        params: list[tuple[str, str]] = []
        if q:
            params.append(("q", q))
        if limit:
            params.append(("limit", str(limit)))
        resp = self._egress_http(
            "get",
            "/v1/egress/peers",
            params=params,
        )
        resp.raise_for_status()
        return [AgentInfo.from_dict(p) for p in resp.json().get("peers", [])]

    def get_agent_public_key(self, agent_id: str, force_refresh: bool = False) -> str:
        """Retrieve agent PEM public key from the broker (TTL-cached).

        ADR-010 Phase 6a: reads from the ``/v1/federation/`` namespace.
        """
        if not force_refresh and agent_id in self._pubkey_cache:
            pubkey_pem, fetched_at = self._pubkey_cache[agent_id]
            if time.time() - fetched_at < _PUBKEY_CACHE_TTL:
                return pubkey_pem
        path = f"/v1/federation/agents/{agent_id}/public-key"
        resp = self._authed_request("GET", path)
        resp.raise_for_status()
        pubkey_pem = resp.json()["public_key_pem"]
        self._pubkey_cache[agent_id] = (pubkey_pem, time.time())
        return pubkey_pem

    def get_agent_public_key_via_egress(
        self, agent_id: str, force_refresh: bool = False,
    ) -> str:
        """Fetch the target agent's PEM cert through the local proxy's
        ``GET /v1/egress/agents/{id}/public-key`` endpoint.

        Egress-only variant — no broker fallback. Intended for callers
        that deliberately want to fail-fast when the proxy doesn't have
        the cert (e.g. device-code-enrolled Connectors that hold no
        broker JWT; falling back to the broker path would just
        surface a less-informative auth error). SDK consumers that
        want the broker fallback should leave ``decrypt_oneshot``'s
        ``pubkey_fetcher`` unset — the default chain covers both paths.

        Returns the PEM cert (not a bare key — the proxy hands back the
        full x509, the verify helpers in :mod:`cullis_sdk.crypto` accept
        either form). Reuses :attr:`_pubkey_cache` with the same TTL as
        the broker path so successive calls don't burn the per-agent
        egress rate-limit budget.

        Raises :class:`PubkeyFetchError` on any failure: 404/501 (route
        missing), 401/403 (auth broken), transport errors, or a 200
        response whose ``cert_pem`` is null/missing.
        """
        if not force_refresh and agent_id in self._pubkey_cache:
            pem, fetched_at = self._pubkey_cache[agent_id]
            if time.time() - fetched_at < _PUBKEY_CACHE_TTL:
                return pem
        path = f"/v1/egress/agents/{agent_id}/public-key"
        try:
            resp = self._egress_http("get", path)
            resp.raise_for_status()
            pem = resp.json().get("cert_pem")
        except PubkeyFetchError:
            raise
        except Exception as exc:
            raise PubkeyFetchError(
                f"GET {path} failed: {exc} ({type(exc).__name__})"
            ) from exc
        if not pem:
            raise PubkeyFetchError(
                f"proxy returned no cert_pem for {agent_id} "
                "(target may be cross-org with no broker bridge "
                "configured, or the agent does not exist)"
            )
        self._pubkey_cache[agent_id] = (pem, time.time())
        return pem

    def _fetch_pubkey_proxy_then_broker(self, agent_id: str) -> str:
        """Default pubkey lookup used by :meth:`decrypt_oneshot`.

        Order of operations:
          1. Ask the local Mastio's ``/v1/egress/agents/<id>/public-key``
             (auth'd via X-API-Key + DPoP — every SDK consumer has this).
          2. If the proxy returns 404 / 501 / cert_pem=null — conditions
             that mean "the proxy doesn't know this agent" rather than
             "the call itself failed" — fall back to the Court's
             ``/v1/federation/agents/<id>/public-key`` (requires a broker
             JWT).
          3. Genuine failures — 401 / 403 (auth broken), transport
             errors — propagate as :class:`PubkeyFetchError` WITHOUT a
             fallback: falling back would just mask a broken setup
             with a second, less-informative auth error.

        TTL-cached on :attr:`_pubkey_cache` so successive calls don't
        re-hit either path within the 300s window.
        """
        if agent_id in self._pubkey_cache:
            pem, fetched_at = self._pubkey_cache[agent_id]
            if time.time() - fetched_at < _PUBKEY_CACHE_TTL:
                return pem

        proxy_path = f"/v1/egress/agents/{agent_id}/public-key"
        should_fallback = False
        proxy_diag = ""
        try:
            resp = self._egress_http("get", proxy_path)
            if resp.status_code in (404, 501):
                should_fallback = True
                proxy_diag = f"proxy endpoint returned {resp.status_code}"
            else:
                resp.raise_for_status()
                pem = resp.json().get("cert_pem")
                if pem:
                    self._pubkey_cache[agent_id] = (pem, time.time())
                    return pem
                should_fallback = True
                proxy_diag = (
                    "proxy returned 200 but cert_pem was null "
                    "(cross-org target with no broker bridge configured "
                    "on the proxy — falling back to broker)"
                )
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code if exc.response is not None else 0
            if code in (404, 501):
                should_fallback = True
                proxy_diag = f"proxy endpoint returned {code}"
            else:
                raise PubkeyFetchError(
                    f"proxy {proxy_path} failed with HTTP {code} — "
                    "auth broken or proxy misconfigured, not retrying "
                    "via broker"
                ) from exc
        except Exception as exc:
            raise PubkeyFetchError(
                f"proxy {proxy_path} transport failure: "
                f"{exc} ({type(exc).__name__}) — not retrying via broker"
            ) from exc

        if not should_fallback:
            # Defensive: every branch above either returned, set the
            # flag, or raised. Reaching here is a programmer error.
            raise PubkeyFetchError(
                f"proxy lookup for {agent_id} ended in an unexpected state"
            )

        try:
            return self.get_agent_public_key(agent_id)
        except Exception as broker_exc:
            raise PubkeyFetchError(
                f"both pubkey lookups failed: {proxy_diag}; "
                f"broker fallback: {broker_exc} "
                f"({type(broker_exc).__name__})"
            ) from broker_exc

    # ── Sessions ────────────────────────────────────────────────────

    def open_session(self, target_agent_id: str, target_org_id: str,
                     capabilities: list[str]) -> str:
        """Open a new session with a target agent. Returns session_id.

        Proxy-bound clients (``from_connector``, ``from_enrollment``,
        ``from_identity_dir``) route through ``/v1/egress/sessions`` —
        the proxy's local mini-broker handles intra-org and falls
        through to the broker bridge for cross-org. Direct-broker
        clients keep using ``/v1/broker/sessions``.
        """
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
        """Accept a pending session."""
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
        """
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
        """Close an active session."""
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
        """
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

    # ── Messaging ───────────────────────────────────────────────────

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
        """
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
        _resolved_org = decision.get("target_org_id")
        _raw_target = decision["target_agent_id"]
        target_agent_id = (
            f"{_resolved_org}::{_raw_target}"
            if _resolved_org and "::" not in _raw_target
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
        """
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
        _resolved_org = decision.get("target_org_id")
        _raw_target = decision["target_agent_id"]
        target_agent_id = (
            f"{_resolved_org}::{_raw_target}"
            if _resolved_org and "::" not in _raw_target
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
        )
        if not ok:
            raise ValueError(
                "One-shot envelope signature verification failed — "
                "envelope may have been tampered with post-send"
            )

        if mode == "mtls-only":
            return {
                "payload": envelope["payload"],
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
        )
        return {
            "payload": plaintext,
            "sender_verified": True,
            "mode": mode,
        }

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
        """
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
        """
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
        """
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

    # ── WebSocket ───────────────────────────────────────────────────

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
        """
        return WebSocketConnection(
            self,
            auto_ack=auto_ack,
            auto_reconnect=auto_reconnect,
        )

    # ── RFQ ─────────────────────────────────────────────────────────

    def create_rfq(
        self,
        capability_filter: list[str],
        payload: dict,
        timeout_seconds: int = 30,
    ) -> RfqResult:
        """Broadcast an RFQ to agents matching capability filter."""
        path = "/v1/broker/rfq"
        resp = self._authed_request("POST", path, json={
            "capability_filter": capability_filter,
            "payload": payload,
            "timeout_seconds": timeout_seconds,
        })
        resp.raise_for_status()
        return RfqResult.from_dict(resp.json())

    def respond_to_rfq(self, rfq_id: str, payload: dict) -> None:
        """Submit a quote response to an open RFQ."""
        path = f"/v1/broker/rfq/{rfq_id}/respond"
        resp = self._authed_request("POST", path, json={"payload": payload})
        resp.raise_for_status()

    def get_rfq(self, rfq_id: str) -> RfqResult:
        """Get RFQ status and collected quotes."""
        path = f"/v1/broker/rfq/{rfq_id}"
        resp = self._authed_request("GET", path)
        resp.raise_for_status()
        return RfqResult.from_dict(resp.json())

    # ── Transaction Tokens ──────────────────────────────────────────

    def request_transaction_token(
        self,
        txn_type: str,
        payload_hash: str,
        *,
        session_id: str | None = None,
        counterparty_agent_id: str | None = None,
        resource_id: str | None = None,
        rfq_id: str | None = None,
        ttl_seconds: int = 60,
    ) -> dict:
        """Request a single-use transaction token for a specific operation."""
        path = "/v1/auth/token/transaction"
        body: dict[str, Any] = {
            "agent_id": self._label,
            "txn_type": txn_type,
            "payload_hash": payload_hash,
            "ttl_seconds": ttl_seconds,
        }
        if session_id:
            body["session_id"] = session_id
        if counterparty_agent_id:
            body["target_agent_id"] = counterparty_agent_id
        if resource_id:
            body["resource_id"] = resource_id
        if rfq_id:
            body["rfq_id"] = rfq_id
        resp = self._authed_request("POST", path, json=body)
        resp.raise_for_status()
        return resp.json()

    # ── Notifications ───────────────────────────────────────────────

    def get_notifications(self) -> list[dict]:
        """Get pending notifications for this agent."""
        path = "/v1/broker/notifications"
        resp = self._authed_request("GET", path)
        resp.raise_for_status()
        return resp.json()

    # ── Onboarding ──────────────────────────────────────────────────

    @classmethod
    def join_network(
        cls,
        broker_url: str,
        org_id: str,
        display_name: str,
        secret: str,
        ca_certificate: str,
        invite_token: str,
        *,
        contact_email: str = "",
        webhook_url: str | None = None,
        verify_tls: bool = True,
    ) -> dict:
        """
        Request to join the Cullis network as a new organization.

        Requires an invite token generated by the network admin.
        The request will be reviewed by the network admin after validation.
        """
        url = broker_url.rstrip("/") + "/v1/onboarding/join"
        body: dict[str, Any] = {
            "org_id": org_id,
            "display_name": display_name,
            "secret": secret,
            "ca_certificate": ca_certificate,
            "invite_token": invite_token,
        }
        if contact_email:
            body["contact_email"] = contact_email
        if webhook_url:
            body["webhook_url"] = webhook_url

        _check_insecure_tls(verify_tls)
        with httpx.Client(verify=verify_tls) as client:
            resp = client.post(url, json=body)
            resp.raise_for_status()
            return resp.json()


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
        client: CullisClient,
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

    def __iter__(self) -> WebSocketConnection:
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
