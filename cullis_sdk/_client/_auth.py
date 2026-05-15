"""Authentication + DPoP + headers extracted from :mod:`cullis_sdk.client`.

Single public symbol:

* :class:`_AuthMixin` — mixin folded into ``CullisClient`` that exposes
  the broker authentication entry points and the low-level DPoP /
  header / authed-request plumbing every other mixin depends on.

Methods moved (security-CRITICAL, byte-perfect):

* ``_dpop_proof`` — RFC 9449 proof builder (claim order, key handling,
  optional nonce binding preserved).
* ``_update_nonce`` — parses ``DPoP-Nonce`` and ``X-Cullis-Role``
  response headers; branch handling identical (incl. the broker
  direct-connect DeprecationWarning).
* ``_headers`` — composes ``Authorization: DPoP <token>`` + ``DPoP:``
  for authed broker calls. Raises when ``self.token`` is missing.
* ``_authed_request`` — wrap an httpx call with the DPoP nonce-retry
  protocol (RFC 9449 §8) and the token-expiry re-login retry
  (`PR #690 _relogin_callable`). Signature and recursion guard
  ``_no_relogin`` preserved.
* ``login`` / ``login_from_pem`` / ``_legacy_login_from_pem`` — legacy
  BYOCA login against the Court (now deprecated under ADR-011). The
  exact ordering of ``DPoP``-protected POSTs to ``/v1/auth/token``,
  the 401 ``use_dpop_nonce`` replay branch, and the deprecation
  warning emission are preserved verbatim.
* ``login_via_proxy`` — ADR-004 §2.4 proxy-mediated login: the Mastio
  mints the ``client_assertion`` and forwards it to the Court via the
  reverse-proxy. Auto-relogin callable wired to itself on success.
* ``login_via_proxy_with_local_key`` — Tech-debt #2 proxy login with
  on-device key signing (challenge → sign locally → endorse via
  proxy → token exchange). Auto-relogin callable wired to itself.

The mixin assumes the host class exposes ``base``, ``_http``,
``_label``, ``_signing_key_pem``, ``_proxy_agent_id``, ``_cert_pem``,
``_dpop_privkey`` / ``_dpop_pubkey_jwk`` / ``_dpop_nonce``,
``server_role``, ``token`` and ``_relogin_callable``.

The module-level helpers (``_check_insecure_tls``,
``_build_proxy_http_client``, ``_cert_key_pair_matches``,
:class:`InsecureTLSWarning`) intentionally remain in
:mod:`cullis_sdk.client` because external callers (`cullis_sdk/_client/
_rfq.py`, tests in ``test_sdk_tls_hardening.py`` and
``test_sdk_proxy_client_ca_pin.py``) import them from that path and
patch them there via ``unittest.mock.patch``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

import httpx

from cullis_sdk.auth import (
    build_client_assertion,
    build_dpop_proof,
    generate_dpop_keypair,
)


class _AuthMixin:
    """Broker authentication + DPoP plumbing on ``CullisClient``."""

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

    def _authed_request(
        self,
        method: str,
        path: str,
        *,
        _no_relogin: bool = False,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make an authenticated request with automatic DPoP nonce retry.

        On a token-expiry 401 (LOCAL_TOKEN past TTL), the client invokes
        ``self._relogin_callable`` once — populated by the login method
        used at bootstrap — and retries the request. ``_no_relogin``
        guards against infinite recursion if the re-login itself yields
        another 401.
        """
        resp = self._http.request(
            method, f"{self.base}{path}",
            headers=self._headers(method, path), **kwargs,
        )
        self._update_nonce(resp)

        # Existing DPoP nonce challenge path (replays the same token).
        if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
            resp = self._http.request(
                method, f"{self.base}{path}",
                headers=self._headers(method, path), **kwargs,
            )
            self._update_nonce(resp)
            return resp

        # Token-expiry 401: re-mint a fresh access token and retry once.
        # No magic string match — any 401 that is NOT a DPoP nonce
        # challenge can be a token expiry (the broker only returns 401
        # in those two cases for an authed request).
        if (
            resp.status_code == 401
            and not _no_relogin
            and self._relogin_callable is not None
        ):
            try:
                self._relogin_callable()
            except Exception:
                # Re-login itself failed — propagate the original 401 so
                # the caller sees the same observable behavior they got
                # before this auto-retry shipped. The login method's own
                # exception type leaks context to logs but doesn't
                # surface to the caller.
                return resp
            return self._authed_request(
                method, path, _no_relogin=True, **kwargs,
            )

        return resp

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
            # Auto-relogin on token expiry — replay the same flow.
            self._relogin_callable = self.login_via_proxy
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
            # Auto-relogin on token expiry — replay the same flow.
            self._relogin_callable = self.login_via_proxy_with_local_key
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise ConnectionError(f"[{agent_id}] Proxy unreachable: {e}") from e
        except httpx.HTTPStatusError as e:
            raise PermissionError(
                f"[{agent_id}] login_via_proxy_with_local_key failed "
                f"(HTTP {e.response.status_code}): {e.response.text}"
            ) from e
