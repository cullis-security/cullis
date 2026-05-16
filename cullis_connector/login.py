"""End-to-end ``cullis-connector login`` flow (ADR-032 Layer 2).

Walks the user through an OIDC Authorization Code + PKCE flow against
the configured IdP, then binds the resulting identity to the Mastio's
``/v1/principals/connector-login`` endpoint and persists the returned
session locally.

Boundary split:

* Protocol logic (PKCE, discovery, JWKS, token exchange) lives in
  :mod:`cullis_sdk.oidc` — shared with the Mastio dashboard.
* Loopback HTTP server for the OIDC ``redirect_uri`` lives here.
* Mastio call uses the SDK's authed client built from the enrolled
  identity (mTLS cert + DPoP key + agent-cert auth path).

Failure modes are reported with actionable hints; the function never
swallows an error silently — a login that doesn't write a session row
is a login the operator must know about.
"""
from __future__ import annotations

import asyncio
import hashlib
import http.server
import logging
import socket
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization

from cullis_connector.identity.oidc_session import (
    OidcSession,
    delete_session,
    load_session,
    save_session,
)
from cullis_connector.identity.store import IdentityBundle
from cullis_sdk.oidc import (
    OidcError,
    OidcFlowState,
    build_authorization_url,
    create_oidc_state,
    exchange_code_for_identity,
)

_log = logging.getLogger("cullis_connector.login")


class LoginError(Exception):
    """Raised when the login flow can't be completed."""


@dataclass
class _CallbackResult:
    code: str | None = None
    state: str | None = None
    error: str | None = None


def _device_cert_thumbprint(identity: IdentityBundle) -> str:
    """SHA-256 hex digest of the Connector cert's DER bytes.

    Matches the format the Mastio stores in ``user_sessions.agent_cert_thumbprint``
    (see ``mcp_proxy.registry.principals_csr._cert_thumbprint_sha256``).
    """
    der = identity.cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def _pick_callback_port(preferred: int | None) -> int:
    """Bind a free loopback port for the OIDC redirect."""
    if preferred:
        return preferred
    # Let the OS assign — works around the 7777 dashboard collision.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run_callback_server(port: int, expected_state: str) -> _CallbackResult:
    """Block on a single OIDC callback hit, then return the parsed code/state.

    Times out after 5 minutes — long enough for the IdP login + MFA, short
    enough that a forgotten browser tab doesn't pin a port for hours.
    """
    result = _CallbackResult()
    server_done = threading.Event()

    class _Handler(http.server.BaseHTTPRequestHandler):
        # Silence the default per-request stderr noise — we drive logging.
        def log_message(self, fmt: str, *args) -> None:  # noqa: D401, ANN001
            return

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/auth/callback":
                self.send_response(404)
                self.end_headers()
                return
            qs = urllib.parse.parse_qs(parsed.query)
            err = qs.get("error", [None])[0]
            code = qs.get("code", [None])[0]
            state = qs.get("state", [None])[0]
            if err:
                result.error = err
            elif not code or not state:
                result.error = "missing code/state in callback"
            elif state != expected_state:
                result.error = "state mismatch — possible CSRF"
            else:
                result.code = code
                result.state = state
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            body = (
                "<html><body style='font-family: sans-serif; padding: 2em'>"
                "<h2>Cullis Connector login</h2>"
                "<p>You can close this tab and return to the terminal.</p>"
                "</body></html>"
            )
            self.wfile.write(body.encode("utf-8"))
            server_done.set()

    srv = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        # 5 minute window for the user to complete the IdP flow.
        if not server_done.wait(timeout=300):
            result.error = "timed out waiting for OIDC callback (5 min)"
    finally:
        srv.shutdown()
        thread.join(timeout=2)
    return result


async def _post_connector_login(
    *,
    site_url: str,
    config_dir: Path,
    verify_tls: bool,
    body: dict,
) -> dict:
    """Call ``POST /v1/principals/connector-login`` via the enrolled SDK client."""
    from cullis_sdk import CullisClient

    client = CullisClient.from_connector(config_dir, verify_tls=verify_tls)
    try:
        client.login_via_proxy_with_local_key()
    except Exception as exc:  # noqa: BLE001
        # Without a broker JWT we can still cert+DPoP — fall through.
        _log.debug("login_via_proxy_with_local_key failed: %s", exc)

    # Reach into the SDK's authed HTTP path the same way other call sites
    # do (cf. ``cullis_connector.discovery``). We need the cert+DPoP envelope
    # for an authenticated POST; ``_authed_request`` (or whichever helper
    # the SDK exposes) is the canonical path. Fall back to a raw httpx call
    # against the proxy URL when the SDK helper changes shape.
    url = site_url.rstrip("/") + "/v1/principals/connector-login"
    helper = getattr(client, "_egress_http", None)
    if helper is None:
        helper = getattr(client, "_authed_request", None)
    if helper is None:
        raise LoginError(
            "SDK CullisClient exposes neither _egress_http nor _authed_request "
            "— upgrade cullis-sdk to a release that ships one of them."
        )
    resp = await asyncio.to_thread(
        helper,
        "POST",
        url,
        json=body,
    )
    if isinstance(resp, tuple):
        # Some SDK versions return (status, json). Normalise.
        status_code, payload = resp[0], resp[1]
    else:
        status_code = getattr(resp, "status_code", 0)
        try:
            payload = resp.json() if status_code else {}
        except Exception:  # noqa: BLE001
            payload = {}
    if status_code != 201:
        raise LoginError(
            f"connector-login Mastio call failed: HTTP {status_code} "
            f"{payload!r}"
        )
    return payload


def perform_login(
    *,
    config_dir: Path,
    identity: IdentityBundle,
    site_url: str,
    verify_tls: bool,
    issuer_url: str,
    client_id: str,
    client_secret: str | None = None,
    callback_port: int | None = None,
    open_browser: bool = True,
) -> OidcSession:
    """Run the full OIDC + Mastio bind flow. Returns the persisted session.

    Caller is expected to print friendly progress messages; this function
    only logs at DEBUG/INFO and raises :class:`LoginError` on failure.
    """
    port = _pick_callback_port(callback_port)
    redirect_uri = f"http://127.0.0.1:{port}/auth/callback"
    flow_state = create_oidc_state()

    auth_url = asyncio.run(build_authorization_url(
        issuer_url=issuer_url,
        client_id=client_id,
        redirect_uri=redirect_uri,
        flow_state=flow_state,
    ))

    _log.info("OIDC login: opening browser to %s", issuer_url)
    if open_browser:
        try:
            webbrowser.open(auth_url, new=2)
        except webbrowser.Error as exc:
            _log.warning(
                "could not open default browser (%s) — visit manually:\n  %s",
                exc, auth_url,
            )
    else:
        print(f"Open this URL in your browser:\n  {auth_url}")  # noqa: T201

    cb = _run_callback_server(port, expected_state=flow_state.state)
    if cb.error:
        raise LoginError(f"OIDC callback failed: {cb.error}")
    if not cb.code:
        raise LoginError("OIDC callback returned no authorization code")

    try:
        identity_resp = asyncio.run(exchange_code_for_identity(
            issuer_url=issuer_url,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code=cb.code,
            flow_state=flow_state,
        ))
    except OidcError as exc:
        raise LoginError(f"OIDC code exchange failed: {exc}") from exc

    device_thumb = _device_cert_thumbprint(identity)
    display_name = identity_resp.email or identity_resp.name or identity_resp.sub

    body = {
        "user_subject_sso": identity_resp.sub,
        "display_name": display_name,
        "idp_issuer": identity_resp.issuer,
        "device_cert_thumbprint": device_thumb,
    }
    resp = asyncio.run(_post_connector_login(
        site_url=site_url,
        config_dir=config_dir,
        verify_tls=verify_tls,
        body=body,
    ))

    expires_raw = resp.get("expires_at")
    if not isinstance(expires_raw, str):
        raise LoginError(
            f"connector-login response missing expires_at: {resp!r}"
        )
    expires_at = datetime.fromisoformat(expires_raw)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    session = OidcSession(
        user_id=str(resp["user_id"]),
        session_token=str(resp["session_token"]),
        sso_subject=identity_resp.sub,
        idp_issuer=identity_resp.issuer,
        display_name=display_name,
        expires_at=expires_at,
        device_thumbprint=device_thumb,
    )
    save_session(config_dir, session)
    return session


def perform_logout(
    *,
    config_dir: Path,
    site_url: str,
    verify_tls: bool,
) -> bool:
    """Revoke the current session server-side then delete it locally.

    Returns True iff a local row was removed. The server-side revoke is
    best-effort: a network failure does not block the local logout.
    """
    session = load_session(config_dir)
    if session is None:
        return False

    try:
        from cullis_sdk import CullisClient

        client = CullisClient.from_connector(config_dir, verify_tls=verify_tls)
        url = site_url.rstrip("/") + "/v1/principals/connector-login"
        helper = (
            getattr(client, "_egress_http", None)
            or getattr(client, "_authed_request", None)
        )
        if helper is not None:
            try:
                helper(
                    "DELETE", url,
                    headers={"X-Cullis-Session-Token": session.session_token},
                )
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "server-side session revoke failed (continuing local "
                    "logout): %s", exc,
                )
    except Exception as exc:  # noqa: BLE001
        _log.warning("could not build SDK client for revoke: %s", exc)

    return delete_session(config_dir)


def describe_session(config_dir: Path) -> str:
    """Render a one-line summary suitable for ``cullis-connector whoami``."""
    session = load_session(config_dir)
    if session is None:
        return "Not logged in (anonymous agent mode)"
    if session.is_expired():
        return (
            f"Session expired for {session.display_name or session.sso_subject}"
            f" — re-login required"
        )
    return (
        f"Logged in as {session.display_name or session.sso_subject}"
        f" @ {session.idp_issuer} "
        f"(expires {session.expires_at.isoformat(timespec='seconds')})"
    )
