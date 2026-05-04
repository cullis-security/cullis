"""Bearer auth + loopback enforcement for the Ambassador.

The Ambassador speaks Bearer to local clients and DPoP+mTLS to Cullis
cloud. The Bearer is a random 32-byte token generated at first start
and stored at ``<config_dir>/local.token`` mode 0600. Validation is
constant-time (``secrets.compare_digest``).

Loopback enforcement: every request whose ``request.client.host`` is
not in ``{127.0.0.1, ::1}`` is rejected with 403. This is a belt-and-
braces guard on top of the recommended bind ``--host 127.0.0.1``: if
the operator overrides the bind to ``0.0.0.0``, the Ambassador still
refuses non-loopback callers.
"""
from __future__ import annotations

import logging
import secrets
from pathlib import Path

from fastapi import HTTPException, Request

_log = logging.getLogger("cullis_connector.ambassador.auth")

# Loopback IP addresses. ``::ffff:127.0.0.1`` is what some HTTP clients
# advertise on dual-stack sockets — accept it explicitly.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "::ffff:127.0.0.1"})

# Header name for the Bearer token. Standard OpenAI clients send
# ``Authorization: Bearer <token>``.
_AUTH_HEADER = "authorization"

LOCAL_TOKEN_FILENAME = "local.token"


def ensure_local_token(config_dir: Path) -> str:
    """Return the local Bearer token, generating it on first call.

    The file is created with mode 0600 (owner read+write only).
    Subsequent calls read the existing file. The token is 32 random
    bytes hex-encoded (64 ASCII chars).
    """
    token_path = config_dir / LOCAL_TOKEN_FILENAME
    if token_path.exists():
        token = token_path.read_text(encoding="utf-8").strip()
        if token:
            return token
        _log.warning("local token file at %s is empty — regenerating", token_path)
    token = secrets.token_hex(32)
    config_dir.mkdir(parents=True, exist_ok=True)
    token_path.write_text(token + "\n", encoding="utf-8")
    try:
        token_path.chmod(0o600)
    except OSError:
        # Some filesystems (e.g. on Windows) ignore chmod. Logged at
        # info, not warning, because the local trust boundary is the
        # OS user not the file mode in those environments.
        _log.info("could not chmod 0600 on %s (filesystem may not support it)", token_path)
    _log.info("generated new local token at %s", token_path)
    return token


def require_loopback(request: Request) -> None:
    """Raise 403 unless the inbound TCP peer is loopback.

    Used as a FastAPI dependency on every Ambassador route.
    """
    host = request.client.host if request.client else None
    if host not in _LOOPBACK_HOSTS:
        _log.warning(
            "rejecting non-loopback request from %s on %s %s",
            host, request.method, request.url.path,
        )
        raise HTTPException(
            status_code=403,
            detail="Ambassador only accepts loopback connections",
        )


def require_bearer(expected_token: str):
    """Build a FastAPI dependency that validates the Bearer header.

    Returns a callable suitable for ``Depends(...)`` so each route can
    mount it without rebuilding the closure.
    """
    if not expected_token:
        raise ValueError("expected_token must be a non-empty string")

    def _checker(request: Request) -> None:
        raw = request.headers.get(_AUTH_HEADER, "")
        if not raw.lower().startswith("bearer "):
            raise HTTPException(
                status_code=401,
                detail="missing or non-Bearer Authorization header",
            )
        presented = raw.split(" ", 1)[1].strip()
        if not secrets.compare_digest(presented, expected_token):
            raise HTTPException(status_code=401, detail="invalid Bearer token")

    return _checker
