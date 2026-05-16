"""Local persistence of the Connector's user session (ADR-032 Layer 2).

After a successful ``cullis-connector login`` (SSO path) OR a successful
local-auth login through the Connector's dashboard (ADR-025 Phase 5 /
F4 R3 path), the Mastio mints a session token bound to the Connector's
enrolled agent identity + the user identity. The Connector keeps a
single JSON row per profile under:

    ~/.cullis/<profile>/oidc_session.json   (chmod 600)

The filename is kept as ``oidc_session.json`` for backward compat with
R1 deployments; the file now carries a ``source`` field so both SSO
and local-auth sessions share the same persistence + load path.

The MCP envelope propagation layer reads this file on every outbound
call to add ``X-Cullis-Session-Token`` + ``X-Cullis-On-Behalf-Of-User``
headers when the session is still alive.

JSON-on-disk instead of sqlite is deliberate: one row total per device,
no concurrent writers, file-locking via atomic replace is enough.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

_log = logging.getLogger("cullis_connector.identity.oidc_session")

OIDC_SESSION_FILENAME = "oidc_session.json"


SessionSource = Literal["sso", "local"]


@dataclass(frozen=True)
class OidcSession:
    """In-memory view of the persisted Connector user session.

    The dataclass name is kept as ``OidcSession`` for backward compat
    with R1 import sites; the ``source`` field distinguishes SSO and
    local-auth sessions. When ``source == "local"`` the
    ``sso_subject`` field carries the local username (prefixed
    ``local:<user_name>`` by the Mastio attribution endpoint) and
    ``idp_issuer`` is the literal ``"local"``.
    """

    user_id: str
    session_token: str
    sso_subject: str
    idp_issuer: str
    display_name: str | None
    expires_at: datetime
    device_thumbprint: str
    source: SessionSource = "sso"

    def is_expired(self, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.expires_at <= now

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "session_token": self.session_token,
            "sso_subject": self.sso_subject,
            "idp_issuer": self.idp_issuer,
            "display_name": self.display_name,
            "expires_at": self.expires_at.astimezone(timezone.utc).isoformat(),
            "device_thumbprint": self.device_thumbprint,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "OidcSession":
        raw_exp = data["expires_at"]
        exp = datetime.fromisoformat(raw_exp)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        # Backward compat: R1 files don't carry ``source``. Default to
        # ``"sso"`` so a legacy oidc_session.json still loads.
        raw_source = data.get("source", "sso")
        source: SessionSource = "local" if raw_source == "local" else "sso"
        return cls(
            user_id=str(data["user_id"]),
            session_token=str(data["session_token"]),
            sso_subject=str(data["sso_subject"]),
            idp_issuer=str(data["idp_issuer"]),
            display_name=data.get("display_name"),
            expires_at=exp,
            device_thumbprint=str(data["device_thumbprint"]),
            source=source,
        )


def _session_path(config_dir: Path) -> Path:
    return config_dir / OIDC_SESSION_FILENAME


def load_session(config_dir: Path) -> OidcSession | None:
    """Return the persisted session, or None when none exists / unreadable."""
    path = _session_path(config_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return OidcSession.from_dict(data)
    except (OSError, ValueError, KeyError) as exc:
        _log.warning("oidc_session: failed to load %s — %s", path, exc)
        return None


def save_session(config_dir: Path, session: OidcSession) -> None:
    """Atomic-write the session JSON with chmod 0600."""
    config_dir.mkdir(parents=True, exist_ok=True)
    path = _session_path(config_dir)
    payload = json.dumps(session.to_dict(), separators=(",", ":"), sort_keys=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=".oidc_session.", suffix=".json.tmp", dir=str(config_dir),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def delete_session(config_dir: Path) -> bool:
    """Remove the persisted session file. Returns True iff a row was deleted."""
    path = _session_path(config_dir)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
