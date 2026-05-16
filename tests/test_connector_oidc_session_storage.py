"""ADR-032 Layer 2 — Connector OIDC session local JSON storage.

Pure unit tests for ``cullis_connector.identity.oidc_session``:
round-trip, atomic replace, 0600 permissions, expired-check behaviour.
"""
from __future__ import annotations

import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from cullis_connector.identity.oidc_session import (
    OidcSession,
    delete_session,
    load_session,
    save_session,
)


def _session(**overrides) -> OidcSession:
    base = dict(
        user_id="acme::user::alice",
        session_token="sess-abc",
        sso_subject="alice@acme.com",
        idp_issuer="https://idp.example.com",
        display_name="Alice",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        device_thumbprint="a" * 64,
    )
    base.update(overrides)
    return OidcSession(**base)


def test_save_and_load_round_trip(tmp_path):
    save_session(tmp_path, _session())
    loaded = load_session(tmp_path)
    assert loaded is not None
    assert loaded.user_id == "acme::user::alice"
    assert loaded.session_token == "sess-abc"
    assert loaded.idp_issuer == "https://idp.example.com"
    assert loaded.device_thumbprint == "a" * 64


def test_load_missing_returns_none(tmp_path):
    assert load_session(tmp_path) is None


def test_load_corrupt_returns_none(tmp_path):
    path = tmp_path / "oidc_session.json"
    path.write_text("{ not json")
    assert load_session(tmp_path) is None


def test_save_overwrites_previous(tmp_path):
    save_session(tmp_path, _session(session_token="first"))
    save_session(tmp_path, _session(session_token="second"))
    loaded = load_session(tmp_path)
    assert loaded is not None
    assert loaded.session_token == "second"


@pytest.mark.skipif(os.name == "nt", reason="POSIX-only permission bits")
def test_save_writes_0600(tmp_path):
    save_session(tmp_path, _session())
    mode = stat.S_IMODE(os.stat(tmp_path / "oidc_session.json").st_mode)
    assert mode == 0o600


def test_delete_returns_true_when_present(tmp_path):
    save_session(tmp_path, _session())
    assert delete_session(tmp_path) is True
    assert load_session(tmp_path) is None


def test_delete_returns_false_when_absent(tmp_path):
    assert delete_session(tmp_path) is False


def test_is_expired_past_expiry():
    s = _session(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert s.is_expired() is True


def test_is_expired_far_future():
    s = _session(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    assert s.is_expired() is False


# ── ADR-025 Phase 5 / F4 R3: source field ────────────────────────────────


def test_source_defaults_to_sso_for_backward_compat():
    """R1 callers construct OidcSession without ``source`` — the
    default must keep them on the SSO path so existing call-sites
    don't silently flip behaviour."""
    s = _session()
    assert s.source == "sso"


def test_save_and_load_round_trip_with_local_source(tmp_path):
    save_session(tmp_path, _session(source="local"))
    loaded = load_session(tmp_path)
    assert loaded is not None
    assert loaded.source == "local"


def test_load_legacy_file_without_source_field(tmp_path):
    """A R1 oidc_session.json on disk (pre-source-field) must still
    load — that's the upgrade path for a Connector that was logged in
    via SSO before the upgrade and continues to use the same session."""
    import json
    path = tmp_path / "oidc_session.json"
    legacy_payload = {
        "user_id": "acme::user::alice",
        "session_token": "legacy-token",
        "sso_subject": "alice@acme.com",
        "idp_issuer": "https://idp.example.com",
        "display_name": "Alice",
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat(),
        "device_thumbprint": "a" * 64,
        # no "source" key — pre-R3 file.
    }
    path.write_text(json.dumps(legacy_payload))
    loaded = load_session(tmp_path)
    assert loaded is not None
    assert loaded.source == "sso"


def test_load_rejects_unknown_source_value_safely(tmp_path):
    """Defence-in-depth: a tampered file with ``source: "admin"``
    must NOT silently grant any new privileges. The dataclass restricts
    to ``Literal["sso", "local"]`` — anything else falls back to sso so
    a forged file cannot opt into a future "trusted" tier without an
    explicit code change."""
    import json
    path = tmp_path / "oidc_session.json"
    tampered = {
        "user_id": "acme::user::alice",
        "session_token": "x",
        "sso_subject": "alice@acme.com",
        "idp_issuer": "https://idp.example.com",
        "display_name": None,
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat(),
        "device_thumbprint": "a" * 64,
        "source": "admin-omg",
    }
    path.write_text(json.dumps(tampered))
    loaded = load_session(tmp_path)
    assert loaded is not None
    assert loaded.source == "sso"
