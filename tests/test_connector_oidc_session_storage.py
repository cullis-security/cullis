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
