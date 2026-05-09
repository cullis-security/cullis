"""Unit tests for cullis_connector.identity.local_session — ADR-025 Phase 2.

Cookie issue/parse roundtrip, signature tamper detection, expiry,
encoding errors, CSRF token rotation, and TTL defaults. Pure-function
tests — no FastAPI / no DB.
"""
from __future__ import annotations

import time

import pytest

from cullis_connector.identity.local_session import (
    LOCAL_SESSION_COOKIE_NAME,
    LOCAL_SESSION_TTL_SEC,
    LocalSessionPayload,
    build_payload,
    issue_local_cookie,
    new_csrf_token,
    parse_local_cookie,
)


SECRET = b"\x00" * 32  # any 32-byte HMAC key works for the unit tests


# ── happy path ──────────────────────────────────────────────────────────


def test_constants_match_contract():
    assert LOCAL_SESSION_COOKIE_NAME == "cullis_local_session"
    assert LOCAL_SESSION_TTL_SEC == 8 * 3600


def test_roundtrip_preserves_all_fields():
    payload = build_payload(
        user_name="mario",
        must_change_password=True,
        principal_name="acme.test/acme/user/mario",
    )
    cookie = issue_local_cookie(payload, SECRET)
    parsed = parse_local_cookie(cookie, SECRET)
    assert parsed is not None
    assert parsed.user_name == "mario"
    assert parsed.principal_name == "acme.test/acme/user/mario"
    assert parsed.must_change_password is True
    assert parsed.csrf_token == payload.csrf_token
    assert parsed.iat == payload.iat
    assert parsed.exp == payload.exp


def test_principal_name_defaults_to_user_name():
    payload = build_payload(user_name="mario", must_change_password=False)
    assert payload.principal_name == "mario"


# ── TTL defaults ─────────────────────────────────────────────────────────


def test_default_ttl_is_eight_hours():
    now = 1_700_000_000
    payload = build_payload(
        user_name="mario", must_change_password=False, now=now,
    )
    assert payload.iat == now
    assert payload.exp == now + 8 * 3600


def test_explicit_ttl_respected():
    now = 1_700_000_000
    payload = build_payload(
        user_name="mario",
        must_change_password=False,
        ttl_seconds=900,
        now=now,
    )
    assert payload.exp == now + 900


def test_zero_or_too_long_ttl_raises():
    with pytest.raises(ValueError):
        build_payload(
            user_name="mario", must_change_password=False, ttl_seconds=0,
        )
    with pytest.raises(ValueError):
        build_payload(
            user_name="mario",
            must_change_password=False,
            ttl_seconds=24 * 3600 + 1,
        )


# ── expiry / clock skew ──────────────────────────────────────────────────


def test_expired_cookie_returns_none():
    now = 1_700_000_000
    payload = build_payload(
        user_name="mario", must_change_password=False, now=now,
        ttl_seconds=60,
    )
    cookie = issue_local_cookie(payload, SECRET)
    assert parse_local_cookie(cookie, SECRET, now=now + 60) is None
    assert parse_local_cookie(cookie, SECRET, now=now + 99999) is None


def test_future_iat_returns_none():
    """Cookie issued in the future = clock skew or replay; refuse it."""
    now = 1_700_000_000
    payload = build_payload(
        user_name="mario", must_change_password=False, now=now + 60,
    )
    cookie = issue_local_cookie(payload, SECRET)
    assert parse_local_cookie(cookie, SECRET, now=now) is None


def test_pre_expiry_returns_payload():
    now = 1_700_000_000
    payload = build_payload(
        user_name="mario", must_change_password=False, now=now,
    )
    cookie = issue_local_cookie(payload, SECRET)
    parsed = parse_local_cookie(cookie, SECRET, now=now + 60)
    assert parsed is not None
    assert parsed.user_name == "mario"


# ── signature tamper ─────────────────────────────────────────────────────


def test_tampered_signature_returns_none():
    payload = build_payload(user_name="mario", must_change_password=False)
    cookie = issue_local_cookie(payload, SECRET)
    body, sig = cookie.split(".", 1)
    bad = sig[:-1] + ("A" if sig[-1] != "A" else "B")
    assert parse_local_cookie(f"{body}.{bad}", SECRET) is None


def test_tampered_payload_returns_none():
    payload = build_payload(user_name="mario", must_change_password=False)
    cookie = issue_local_cookie(payload, SECRET)
    body, sig = cookie.split(".", 1)
    bad_body = body[:-1] + ("A" if body[-1] != "A" else "B")
    assert parse_local_cookie(f"{bad_body}.{sig}", SECRET) is None


def test_wrong_secret_returns_none():
    payload = build_payload(user_name="mario", must_change_password=False)
    cookie = issue_local_cookie(payload, SECRET)
    assert parse_local_cookie(cookie, b"\x99" * 32) is None


# ── encoding / structural errors ─────────────────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "no-dot-here",
        "...",
        "%%%.%%%",
        "a" * 5000,  # exceeds _MAX_COOKIE_BYTES
    ],
)
def test_malformed_cookie_returns_none(bad):
    assert parse_local_cookie(bad, SECRET) is None


def test_short_secret_rejected_on_issue():
    payload = build_payload(user_name="mario", must_change_password=False)
    with pytest.raises(ValueError):
        issue_local_cookie(payload, b"\x00" * 8)


def test_short_secret_rejected_on_parse():
    payload = build_payload(user_name="mario", must_change_password=False)
    cookie = issue_local_cookie(payload, SECRET)
    # If a caller passes a too-short secret to parse, fail closed.
    assert parse_local_cookie(cookie, b"\x00" * 8) is None


# ── CSRF token rotation ──────────────────────────────────────────────────


def test_csrf_token_rotates_on_each_build():
    a = build_payload(user_name="mario", must_change_password=False)
    b = build_payload(user_name="mario", must_change_password=False)
    assert a.csrf_token != b.csrf_token
    assert len(a.csrf_token) == 32
    assert all(c in "0123456789abcdef" for c in a.csrf_token)


def test_explicit_csrf_token_respected():
    payload = build_payload(
        user_name="mario", must_change_password=False, csrf_token="x" * 32,
    )
    assert payload.csrf_token == "x" * 32


def test_new_csrf_token_format():
    tok = new_csrf_token()
    assert len(tok) == 32
    int(tok, 16)  # raises if not hex


# ── must_change flag round-trips as a real bool ──────────────────────────


def test_must_change_true_round_trips_as_bool():
    payload = build_payload(user_name="mario", must_change_password=True)
    cookie = issue_local_cookie(payload, SECRET)
    parsed = parse_local_cookie(cookie, SECRET)
    assert parsed is not None
    assert parsed.must_change_password is True
    assert isinstance(parsed.must_change_password, bool)


def test_must_change_false_round_trips_as_bool():
    payload = build_payload(user_name="mario", must_change_password=False)
    cookie = issue_local_cookie(payload, SECRET)
    parsed = parse_local_cookie(cookie, SECRET)
    assert parsed is not None
    assert parsed.must_change_password is False
    assert isinstance(parsed.must_change_password, bool)


# ── direct dataclass JSON roundtrip ─────────────────────────────────────


def test_payload_json_canonical_keys():
    payload = LocalSessionPayload(
        user_name="mario",
        principal_name="mario",
        must_change_password=False,
        csrf_token="a" * 32,
        iat=1_700_000_000,
        exp=1_700_028_800,
    )
    raw = payload.as_json_bytes()
    # Sorted keys + compact separators — stable hash input for HMAC.
    assert raw == (
        b'{"csrf_token":"' + b"a" * 32 + b'",'
        b'"exp":1700028800,'
        b'"iat":1700000000,'
        b'"must_change_password":false,'
        b'"principal_name":"mario",'
        b'"user_name":"mario"}'
    )


def test_payload_from_json_missing_key_raises():
    import json
    raw = json.dumps({"user_name": "mario"}).encode()
    with pytest.raises(ValueError):
        LocalSessionPayload.from_json_bytes(raw)


def test_payload_from_json_non_object_raises():
    with pytest.raises(ValueError):
        LocalSessionPayload.from_json_bytes(b"[1,2,3]")


# ── live time path (smoke) ───────────────────────────────────────────────


def test_live_time_default_now_works():
    """Ensure passing no explicit ``now`` resolves through time.time."""
    payload = build_payload(user_name="mario", must_change_password=False)
    assert abs(payload.iat - int(time.time())) < 5
    cookie = issue_local_cookie(payload, SECRET)
    parsed = parse_local_cookie(cookie, SECRET)
    assert parsed is not None
