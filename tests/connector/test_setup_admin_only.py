"""ADR-034 §1 — admin-only setup surface in shared mode.

Covers:

  * ``cullis_connector.setup_auth.verify_setup_request`` decision
    matrix (single bypass, completed refuse, bearer ok, HMAC ok,
    no-proof warn vs required).
  * ``cullis_connector.setup_auth.read_or_generate_setup_bearer``
    persistence + invalidation lifecycle.
  * ``cullis_connector.enrollment._check_mastio_version_for_shared_mode``
    refuses Mastio < 0.5 (PR-A compat blocker).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from cullis_connector.enrollment import (
    EnrollmentFailed,
    _check_mastio_version_for_shared_mode,
    _parse_semver,
)
from cullis_connector.setup_auth import (
    ENFORCEMENT_REQUIRED,
    ENFORCEMENT_WARN,
    ENV_BEARER,
    ENV_ENFORCEMENT,
    ENV_HMAC_KEY,
    HMAC_REPLAY_WINDOW_S,
    SETUP_STATE_FILENAME,
    is_setup_completed,
    mark_setup_completed,
    read_or_generate_setup_bearer,
    read_setup_auth_enforcement,
    verify_setup_request,
)


# ── verify_setup_request ───────────────────────────────────────────


def test_single_mode_bypasses_all_checks(tmp_path):
    """``AMBASSADOR_MODE`` unset → single mode → bypass. The
    require_local_only loopback gate on the ambassador is the
    authoritative guard for Cullis Chat desktop; this middleware
    only fires in shared.
    """
    outcome = verify_setup_request(
        config_dir=tmp_path,
        method="GET",
        path="/setup",
        headers={},
        query_params={},
        body_bytes=b"",
        env={},
    )
    assert outcome.allowed is True
    assert outcome.reason == "single_mode_bypass"


def test_shared_mode_no_proof_warn_by_default(tmp_path):
    """Default enforcement is ``warn`` — middleware must let the
    request through (the audit warning is logged separately). Without
    this, the v0.5.0 release would break every existing Frontdesk
    deployment the moment they upgrade.
    """
    env = {"AMBASSADOR_MODE": "shared"}
    outcome = verify_setup_request(
        config_dir=tmp_path,
        method="GET",
        path="/setup",
        headers={},
        query_params={},
        body_bytes=b"",
        env=env,
    )
    assert outcome.allowed is True
    assert outcome.reason == "no_proof_warn"
    assert outcome.enforcement == ENFORCEMENT_WARN


def test_shared_mode_no_proof_refused_in_required(tmp_path):
    env = {
        "AMBASSADOR_MODE": "shared",
        ENV_ENFORCEMENT: ENFORCEMENT_REQUIRED,
    }
    outcome = verify_setup_request(
        config_dir=tmp_path,
        method="POST",
        path="/setup/pin-ca",
        headers={},
        query_params={},
        body_bytes=b"",
        env=env,
    )
    assert outcome.allowed is False
    assert outcome.reason == "no_proof_refused"
    assert outcome.enforcement == ENFORCEMENT_REQUIRED


def test_shared_mode_bearer_authorization_header_accepted(tmp_path):
    env = {
        "AMBASSADOR_MODE": "shared",
        ENV_BEARER: "deadbeef",
        ENV_ENFORCEMENT: ENFORCEMENT_REQUIRED,
    }
    outcome = verify_setup_request(
        config_dir=tmp_path,
        method="GET",
        path="/setup",
        headers={"authorization": "Bearer deadbeef"},
        query_params={},
        body_bytes=b"",
        env=env,
    )
    assert outcome.allowed is True
    assert outcome.reason == "bearer_ok"


def test_shared_mode_bearer_query_param_accepted(tmp_path):
    """The query-param fallback covers the ``GET /setup`` browser
    landing where setting an ``Authorization`` header is awkward.
    """
    env = {
        "AMBASSADOR_MODE": "shared",
        ENV_BEARER: "deadbeef",
        ENV_ENFORCEMENT: ENFORCEMENT_REQUIRED,
    }
    outcome = verify_setup_request(
        config_dir=tmp_path,
        method="GET",
        path="/setup",
        headers={},
        query_params={"setup_token": "deadbeef"},
        body_bytes=b"",
        env=env,
    )
    assert outcome.allowed is True
    assert outcome.reason == "bearer_ok"


def test_shared_mode_wrong_bearer_refused(tmp_path):
    env = {
        "AMBASSADOR_MODE": "shared",
        ENV_BEARER: "deadbeef",
        ENV_ENFORCEMENT: ENFORCEMENT_REQUIRED,
    }
    outcome = verify_setup_request(
        config_dir=tmp_path,
        method="GET",
        path="/setup",
        headers={"authorization": "Bearer notthekey"},
        query_params={},
        body_bytes=b"",
        env=env,
    )
    assert outcome.allowed is False
    assert outcome.reason == "no_proof_refused"


def test_shared_mode_hmac_signature_accepted(tmp_path):
    hmac_key = "ci-shared-secret"
    body = b'{"site_url":"https://mastio"}'
    path = "/setup/pin-ca"
    method = "POST"
    ts_ms = int(time.time() * 1000)
    payload = f"{ts_ms}|{method}|{path}|{hashlib.sha256(body).hexdigest()}"
    sig = hmac.new(
        hmac_key.encode(), payload.encode(), hashlib.sha256,
    ).hexdigest()

    env = {
        "AMBASSADOR_MODE": "shared",
        ENV_HMAC_KEY: hmac_key,
        ENV_ENFORCEMENT: ENFORCEMENT_REQUIRED,
    }
    outcome = verify_setup_request(
        config_dir=tmp_path,
        method=method,
        path=path,
        headers={"x-cullis-setup-sig": f"ts={ts_ms},sig={sig}"},
        query_params={},
        body_bytes=body,
        env=env,
    )
    assert outcome.allowed is True
    assert outcome.reason == "hmac_ok"


def test_shared_mode_hmac_replay_rejected(tmp_path):
    """A signature older than ``HMAC_REPLAY_WINDOW_S`` is refused
    even when the digest still verifies cryptographically.
    """
    hmac_key = "ci-shared-secret"
    body = b""
    path = "/setup"
    method = "GET"
    ts_ms = int((time.time() - HMAC_REPLAY_WINDOW_S - 60) * 1000)
    payload = f"{ts_ms}|{method}|{path}|{hashlib.sha256(body).hexdigest()}"
    sig = hmac.new(
        hmac_key.encode(), payload.encode(), hashlib.sha256,
    ).hexdigest()

    env = {
        "AMBASSADOR_MODE": "shared",
        ENV_HMAC_KEY: hmac_key,
        ENV_ENFORCEMENT: ENFORCEMENT_REQUIRED,
    }
    outcome = verify_setup_request(
        config_dir=tmp_path,
        method=method,
        path=path,
        headers={"x-cullis-setup-sig": f"ts={ts_ms},sig={sig}"},
        query_params={},
        body_bytes=body,
        env=env,
    )
    assert outcome.allowed is False
    assert outcome.reason == "no_proof_refused"


def test_completed_setup_refuses_even_with_valid_bearer(tmp_path):
    """Once ``mark_setup_completed`` runs, no proof gets the caller in.
    Operator escape hatch is to redeploy the container with fresh
    state, never to re-grant via the existing bearer.
    """
    mark_setup_completed(tmp_path)
    assert is_setup_completed(tmp_path) is True
    env = {
        "AMBASSADOR_MODE": "shared",
        ENV_BEARER: "deadbeef",
        ENV_ENFORCEMENT: ENFORCEMENT_REQUIRED,
    }
    outcome = verify_setup_request(
        config_dir=tmp_path,
        method="GET",
        path="/setup",
        headers={"authorization": "Bearer deadbeef"},
        query_params={},
        body_bytes=b"",
        env=env,
    )
    assert outcome.allowed is False
    assert outcome.reason == "completed_refused"


# ── read_or_generate_setup_bearer ───────────────────────────────────


def test_bearer_generates_once_persists_on_disk(tmp_path):
    env = {"AMBASSADOR_MODE": "shared"}
    bearer_1 = read_or_generate_setup_bearer(tmp_path, env=env)
    bearer_2 = read_or_generate_setup_bearer(tmp_path, env=env)
    assert bearer_1 is not None
    assert bearer_1 == bearer_2
    state = json.loads(
        (tmp_path / SETUP_STATE_FILENAME).read_text(encoding="utf-8"),
    )
    assert state["bearer"] == bearer_1
    # 32 bytes hex = 64 chars; the banner relies on this size budget.
    assert len(bearer_1) == 64


def test_bearer_env_overrides_disk(tmp_path):
    """Env wins so an operator can rotate the bearer without touching
    the file. The persisted bearer stays on disk as a fallback for
    restarts that don't carry the env.
    """
    Path(tmp_path / SETUP_STATE_FILENAME).write_text(
        json.dumps({"bearer": "old-disk-bearer"}), encoding="utf-8",
    )
    env = {"AMBASSADOR_MODE": "shared", ENV_BEARER: "env-bearer"}
    assert read_or_generate_setup_bearer(tmp_path, env=env) == "env-bearer"


def test_bearer_none_in_single_mode(tmp_path):
    assert read_or_generate_setup_bearer(tmp_path, env={}) is None


def test_bearer_none_after_completed(tmp_path):
    env = {"AMBASSADOR_MODE": "shared"}
    read_or_generate_setup_bearer(tmp_path, env=env)
    mark_setup_completed(tmp_path)
    assert read_or_generate_setup_bearer(tmp_path, env=env) is None


# ── read_setup_auth_enforcement ─────────────────────────────────────


def test_enforcement_default_warn():
    assert read_setup_auth_enforcement({}) == ENFORCEMENT_WARN


def test_enforcement_required_value():
    assert (
        read_setup_auth_enforcement({ENV_ENFORCEMENT: "required"})
        == ENFORCEMENT_REQUIRED
    )


def test_enforcement_typo_falls_back_to_warn():
    assert (
        read_setup_auth_enforcement({ENV_ENFORCEMENT: "strict"})
        == ENFORCEMENT_WARN
    )


# ── Mastio version probe ────────────────────────────────────────────


def test_version_probe_passes_on_0_5_0():
    response = httpx.Response(200, json={"status": "ok", "version": "0.5.0"})
    with patch.object(httpx, "get", return_value=response):
        _check_mastio_version_for_shared_mode(
            site_url="https://mastio.test",
            verify_tls=False,
            timeout_s=5.0,
        )


def test_version_probe_passes_on_dev():
    """``CULLIS_MASTIO_VERSION`` falls back to ``dev`` for source-tree
    runs; the probe must accept that so dogfood from a checkout still
    enrolls. Production images always inject the semver.
    """
    response = httpx.Response(200, json={"status": "ok", "version": "dev"})
    with patch.object(httpx, "get", return_value=response):
        _check_mastio_version_for_shared_mode(
            site_url="https://mastio.test",
            verify_tls=False,
            timeout_s=5.0,
        )


def test_version_probe_refuses_pre_0_5():
    response = httpx.Response(200, json={"status": "ok", "version": "0.4.5"})
    with patch.object(httpx, "get", return_value=response):
        with pytest.raises(EnrollmentFailed) as excinfo:
            _check_mastio_version_for_shared_mode(
                site_url="https://mastio.test",
                verify_tls=False,
                timeout_s=5.0,
            )
    msg = str(excinfo.value)
    assert "0.4.5" in msg
    assert "0.5" in msg
    assert "ADR-034" in msg


def test_version_probe_refuses_unreachable_mastio():
    with patch.object(
        httpx, "get",
        side_effect=httpx.ConnectError("Connection refused"),
    ):
        with pytest.raises(EnrollmentFailed) as excinfo:
            _check_mastio_version_for_shared_mode(
                site_url="https://mastio.test",
                verify_tls=False,
                timeout_s=5.0,
            )
    assert "/health" in str(excinfo.value)


def test_parse_semver_handles_rc_and_v_prefix():
    assert _parse_semver("0.5.0") == (0, 5, 0)
    assert _parse_semver("v0.5.0") == (0, 5, 0)
    assert _parse_semver("0.5.0-rc1") == (0, 5, 0)
    assert _parse_semver("0.5.0+gha.42") == (0, 5, 0)
    assert _parse_semver("dev") is None
    assert _parse_semver("") is None
    assert _parse_semver("not-a-version") is None
