"""ADR-034 §1 + §3 — admin-only setup surface + wizard dispatcher.

Covers:

  * ``cullis_connector.setup_auth.verify_setup_request`` decision
    matrix (single bypass, completed refuse, bearer ok, HMAC ok,
    no-proof warn vs required).
  * ``cullis_connector.setup_auth.read_or_generate_setup_bearer``
    persistence + invalidation lifecycle.
  * ``cullis_connector.enrollment._check_mastio_version_for_shared_mode``
    refuses Mastio < 0.5 (PR-A compat blocker).
  * Setup wizard dispatcher (ADR-034 §3): ``/setup`` returns
    ``setup.html`` in single mode and ``setup_workload.html`` in
    shared mode so the wizard framing matches the deployment topology.
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
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
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
from cullis_connector.web import build_app


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


# ── Setup wizard dispatcher (ADR-034 §3) ────────────────────────────


def _setup_dispatcher_client(tmp_path, monkeypatch) -> TestClient:
    """Build the dashboard app with a clean tmp config_dir + identity
    forced to absent so ``/setup`` lands on the wizard rather than
    short-circuiting to ``/connected``.
    """
    import cullis_connector.web as _web

    monkeypatch.setattr(_web, "has_identity", lambda _: False)
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test:9443",
        verify_tls=False,
    )
    return TestClient(build_app(cfg))


def test_setup_get_renders_single_mode_template_by_default(
    tmp_path, monkeypatch,
):
    """In single mode the wizard keeps the legacy ``setup.html`` page
    with the "Your name / Work email" framing — the operator IS the
    single user, so the labelling is honest.
    """
    monkeypatch.delenv("AMBASSADOR_MODE", raising=False)
    monkeypatch.delenv("AUTH_MODE", raising=False)
    client = _setup_dispatcher_client(tmp_path, monkeypatch)
    resp = client.get("/setup", headers={"Origin": "http://testserver"})
    assert resp.status_code == 200, resp.text
    # Single-mode wizard advertises the personal framing.
    assert "Your name" in resp.text
    assert "Work email" in resp.text
    # And does NOT carry the workload-only banner from the shared
    # template — that copy is exclusive to ``setup_workload.html``.
    assert "You are configuring the Frontdesk workload" not in resp.text


def test_setup_get_renders_workload_template_in_shared_mode(
    tmp_path, monkeypatch,
):
    """In shared mode the wizard switches to ``setup_workload.html``
    so the operator sees workload-not-user framing. The
    ``principal_type=workload`` lock and the "end-users sign in
    separately" banner are the discriminators against single-mode
    output.
    """
    monkeypatch.setenv("AMBASSADOR_MODE", "shared")
    client = _setup_dispatcher_client(tmp_path, monkeypatch)
    resp = client.get(
        "/setup",
        headers={
            "Origin": "http://testserver",
            # PR-B middleware is in warn mode by default, so we don't
            # need a bearer to reach the handler. The test confirms
            # the dispatcher chooses the right template, not the
            # admin-proof check that PR-B already covers.
        },
    )
    assert resp.status_code == 200, resp.text
    assert "Register this <em>workload</em>" in resp.text
    assert "You are configuring the Frontdesk workload" in resp.text
    assert "Workload name" in resp.text
    assert "Operator admin email" in resp.text
    # Principal type is locked + visible to the operator. The shared
    # template carries the "End-users sign in separately" banner
    # copy that the single-mode wizard never mentions; assert it as
    # the discriminator instead of the more generic ``workload``
    # token (which appears in single mode too via field hints).
    assert "End-users sign in separately" in resp.text


def test_setup_get_redirects_to_connected_when_identity_exists(
    tmp_path, monkeypatch,
):
    """If the workload already enrolled, no wizard — the route 303s
    to ``/connected``. Independent of mode: in either topology a
    completed enrollment means the wizard is done.
    """
    import cullis_connector.web as _web

    monkeypatch.setattr(_web, "has_identity", lambda _: True)
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test:9443",
        verify_tls=False,
    )
    client = TestClient(build_app(cfg))
    resp = client.get(
        "/setup",
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/connected"


def test_mark_setup_completed_is_wired_to_save_identity_branch():
    """Regression for the gap left by PR-B (#810): the call site to
    ``mark_setup_completed`` is supposed to fire after a successful
    enrollment so the ``/setup/*`` middleware refuses any further
    access. PR-B introduced the helper but didn't wire it; this test
    pins the call site by reading the web.py source.

    A real end-to-end test of the polling enrollment loop would
    require a live Mastio fake — the source-level pin catches the
    "orphaned helper" failure mode cheaply while leaving the wiring
    visible to a future reader.
    """
    import inspect

    from cullis_connector import web as _web

    src = inspect.getsource(_web)
    assert "mark_setup_completed(config.config_dir)" in src, (
        "mark_setup_completed must be invoked from the save_identity "
        "success branch in shared mode (ADR-034 §1)"
    )
