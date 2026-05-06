"""Tests for cullis_connector.enrollment — device-code client flow.

Uses a stubbed httpx via ``monkeypatch`` to drive the poll state machine
through its possible outcomes without booting a real Site.
"""
from __future__ import annotations

import io
from pathlib import Path

import pytest

from cullis_connector import enrollment
from cullis_connector.enrollment import EnrollmentFailed, RequesterInfo, enroll
from cullis_connector.identity import has_identity, load_identity


# ── Fake httpx transport ────────────────────────────────────────────


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | str):
        self.status_code = status_code
        self._payload = payload
        self.text = payload if isinstance(payload, str) else ""

    def json(self) -> dict:
        if not isinstance(self._payload, dict):
            raise ValueError("not json")
        return self._payload


@pytest.fixture
def fake_httpx(monkeypatch):
    """Intercept httpx.post + httpx.get. Tests push canned responses via
    the returned ``Script`` helper."""

    class Script:
        def __init__(self):
            self.posts: list[dict] = []
            self.gets: list[str] = []
            self._post_responses: list[_FakeResponse] = []
            self._get_responses: list[_FakeResponse] = []

        def enqueue_post(self, resp: _FakeResponse) -> None:
            self._post_responses.append(resp)

        def enqueue_get(self, resp: _FakeResponse) -> None:
            self._get_responses.append(resp)

        def _post(self, url: str, **kwargs) -> _FakeResponse:
            self.posts.append({"url": url, **kwargs})
            if not self._post_responses:
                raise AssertionError(f"Unexpected POST to {url}")
            return self._post_responses.pop(0)

        def _get(self, url: str, **kwargs) -> _FakeResponse:
            self.gets.append(url)
            if not self._get_responses:
                raise AssertionError(f"Unexpected GET to {url}")
            return self._get_responses.pop(0)

    script = Script()
    monkeypatch.setattr(enrollment.httpx, "post", script._post)
    monkeypatch.setattr(enrollment.httpx, "get", script._get)
    # Kill the real sleep so polling is instant.
    monkeypatch.setattr(enrollment.time, "sleep", lambda _s: None)
    return script


def _approved_record(cert_pem: str = "approved-cert-pem") -> _FakeResponse:
    return _FakeResponse(
        200,
        {
            "session_id": "session-abc",
            "status": "approved",
            "agent_id": "acme::agent-mrossi",
            "cert_pem": cert_pem,
            "capabilities": ["procurement.read"],
        },
    )


def _pending_record() -> _FakeResponse:
    return _FakeResponse(
        200, {"session_id": "session-abc", "status": "pending"}
    )


def _start_response() -> _FakeResponse:
    return _FakeResponse(
        201,
        {
            "session_id": "session-abc",
            "status": "pending",
            "poll_url": "https://site.test/v1/enrollment/session-abc/status",
            "enroll_url": "https://site.test/enroll?session=session-abc",
            "poll_interval_s": 1,
            "expires_at": "2026-04-14T13:00:00+00:00",
        },
    )


# ── Tests ─────────────────────────────────────────────────────────


def test_enroll_happy_path_persists_identity(
    tmp_path: Path, fake_httpx, monkeypatch
):
    # Use a real self-signed cert so load_identity round-trips the x509 parse.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme::agent-mrossi")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )
    real_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(_pending_record())
    fake_httpx.enqueue_get(_approved_record(cert_pem=real_cert_pem))

    sink = io.StringIO()
    bundle = enroll(
        site_url="https://site.test",
        config_dir=tmp_path,
        requester=RequesterInfo(
            name="Mario Rossi", email="mario@acme.com", reason="Q2 project"
        ),
        verify_tls=True,
        poll_sink=sink,
    )

    assert has_identity(tmp_path)
    assert bundle.metadata.agent_id == "acme::agent-mrossi"
    assert bundle.metadata.capabilities == ["procurement.read"]
    # Re-load from disk and confirm it matches what `enroll` returned.
    reloaded = load_identity(tmp_path)
    assert reloaded.cert_pem == real_cert_pem


def test_enroll_raises_on_rejection(tmp_path: Path, fake_httpx):
    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(
        _FakeResponse(
            200,
            {
                "session_id": "session-abc",
                "status": "rejected",
                "rejection_reason": "Not a known user",
            },
        )
    )
    with pytest.raises(EnrollmentFailed) as exc:
        enroll(
            site_url="https://site.test",
            config_dir=tmp_path,
            requester=RequesterInfo(name="X", email="x@x.com"),
            poll_sink=io.StringIO(),
        )
    assert "Not a known user" in str(exc.value)
    assert not has_identity(tmp_path)


def test_enroll_raises_on_start_failure(tmp_path: Path, fake_httpx):
    fake_httpx.enqueue_post(_FakeResponse(500, "boom"))
    with pytest.raises(EnrollmentFailed) as exc:
        enroll(
            site_url="https://site.test",
            config_dir=tmp_path,
            requester=RequesterInfo(name="X", email="x@x.com"),
            poll_sink=io.StringIO(),
        )
    assert "HTTP 500" in str(exc.value)


def test_enroll_raises_on_expired(tmp_path: Path, fake_httpx):
    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(
        _FakeResponse(200, {"session_id": "session-abc", "status": "expired"})
    )
    with pytest.raises(EnrollmentFailed):
        enroll(
            site_url="https://site.test",
            config_dir=tmp_path,
            requester=RequesterInfo(name="X", email="x@x.com"),
            poll_sink=io.StringIO(),
        )


def test_enroll_submits_pubkey_not_private_key(tmp_path: Path, fake_httpx):
    """Sanity check that we never send private material to the Site."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    k = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(k.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(k, hashes.SHA256())
    )
    real_cert = cert.public_bytes(serialization.Encoding.PEM).decode()

    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(_approved_record(cert_pem=real_cert))

    enroll(
        site_url="https://site.test",
        config_dir=tmp_path,
        requester=RequesterInfo(name="X", email="x@x.com"),
        poll_sink=io.StringIO(),
    )

    submitted = fake_httpx.posts[0]["json"]
    assert "pubkey_pem" in submitted
    assert "PRIVATE KEY" not in submitted["pubkey_pem"]
    assert "PUBLIC KEY" in submitted["pubkey_pem"]
    assert submitted["requester_email"] == "x@x.com"


def test_enroll_injects_ambassador_mode_shared_into_device_info(
    tmp_path: Path, fake_httpx, monkeypatch,
):
    """``AMBASSADOR_MODE=shared`` env → flag travels in ``device_info`` JSON.

    The proxy reads the flag at approve() time to skip the auto-baseline
    binding. The Connector is the only place that knows it's running as
    a shared-mode workload (the proxy doesn't see the env var), so the
    declaration has to ride along with the enrollment payload.
    """
    monkeypatch.setenv("AMBASSADOR_MODE", "shared")

    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(_pending_record())
    fake_httpx.enqueue_get(
        _FakeResponse(200, {"session_id": "session-abc", "status": "rejected",
                            "rejection_reason": "stop test"}),
    )

    with pytest.raises(EnrollmentFailed):
        enroll(
            site_url="https://site.test",
            config_dir=tmp_path,
            requester=RequesterInfo(
                name="Frontdesk", email="fd@acme.com",
                device_info='{"host":"fd-1"}',
            ),
            poll_sink=io.StringIO(),
        )

    import json as _json
    submitted = fake_httpx.posts[0]["json"]
    assert "device_info" in submitted
    parsed = _json.loads(submitted["device_info"])
    assert parsed.get("ambassador_mode") == "shared"
    # Original device_info content is preserved.
    assert parsed.get("host") == "fd-1"


def test_enroll_no_env_leaves_device_info_unchanged(
    tmp_path: Path, fake_httpx, monkeypatch,
):
    """Single-mode default (no env) must not touch ``device_info``."""
    monkeypatch.delenv("AMBASSADOR_MODE", raising=False)

    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(
        _FakeResponse(200, {"session_id": "session-abc", "status": "rejected",
                            "rejection_reason": "stop test"}),
    )

    with pytest.raises(EnrollmentFailed):
        enroll(
            site_url="https://site.test",
            config_dir=tmp_path,
            requester=RequesterInfo(
                name="Daniele", email="d@acme.com",
                device_info="my-laptop",
            ),
            poll_sink=io.StringIO(),
        )

    submitted = fake_httpx.posts[0]["json"]
    # Plain string preserved verbatim — no JSON wrapping when not shared.
    assert submitted["device_info"] == "my-laptop"


def test_wrap_device_info_helper_handles_inputs():
    f = enrollment._wrap_device_info_with_shared_mode
    import json as _json

    # None / empty → bare {"ambassador_mode": "shared"}
    assert _json.loads(f(None)) == {"ambassador_mode": "shared"}
    assert _json.loads(f("")) == {"ambassador_mode": "shared"}

    # Plain string → nested under "raw"
    parsed = _json.loads(f("my-laptop"))
    assert parsed == {"ambassador_mode": "shared", "raw": "my-laptop"}

    # JSON object → merged, existing key wins
    parsed = _json.loads(f('{"ambassador_mode": "single", "host": "x"}'))
    assert parsed == {"ambassador_mode": "single", "host": "x"}

    # JSON object without ambassador_mode → flag added
    parsed = _json.loads(f('{"host": "x"}'))
    assert parsed == {"ambassador_mode": "shared", "host": "x"}

    # JSON array (not a dict) → nested under "raw"
    parsed = _json.loads(f('[1,2,3]'))
    assert parsed == {"ambassador_mode": "shared", "raw": "[1,2,3]"}
