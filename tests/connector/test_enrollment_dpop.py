"""F-B-11 Phase 3d — Connector generates + submits + persists the DPoP JWK.

Covers the end-to-end wiring between the three parties:

* ``cullis_connector.enrollment.enroll`` builds an EC P-256 keypair,
  submits the public JWK as ``dpop_jwk`` on ``/v1/enrollment/start``,
  and persists the private half at ``<identity_dir>/dpop.jwk`` (0600)
  on approval.

* ``cullis_connector.identity.store.save_identity`` refuses to write
  a public-only JWK (no ``d``).

* ``cullis_sdk.CullisClient.from_connector`` picks up the persisted
  JWK and reuses the same keypair across restarts, so the server's
  pinned thumbprint keeps matching.
"""
from __future__ import annotations

import io
import json
import os
import stat
from pathlib import Path

import pytest

from cullis_connector import enrollment
from cullis_connector.enrollment import RequesterInfo, enroll
from cullis_connector.identity import has_identity
from cullis_connector.identity.store import save_identity, IdentityMetadata


# ── Shared fake httpx harness (mirrors test_enrollment_client) ─────

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
    monkeypatch.setattr(enrollment.time, "sleep", lambda _s: None)
    return script


def _approved_record(cert_pem: str) -> _FakeResponse:
    return _FakeResponse(
        200,
        {
            "session_id": "session-abc",
            "status": "approved",
            "agent_id": "acme::agent-fb11",
            "cert_pem": cert_pem,
            "capabilities": ["order.read"],
        },
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
            "expires_at": "2099-01-01T00:00:00+00:00",
        },
    )


def _real_cert_pem() -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme::agent-fb11")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ── tests ──────────────────────────────────────────────────────────


def test_enroll_submits_dpop_jwk_in_start_body(tmp_path: Path, fake_httpx):
    """The Connector includes ``dpop_jwk`` in the body of
    ``/v1/enrollment/start`` — the field Phase 3b wired on the server
    (#207) to populate ``pending_enrollments.dpop_jkt``."""
    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(_approved_record(cert_pem=_real_cert_pem()))

    enroll(
        site_url="https://site.test",
        config_dir=tmp_path,
        requester=RequesterInfo(name="Mario Rossi", email="mario@acme.com"),
        verify_tls=True,
        poll_sink=io.StringIO(),
    )

    # One POST, and its body includes the public JWK.
    assert len(fake_httpx.posts) == 1
    body = fake_httpx.posts[0]["json"]
    assert "dpop_jwk" in body, "Connector did not submit dpop_jwk"
    jwk = body["dpop_jwk"]
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert "x" in jwk and "y" in jwk
    # Public JWK only — never send the private scalar on the wire.
    assert "d" not in jwk


def test_enroll_persists_dpop_key_on_approval(tmp_path: Path, fake_httpx):
    """On approval, the Connector writes ``<identity_dir>/dpop.jwk``
    with 0600 perms. The file is the private JWK that the SDK's
    ``from_connector`` will load on subsequent runs."""
    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(_approved_record(cert_pem=_real_cert_pem()))

    enroll(
        site_url="https://site.test",
        config_dir=tmp_path,
        requester=RequesterInfo(name="Mario", email="m@acme.com"),
        verify_tls=True,
        poll_sink=io.StringIO(),
    )

    assert has_identity(tmp_path)
    dpop_path = tmp_path / "identity" / "dpop.jwk"
    assert dpop_path.exists(), "dpop.jwk was not persisted on approval"

    mode = stat.S_IMODE(os.stat(dpop_path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    persisted = json.loads(dpop_path.read_text())
    assert "private_jwk" in persisted
    priv_jwk = persisted["private_jwk"]
    assert priv_jwk["kty"] == "EC"
    assert "d" in priv_jwk  # private scalar IS on disk (0600 local file)


def test_enroll_submitted_jwk_matches_persisted_jwk(
    tmp_path: Path, fake_httpx,
):
    """The public JWK submitted to the server must be the public half
    of the private JWK persisted locally — if they drift, the server's
    pinned thumbprint will never match the SDK's proofs."""
    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(_approved_record(cert_pem=_real_cert_pem()))

    enroll(
        site_url="https://site.test",
        config_dir=tmp_path,
        requester=RequesterInfo(name="x", email="x@y.z"),
        verify_tls=True,
        poll_sink=io.StringIO(),
    )

    submitted = fake_httpx.posts[0]["json"]["dpop_jwk"]
    persisted = json.loads(
        (tmp_path / "identity" / "dpop.jwk").read_text()
    )["private_jwk"]
    for field in ("kty", "crv", "x", "y"):
        assert submitted[field] == persisted[field], (
            f"drift on {field}: submitted {submitted[field]!r} vs "
            f"persisted {persisted[field]!r}"
        )


def test_save_identity_rejects_public_only_dpop_jwk(tmp_path: Path):
    """Guardrail on the storage layer: never persist a JWK without a
    private ``d`` — a public-only file is useless for signing and an
    operator who drops one here probably made a copy-paste mistake."""
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256R1())
    # Build a fake public-only JWK (no 'd').
    import base64
    nums = priv.public_key().public_numbers()
    pub_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode(),
    }

    metadata = IdentityMetadata(
        agent_id="acme::x",
        capabilities=[],
        site_url="https://site.test",
        issued_at="2026-04-18T00:00:00+00:00",
    )
    with pytest.raises(ValueError, match="'d'"):
        save_identity(
            config_dir=tmp_path,
            cert_pem=_real_cert_pem(),
            private_key=priv,
            ca_chain_pem=None,
            metadata=metadata,
            dpop_private_jwk=pub_jwk,  # missing 'd'
        )


def test_from_connector_loads_persisted_dpop_key(tmp_path: Path, fake_httpx):
    """End-to-end: after enroll persists the key, ``from_connector``
    loads it. Two calls on two different ``from_connector`` instances
    must surface the same thumbprint (server keeps matching)."""
    fake_httpx.enqueue_post(_start_response())
    fake_httpx.enqueue_get(_approved_record(cert_pem=_real_cert_pem()))

    enroll(
        site_url="https://site.test",
        config_dir=tmp_path,
        requester=RequesterInfo(name="x", email="x@y.z"),
        verify_tls=True,
        poll_sink=io.StringIO(),
    )

    from cullis_sdk import CullisClient
    cli_a = CullisClient.from_connector(tmp_path)
    cli_b = CullisClient.from_connector(tmp_path)
    assert cli_a._egress_dpop_key is not None
    assert cli_b._egress_dpop_key is not None
    assert cli_a._egress_dpop_key.thumbprint() == cli_b._egress_dpop_key.thumbprint()


def test_from_connector_without_dpop_jwk_generates(tmp_path: Path):
    """Legacy Connector identity (no ``dpop.jwk`` persisted): the SDK
    generates locally so users who upgrade the SDK without re-enrolling
    still get a DPoP path. The resulting thumbprint is NOT yet bound
    server-side — operator registers via #206 or re-enrolls."""
    # Build a minimal legacy identity on disk: cert + key + metadata +
    # api_key, but no dpop.jwk.
    from cryptography.hazmat.primitives.asymmetric import ec

    metadata_path = tmp_path / "identity" / "metadata.json"
    (tmp_path / "identity").mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps({
        "agent_id": "acme::legacy",
        "capabilities": [],
        "site_url": "http://site.test",
        "issued_at": "2026-04-18T00:00:00+00:00",
    }))
    (tmp_path / "identity" / "api_key").write_text("sk_local_legacy_" + "a" * 32 + "\n")
    priv = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives import serialization
    (tmp_path / "identity" / "agent.key").write_text(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
    )
    (tmp_path / "identity" / "agent.crt").write_text(_real_cert_pem())

    assert not (tmp_path / "identity" / "dpop.jwk").exists()

    from cullis_sdk import CullisClient
    cli = CullisClient.from_connector(tmp_path)
    assert cli._egress_dpop_key is not None
    # After the first from_connector, the generated key landed at
    # the expected path so a second load is idempotent.
    assert (tmp_path / "identity" / "dpop.jwk").exists()

    cli2 = CullisClient.from_connector(tmp_path)
    assert cli._egress_dpop_key.thumbprint() == cli2._egress_dpop_key.thumbprint()
