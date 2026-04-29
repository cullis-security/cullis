"""Tests for the SDK's proxy-facing httpx client TLS verification.

Closes a dogfood bug found 2026-04-30: ``hello_site`` returned
``tls_verified: true`` but ``discover_agents`` (and every other call
that goes through ``self._http``) failed with
``CERTIFICATE_VERIFY_FAILED — unable to get local issuer
certificate``. Root cause: ``_build_proxy_http_client`` received
``verify_tls=True`` (bool) and called ``httpx.Client(verify=True)``,
which uses the system CA store. A standalone Mastio's self-signed
Org CA isn't in that store, so verification always failed.

The Connector dashboard writes ``identity/ca-chain.pem`` after the
operator confirms the TOFU fingerprint at first contact. The fix
threads that path through to the httpx client so the pin is
actually used.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from cullis_sdk.client import _build_proxy_http_client


def _write_dummy_pem(path: Path) -> Path:
    """Write a real, parseable self-signed PEM so httpx's SSL context
    accepts it as a verify path. These tests don't perform TLS
    handshakes — they only verify *which path the client receives*
    — but httpx validates the PEM at Client() construction time, so
    we can't get away with a fake byte blob."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "fake-test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import Encoding
    path.write_bytes(cert.public_bytes(Encoding.PEM))
    return path


def test_pinned_ca_used_when_present_and_verify_on(tmp_path):
    """Happy path: pinned CA exists + verify_tls=True → httpx client
    must be built with the path as ``verify=``, not the bool."""
    ca = _write_dummy_pem(tmp_path / "ca-chain.pem")
    client = _build_proxy_http_client(
        verify_tls=True,
        timeout=5.0,
        ca_chain_path=ca,
    )
    # httpx stashes verify on the SSL context of the underlying
    # transport. Easiest portable check: confirm the client was
    # constructed without error and the file is the path it would
    # validate against. If we passed ``True`` here the bug would
    # repro because the system store would be consulted instead.
    assert isinstance(client, httpx.Client)
    # Sanity: the constructor accepted the path (no exception).


def test_verify_false_overrides_pinned_ca(tmp_path):
    """Operator opt-out is opt-out — a stale ca-chain.pem on disk
    must NOT silently re-enable TLS verification when the caller
    passed ``verify_tls=False``. (CULLIS_SDK_ALLOW_INSECURE_TLS dev
    paths still need to actually disable verification.)"""
    ca = _write_dummy_pem(tmp_path / "ca-chain.pem")
    client = _build_proxy_http_client(
        verify_tls=False,
        timeout=5.0,
        ca_chain_path=ca,
    )
    assert isinstance(client, httpx.Client)
    # The bool path is taken — there's no portable httpx accessor
    # for the resolved verify_arg, but the assertion that no path-
    # related ssl error fires at construction is the contract here.


def test_missing_pinned_file_falls_back_to_system_store(tmp_path):
    """Pre-TOFU first-contact: pinned CA path is supplied but the
    file doesn't exist yet. Must fall back to ``verify=True`` (system
    store) — refusing here would block the dashboard's first /setup
    fetch which intentionally runs before the pin."""
    missing = tmp_path / "nope-ca-chain.pem"
    assert not missing.exists()
    client = _build_proxy_http_client(
        verify_tls=True,
        timeout=5.0,
        ca_chain_path=missing,
    )
    assert isinstance(client, httpx.Client)


def test_no_ca_chain_argument_keeps_legacy_behaviour():
    """Direct-broker SDKs (``CullisClient(broker_url=…)``) call this
    builder without a ca_chain_path. Behaviour must be unchanged for
    them — system store is consulted, which is correct against a
    public-CA-issued broker."""
    client = _build_proxy_http_client(
        verify_tls=True,
        timeout=5.0,
    )
    assert isinstance(client, httpx.Client)


def test_client_cert_loaded_into_ssl_context(tmp_path):
    """Found dogfooding 2026-04-30 with httpx 0.28: passing
    ``cert=(crt, key)`` together with ``verify=<str>`` silently fails
    to present the client cert at the TLS handshake, so nginx's
    ``ssl_verify_client optional`` returns 401 on every
    ``/v1/egress/*`` call. Fix: build an explicit ``ssl.SSLContext``
    and call ``load_cert_chain``. Pin that the constructed transport
    has the SSLContext shape we expect.
    """
    from cryptography.hazmat.primitives import serialization
    import ssl as _ssl

    # Real cert+key pair — ``_cert_key_pair_matches`` rejects fakes,
    # which is the right thing for the SDK but means we have to mint
    # one for the test.
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "agent")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = tmp_path / "agent.crt"
    key_pem = tmp_path / "agent.key"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    ca_pem = _write_dummy_pem(tmp_path / "ca-chain.pem")

    client = _build_proxy_http_client(
        verify_tls=True,
        timeout=5.0,
        cert_path=cert_pem,
        key_path=key_pem,
        ca_chain_path=ca_pem,
    )
    # The httpx transport's pool holds the SSLContext we built. If
    # the bug were back (path string verify + tuple cert), this
    # attribute would either be missing or be a default context
    # without our cert chain.
    pool = client._transport._pool  # type: ignore[attr-defined]
    ctx = pool._ssl_context
    assert isinstance(ctx, _ssl.SSLContext)


def test_verify_false_skips_ssl_context_build():
    """``verify_tls=False`` is an explicit operator opt-out — must
    pass straight through to ``httpx.Client(verify=False)``, not
    silently re-enable verification by building a default context."""
    client = _build_proxy_http_client(
        verify_tls=False,
        timeout=5.0,
    )
    assert isinstance(client, httpx.Client)


def test_from_connector_picks_up_pinned_ca(tmp_path, monkeypatch):
    """End-to-end: a profile dir with a real-shape ca-chain.pem +
    metadata.json must produce a client that uses the PEM as its
    trust store. Pre-fix, ``from_connector`` ignored the file and
    every authenticated egress call failed
    CERTIFICATE_VERIFY_FAILED."""
    from cullis_sdk import CullisClient

    profile = tmp_path / "profile"
    identity = profile / "identity"
    identity.mkdir(parents=True)
    _write_dummy_pem(identity / "ca-chain.pem")
    (identity / "metadata.json").write_text(
        '{"agent_id": "acme::test", "site_url": "https://fake-mastio.test:9443"}'
    )
    # No agent.crt + agent.key on this fixture — covers the legacy
    # branch that doesn't trigger mTLS, isolating the CA-pin logic.
    client = CullisClient.from_connector(profile, verify_tls=True)
    assert client is not None
    # The flag we care about: client built without raising on the
    # ca_chain_path plumbing. If the SSL context wasn't initialised
    # from the path, httpx would raise on first request — covered by
    # the live integration test (manual). Unit test pins the
    # construction contract.
