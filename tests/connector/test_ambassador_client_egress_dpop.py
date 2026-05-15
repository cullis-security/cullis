"""AmbassadorClient populates _egress_dpop_key on the SDK instance
when a dpop_key_path is provided.

Follow-up to PR #724 (SDK chat completion → egress path). Without
this wiring, the Connector ambassador builds a CullisClient via the
basic constructor + login_from_pem, leaving _egress_dpop_key None;
the chat path then arrives at Mastio without a DPoP header and is
refused on the cert-pinned route. Tests pin both branches:

* dpop_key_path provided → SDK._egress_dpop_key set, thumbprint
  matches the on-disk dpop.jwk
* dpop_key_path absent → back-compat, _egress_dpop_key stays None
"""
from __future__ import annotations

import pytest


class _FakeCullisClient:
    """Stand-in that mirrors the relevant SDK surface AmbassadorClient
    touches. Avoids spinning up the real CullisClient (which would
    need an HTTPS Mastio reachable to complete login_from_pem)."""

    def __init__(self, site_url, *, verify_tls=True, timeout=10.0):
        self.site_url = site_url
        self._verify_tls = verify_tls
        self.token = None
        self._egress_dpop_key = None
        self._dpop_privkey = None
        self.agent_id = None

    def login_from_pem(self, agent_id, org_id, cert_pem, key_pem, **kw):
        self.agent_id = agent_id
        # Mirror the SDK behaviour: login mints an ephemeral DPoP for
        # the bearer-DPoP path. _egress_dpop_key is untouched.
        self._dpop_privkey = object()


@pytest.fixture(autouse=True)
def _patch_sdk(monkeypatch):
    import cullis_sdk
    monkeypatch.setattr(cullis_sdk, "CullisClient", _FakeCullisClient)
    yield


def _self_signed_pair(common_name: str) -> tuple[str, str]:
    """Mint a self-signed cert + matching private key PEM for the
    AmbassadorClient constructor. The cert content does not have to
    be valid in this test; only the constructor arity matters."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def test_egress_dpop_key_populated_when_path_given(tmp_path):
    """Happy path: pass dpop_key_path to the holder, get() returns a
    client whose _egress_dpop_key matches the on-disk file's
    thumbprint."""
    from cullis_connector.ambassador.client import AmbassadorClient
    from cullis_sdk.dpop import DpopKey

    dpop_path = tmp_path / "dpop.jwk"
    # Pre-generate the file so the persistent thumbprint is fixed.
    seeded = DpopKey.generate(path=dpop_path)
    expected_jkt = seeded.thumbprint()

    cert_pem, key_pem = _self_signed_pair("demo-org::alice")

    holder = AmbassadorClient(
        site_url="https://mastio.test",
        agent_id="demo-org::alice",
        org_id="demo-org",
        cert_pem=cert_pem,
        key_pem=key_pem,
        verify_tls=False,
        dpop_key_path=dpop_path,
    )
    client = holder.get()

    assert client._egress_dpop_key is not None, (
        "_egress_dpop_key must be populated when dpop_key_path is given; "
        "otherwise the SDK chat path 401s on Mastio's cert-pinned route"
    )
    assert client._egress_dpop_key.thumbprint() == expected_jkt


def test_egress_dpop_key_none_when_path_absent(tmp_path):
    """Back-compat: legacy callers that don't pass dpop_key_path
    continue to get a client with _egress_dpop_key None (chat path
    still won't work for them, but the bearer-DPoP routes do)."""
    from cullis_connector.ambassador.client import AmbassadorClient

    cert_pem, key_pem = _self_signed_pair("demo-org::alice")

    holder = AmbassadorClient(
        site_url="https://mastio.test",
        agent_id="demo-org::alice",
        org_id="demo-org",
        cert_pem=cert_pem,
        key_pem=key_pem,
        verify_tls=False,
        # dpop_key_path intentionally omitted
    )
    client = holder.get()
    assert client._egress_dpop_key is None


def test_egress_dpop_key_load_failure_does_not_abort_build(
    tmp_path, monkeypatch,
):
    """If the on-disk dpop.jwk is unreadable (permission denied,
    corrupted file), build still returns a client so the bearer-DPoP
    routes keep working. The operator sees a warning and the chat
    path will 401 on its own with a clearer Mastio detail."""
    from cullis_connector.ambassador.client import AmbassadorClient
    from cullis_sdk import dpop as _dpop

    def _boom(*a, **kw):
        raise OSError("simulated: cannot read dpop.jwk")

    # AmbassadorClient._build uses load() / generate() (not
    # load_or_generate, whose signature is agent_id-based). Patch both
    # so the failure surfaces regardless of whether the path exists.
    monkeypatch.setattr(_dpop.DpopKey, "load", _boom)
    monkeypatch.setattr(_dpop.DpopKey, "generate", _boom)

    cert_pem, key_pem = _self_signed_pair("demo-org::alice")
    holder = AmbassadorClient(
        site_url="https://mastio.test",
        agent_id="demo-org::alice",
        org_id="demo-org",
        cert_pem=cert_pem,
        key_pem=key_pem,
        verify_tls=False,
        dpop_key_path=tmp_path / "dpop.jwk",
    )
    client = holder.get()
    # Build succeeded; chat path is the only thing that will fail later.
    assert client is not None
    assert client._egress_dpop_key is None
