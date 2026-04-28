"""ADR-011 Phase 2 — unified SDK runtime + enrollment helpers.

Covers:
  - ``from_api_key_file`` reads credentials from disk and returns a
    runtime-ready client.
  - ``enroll_via_byoca`` POSTs the Mastio endpoint, persists API key
    + DPoP JWK, and returns a client with those credentials wired.
  - ``enroll_via_spiffe`` same shape, different body + endpoint path.
  - Persistence layout matches the ADR-011 contract:
    ``<persist_to>/{api-key, dpop.jwk, agent.json}`` with 0600 on
    secrets.
  - ``from_spiffe_workload_api`` + ``login_from_pem`` emit
    ``DeprecationWarning`` — the sunset signal operators should see
    at call time.
  - ``enable_dpop=False`` omits the DPoP JWK from the enrollment body
    and from the persisted layout.

No live Mastio: the enroll helpers call the endpoint through a
patched ``httpx.Client`` that returns a canned success body. The
``internal_agents`` row is not exercised — the Phase 1b/1c test
suites already cover that.
"""
from __future__ import annotations

import json
import warnings

import httpx
import pytest


# ── fixtures ─────────────────────────────────────────────────────────────


class _StubResponse:
    """Minimal ``httpx.Response`` surface the SDK consumes on the enroll
    hot path — status_code, text, .json()."""

    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self) -> dict:
        return self._payload


@pytest.fixture
def patched_httpx(monkeypatch):
    """Intercept ``httpx.Client.post`` calls the enroll helpers make.

    Returns a dict the test can poke at to check URL / headers / body,
    and can set ``.next_response`` to any ``_StubResponse`` before
    issuing the SDK call.
    """
    state: dict = {"calls": [], "next_response": None}

    class _StubClient:
        def __init__(self, *args, **kwargs):
            pass

        def post(self, url, *, json=None, headers=None):
            state["calls"].append({"url": url, "json": json, "headers": headers})
            resp = state["next_response"]
            assert resp is not None, "test forgot to set next_response"
            return resp

        def close(self):
            pass

    monkeypatch.setattr(httpx, "Client", _StubClient)
    return state


# ── from_identity_dir (ADR-014) ──────────────────────────────────────────


def test_from_identity_dir_loads_cert_and_dpop(tmp_path):
    from cullis_sdk import CullisClient
    from cullis_sdk.dpop import DpopKey
    from tests._mtls_helpers import mint_agent_cert

    cert_pem, key_pem = mint_agent_cert(org_id="orga", agent_name="alice")
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text(cert_pem)
    key_path.write_text(key_pem)

    dpop_key = DpopKey.generate(path=tmp_path / "dpop.jwk")

    client = CullisClient.from_identity_dir(
        "http://proxy-a:9100",
        cert_path=cert_path,
        key_path=key_path,
        dpop_key_path=tmp_path / "dpop.jwk",
        agent_id="orga::alice",
        org_id="orga",
    )

    assert client._proxy_agent_id == "orga::alice"
    assert client._proxy_org_id == "orga"
    assert client._egress_dpop_key is not None
    # Loaded key must match the one we wrote — thumbprint equality
    # is a sharper assertion than comparing the JWK dict byte-for-byte.
    assert client._egress_dpop_key.thumbprint() == dpop_key.thumbprint()


def test_from_identity_dir_without_dpop_works(tmp_path):
    from cullis_sdk import CullisClient
    from tests._mtls_helpers import mint_agent_cert

    cert_pem, key_pem = mint_agent_cert(org_id="orga", agent_name="alice")
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text(cert_pem)
    key_path.write_text(key_pem)

    client = CullisClient.from_identity_dir(
        "http://proxy-a:9100",
        cert_path=cert_path,
        key_path=key_path,
    )
    assert client._egress_dpop_key is None


def test_from_api_key_file_deprecated_and_requires_cert(tmp_path):
    """The legacy ``from_api_key_file`` entrypoint emits a deprecation
    warning and refuses to build a client without cert+key — under PR-C
    the api_key path is gone so it would silently authenticate to nothing."""
    import warnings as _warnings
    from cullis_sdk import CullisClient

    with pytest.raises(ValueError, match="cert_path and key_path"):
        with _warnings.catch_warnings():
            _warnings.simplefilter("ignore")
            CullisClient.from_api_key_file(
                "http://proxy-a:9100",
                api_key_path=tmp_path / "ignored",
            )


# ── enroll_via_byoca ─────────────────────────────────────────────────────


def test_enroll_via_byoca_posts_and_persists(tmp_path, patched_httpx):
    from cullis_sdk import CullisClient

    patched_httpx["next_response"] = _StubResponse(201, {
        "agent_id": "orga::alice",
        "cert_thumbprint": "0" * 64,
        "spiffe_id": None,
        "dpop_jkt": None,  # server echoes whatever we sent
    })

    client = CullisClient.enroll_via_byoca(
        "http://proxy-a:9100",
        admin_secret="top-secret",
        agent_name="alice",
        cert_pem="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
        private_key_pem="-----BEGIN EC PRIVATE KEY-----\nY\n-----END EC PRIVATE KEY-----\n",
        capabilities=["order.read"],
        persist_to=tmp_path / "identity",
    )

    # HTTP call shape
    call = patched_httpx["calls"][0]
    assert call["url"] == "http://proxy-a:9100/v1/admin/agents/enroll/byoca"
    assert call["headers"]["X-Admin-Secret"] == "top-secret"
    assert call["json"]["agent_name"] == "alice"
    assert call["json"]["capabilities"] == ["order.read"]
    # enable_dpop default True → SDK generated a JWK and attached it
    assert "dpop_jwk" in call["json"]
    assert call["json"]["dpop_jwk"]["kty"] == "EC"
    assert "d" not in call["json"]["dpop_jwk"]  # private material never shipped

    # Client credentials wired (ADR-014: agent_id only — cert is the credential)
    assert client._proxy_agent_id == "orga::alice"
    assert client._proxy_org_id == "orga"
    assert client._egress_dpop_key is not None

    # Persisted layout (no api-key file under PR-C)
    persist = tmp_path / "identity"
    assert (persist / "dpop.jwk").exists()
    agent_meta = json.loads((persist / "agent.json").read_text())
    assert agent_meta["agent_id"] == "orga::alice"
    assert agent_meta["org_id"] == "orga"
    assert agent_meta["mastio_url"] == "http://proxy-a:9100"
    assert (persist / "dpop.jwk").stat().st_mode & 0o777 == 0o600
    # The legacy api-key file MUST NOT be written.
    assert not (persist / "api-key").exists()


def test_enroll_via_byoca_raises_on_server_error(tmp_path, patched_httpx):
    from cullis_sdk import CullisClient

    patched_httpx["next_response"] = _StubResponse(400, {"detail": "foreign CA"})

    with pytest.raises(PermissionError, match="400"):
        CullisClient.enroll_via_byoca(
            "http://proxy-a:9100",
            admin_secret="top-secret",
            agent_name="alice",
            cert_pem="X",
            private_key_pem="Y",
            persist_to=tmp_path / "identity",
        )
    # Nothing persisted on failure.
    assert not (tmp_path / "identity").exists()


def test_enroll_via_byoca_enable_dpop_false_skips_jwk(tmp_path, patched_httpx):
    from cullis_sdk import CullisClient

    patched_httpx["next_response"] = _StubResponse(201, {
        "agent_id": "orga::nodpop",
        "cert_thumbprint": "0" * 64,
        "spiffe_id": None,
        "dpop_jkt": None,
    })

    client = CullisClient.enroll_via_byoca(
        "http://proxy-a:9100",
        admin_secret="top-secret",
        agent_name="nodpop",
        cert_pem="X",
        private_key_pem="Y",
        enable_dpop=False,
        persist_to=tmp_path / "id",
    )

    call = patched_httpx["calls"][0]
    assert "dpop_jwk" not in call["json"]
    assert client._egress_dpop_key is None
    assert not (tmp_path / "id" / "dpop.jwk").exists()


# ── enroll_via_spiffe ────────────────────────────────────────────────────


def test_enroll_via_spiffe_posts_svid_and_bundle(tmp_path, patched_httpx):
    from cullis_sdk import CullisClient

    spiffe = "spiffe://orga.test/agent/bob"
    patched_httpx["next_response"] = _StubResponse(201, {
        "agent_id": "orga::bob",
        "cert_thumbprint": "0" * 64,
        "spiffe_id": spiffe,
        "dpop_jkt": "fake-jkt",
    })

    client = CullisClient.enroll_via_spiffe(
        "http://proxy-a:9100",
        admin_secret="top-secret",
        agent_name="bob",
        svid_pem="-----BEGIN CERTIFICATE-----\nSVID\n-----END CERTIFICATE-----\n",
        svid_key_pem="-----BEGIN EC PRIVATE KEY-----\nK\n-----END EC PRIVATE KEY-----\n",
        trust_bundle_pem="-----BEGIN CERTIFICATE-----\nBUNDLE\n-----END CERTIFICATE-----\n",
        persist_to=tmp_path / "identity",
    )

    call = patched_httpx["calls"][0]
    assert call["url"] == "http://proxy-a:9100/v1/admin/agents/enroll/spiffe"
    assert call["json"]["svid_pem"].startswith("-----BEGIN")
    assert call["json"]["trust_bundle_pem"].startswith("-----BEGIN")
    assert "dpop_jwk" in call["json"]

    assert client._proxy_agent_id == "orga::bob"
    # ADR-014 PR-C: no api-key file persisted.
    assert not (tmp_path / "identity" / "api-key").exists()


def test_enroll_via_spiffe_omits_bundle_when_none_supplied(tmp_path, patched_httpx):
    from cullis_sdk import CullisClient

    patched_httpx["next_response"] = _StubResponse(201, {
        "agent_id": "orga::bob",
        "cert_thumbprint": "0" * 64,
        "spiffe_id": "spiffe://x.test/y",
        "dpop_jkt": None,
    })

    CullisClient.enroll_via_spiffe(
        "http://proxy-a:9100",
        admin_secret="top-secret",
        agent_name="bob",
        svid_pem="X",
        svid_key_pem="Y",
        # no trust_bundle_pem — server should fall back to proxy_config
        persist_to=tmp_path / "id",
    )

    call = patched_httpx["calls"][0]
    assert "trust_bundle_pem" not in call["json"]


# ── deprecation warnings ─────────────────────────────────────────────────


def test_login_from_pem_emits_deprecation_warning():
    """Documented ADR-011 Phase 2 signal: deprecation fires at call site
    so SDK users see it without digging through audit events."""
    from cullis_sdk import CullisClient

    c = CullisClient("http://any", verify_tls=False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        # Will fail the broker call downstream — we only care the
        # warning fires before any network activity.
        try:
            c.login_from_pem("orga::a", "orga", "cert", "key")
        except Exception:
            pass
    dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert dep, "login_from_pem must emit DeprecationWarning"
    assert "ADR-011" in str(dep[0].message)


def test_from_spiffe_workload_api_emits_deprecation_warning(monkeypatch):
    from cullis_sdk import CullisClient

    # Stub the SPIFFE fetch so the test doesn't need a live SPIRE.
    class _FakeSvid:
        spiffe_id = "spiffe://test/agent"
        cert_pem = "C"
        key_pem = "K"

    monkeypatch.setattr(
        "cullis_sdk.spiffe.fetch_x509_svid",
        lambda _sock: _FakeSvid(),
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            CullisClient.from_spiffe_workload_api(
                "http://any", org_id="test", socket_path="/dev/null",
            )
        except Exception:
            pass
    dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert dep, "from_spiffe_workload_api must emit DeprecationWarning"
    msg = str(dep[0].message)
    assert "ADR-011" in msg
    assert "enroll_via_spiffe" in msg
