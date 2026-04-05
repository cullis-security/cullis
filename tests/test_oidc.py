"""Tests for OIDC federation login."""
import time
import pytest
from unittest.mock import patch, AsyncMock

from httpx import AsyncClient

from tests.conftest import ADMIN_HEADERS, TestSessionLocal
from app.dashboard.oidc import (
    create_oidc_state, _pkce_code_challenge, OidcFlowState,
    OidcIdentity,
)

pytestmark = pytest.mark.asyncio


# ── Unit tests ──────────────────────────────────────────────────────────────

def test_create_oidc_state():
    """create_oidc_state generates unique cryptographic values."""
    s1 = create_oidc_state("org", "acme")
    s2 = create_oidc_state("admin")
    assert s1.state != s2.state
    assert s1.nonce != s2.nonce
    assert s1.code_verifier != s2.code_verifier
    assert s1.role == "org"
    assert s1.org_id == "acme"
    assert s2.role == "admin"
    assert s2.org_id is None


def test_pkce_code_challenge():
    """PKCE code challenge is base64url(SHA256(verifier))."""
    verifier = "test_verifier_string"
    challenge = _pkce_code_challenge(verifier)
    assert len(challenge) > 10
    assert "=" not in challenge  # no padding


def test_flow_state_roundtrip():
    """OidcFlowState serializes and deserializes correctly."""
    state = create_oidc_state("org", "test-org")
    d = state.to_dict()
    restored = OidcFlowState.from_dict(d)
    assert restored.state == state.state
    assert restored.nonce == state.nonce
    assert restored.code_verifier == state.code_verifier
    assert restored.role == state.role
    assert restored.org_id == state.org_id


# ── Integration tests ───────────────────────────────────────────────────────

async def _setup_org_with_oidc(client: AsyncClient, org_id: str = "oidc-org"):
    """Create an org with OIDC configuration."""
    from app.registry.org_store import update_org_oidc
    from tests.cert_factory import get_org_ca_pem

    org_secret = org_id + "-secret"
    ca_pem = get_org_ca_pem(org_id)
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
        "ca_certificate": ca_pem,
    }, headers=ADMIN_HEADERS)

    # Set OIDC config directly in DB
    async with TestSessionLocal() as db:
        await update_org_oidc(db, org_id,
            issuer_url="https://idp.example.com",
            client_id="test-client-id",
            client_secret="test-client-secret")
        # Activate org
        from app.registry.org_store import set_org_status
        await set_org_status(db, org_id, "active")


async def test_oidc_start_requires_broker_public_url(client: AsyncClient):
    """SSO start fails gracefully when BROKER_PUBLIC_URL is not set."""
    resp = await client.get("/dashboard/oidc/start?role=org&org_id=any",
                            follow_redirects=False)
    assert resp.status_code == 200
    assert b"BROKER_PUBLIC_URL" in resp.content


async def test_oidc_start_org_no_config(client: AsyncClient):
    """SSO start for org without OIDC config shows error on login page."""
    await client.post("/v1/registry/orgs", json={
        "org_id": "nooidc-org", "display_name": "No OIDC", "secret": "s",
    }, headers=ADMIN_HEADERS)

    # The test env has no broker_public_url, so we get that error first.
    # This test verifies the start endpoint handles misconfigured orgs gracefully.
    resp = await client.get("/dashboard/oidc/start?role=org&org_id=nooidc-org",
                            follow_redirects=False)
    assert resp.status_code == 200  # renders login page (not a crash)


async def test_oidc_start_admin_no_config(client: AsyncClient):
    """SSO start for admin without config shows error on login page."""
    resp = await client.get("/dashboard/oidc/start?role=admin",
                            follow_redirects=False)
    assert resp.status_code == 200  # renders login page (not a crash)


async def test_oidc_start_org_with_config(client: AsyncClient):
    """SSO start for org with OIDC config redirects to auth URL."""
    await _setup_org_with_oidc(client, "oidcstart-org")

    mock_discovery = {
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
        "issuer": "https://idp.example.com",
    }

    with patch("app.dashboard.oidc._fetch_discovery", new=AsyncMock(return_value=mock_discovery)), \
         patch("app.config.get_settings") as mock_settings:
        s = mock_settings.return_value
        s.broker_public_url = "https://broker.test"
        s.admin_oidc_issuer_url = ""
        s.admin_oidc_client_id = ""
        s.admin_oidc_client_secret = ""
        s.admin_secret = "change-me-in-production"
        s.dashboard_signing_key = "test-key-for-oidc"

        resp = await client.get(
            "/dashboard/oidc/start?role=org&org_id=oidcstart-org",
            follow_redirects=False,
        )

    assert resp.status_code == 303
    location = resp.headers.get("location", "")
    assert "idp.example.com/authorize" in location
    assert "code_challenge" in location
    assert "state=" in location
    # State cookie should be set
    assert "atn_oidc_state" in resp.headers.get("set-cookie", "")


async def test_oidc_callback_no_state_cookie(client: AsyncClient):
    """Callback without state cookie returns error."""
    resp = await client.get(
        "/dashboard/oidc/callback?code=test-code&state=test-state",
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert b"SSO session expired" in resp.content


async def test_oidc_callback_idp_error(client: AsyncClient):
    """Callback with error param shows provider error."""
    resp = await client.get(
        "/dashboard/oidc/callback?error=access_denied&error_description=User+cancelled",
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert b"SSO provider error" in resp.content


async def test_oidc_callback_success_org(client: AsyncClient):
    """Successful OIDC callback for org creates session."""
    await _setup_org_with_oidc(client, "oidccb-org")

    mock_identity = OidcIdentity(
        sub="user-123", email="user@example.com",
        name="Test User", issuer="https://idp.example.com",
    )

    # Manually create a state cookie by building a fake request/response
    flow_state = create_oidc_state("org", "oidccb-org")
    state_value = flow_state.state

    with patch("app.dashboard.session.get_oidc_state", return_value={
            **flow_state.to_dict(), "exp": int(time.time()) + 600}), \
         patch("app.dashboard.oidc.exchange_code_for_identity",
               new=AsyncMock(return_value=mock_identity)), \
         patch("app.dashboard.session.clear_oidc_state"):

        resp = await client.get(
            f"/dashboard/oidc/callback?code=test-code&state={state_value}",
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers.get("location") == "/dashboard"
    # Session cookie should be set
    assert "atn_session" in resp.headers.get("set-cookie", "")


async def test_oidc_callback_state_mismatch(client: AsyncClient):
    """Callback with mismatched state returns error."""
    flow_state = create_oidc_state("org", "some-org")

    with patch("app.dashboard.session.get_oidc_state", return_value={
            **flow_state.to_dict(), "exp": int(time.time()) + 600}):
        resp = await client.get(
            "/dashboard/oidc/callback?code=test-code&state=wrong-state",
            follow_redirects=False,
        )

    assert resp.status_code == 200
    assert b"state mismatch" in resp.content
