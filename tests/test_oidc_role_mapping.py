"""
Tests for the OIDC role mapping feature (Item 1 in plan.md).

Validates that an org can configure a claim path + admin values to gate
which IdP-authenticated users get the "org" role on the dashboard.

Backward compat: orgs without a mapping retain the legacy behavior
(any IdP-authenticated user becomes org admin).
"""
import time
import pytest
from unittest.mock import patch, AsyncMock

from httpx import AsyncClient

from tests.conftest import ADMIN_HEADERS, TestSessionLocal
from app.dashboard.oidc import (
    OidcIdentity,
    create_oidc_state,
    _extract_claim,
    validate_role_mapping,
)

pytestmark = pytest.mark.asyncio


# ── Pure unit tests for _extract_claim ──────────────────────────────────────

def test_extract_claim_top_level_string():
    assert _extract_claim({"sub": "alice"}, "sub") == "alice"


def test_extract_claim_top_level_list():
    assert _extract_claim({"groups": ["a", "b"]}, "groups") == ["a", "b"]


def test_extract_claim_nested_dict():
    claims = {"role": {"name": "admin", "level": 5}}
    assert _extract_claim(claims, "role.name") == "admin"
    assert _extract_claim(claims, "role.level") == 5


def test_extract_claim_list_index():
    claims = {"items": [{"id": 1}, {"id": 2}]}
    assert _extract_claim(claims, "items.0.id") == 1
    assert _extract_claim(claims, "items.1.id") == 2


def test_extract_claim_missing_path():
    assert _extract_claim({"a": 1}, "b") is None
    assert _extract_claim({"a": {"b": 1}}, "a.c") is None
    assert _extract_claim({}, "anything") is None


def test_extract_claim_walk_into_scalar():
    # Cannot walk past a scalar
    assert _extract_claim({"a": 1}, "a.b") is None


def test_extract_claim_list_out_of_range():
    assert _extract_claim({"items": [1, 2]}, "items.5") is None


def test_extract_claim_empty_path():
    assert _extract_claim({"a": 1}, "") is None


# ── Pure unit tests for validate_role_mapping ───────────────────────────────

def test_validate_no_mapping_legacy_allow():
    """No mapping configured → backward compat (allow)."""
    allowed, reason = validate_role_mapping(None, {"sub": "u"})
    assert allowed is True
    assert reason == "no_mapping_legacy"

    allowed, reason = validate_role_mapping({}, {"sub": "u"})
    assert allowed is True


def test_validate_string_claim_match():
    mapping = {
        "claim_path": "role",
        "admin_values": ["cullis-admin"],
        "default_role": "deny",
    }
    allowed, reason = validate_role_mapping(mapping, {"role": "cullis-admin"})
    assert allowed is True
    assert reason == "match"


def test_validate_list_claim_match():
    mapping = {
        "claim_path": "groups",
        "admin_values": ["cullis-admin", "platform-eng"],
        "default_role": "deny",
    }
    allowed, reason = validate_role_mapping(
        mapping, {"groups": ["readonly", "platform-eng"]}
    )
    assert allowed is True
    assert reason == "match"


def test_validate_list_claim_no_match_deny():
    mapping = {
        "claim_path": "groups",
        "admin_values": ["cullis-admin"],
        "default_role": "deny",
    }
    allowed, reason = validate_role_mapping(
        mapping, {"groups": ["readonly", "viewer"]}
    )
    assert allowed is False
    assert reason == "no_match"


def test_validate_claim_missing_deny():
    mapping = {
        "claim_path": "groups",
        "admin_values": ["cullis-admin"],
        "default_role": "deny",
    }
    allowed, reason = validate_role_mapping(mapping, {"sub": "alice"})
    assert allowed is False
    assert reason == "claim_missing"


def test_validate_claim_missing_default_org():
    """default_role=org → missing claim still grants access (legacy fallback)."""
    mapping = {
        "claim_path": "groups",
        "admin_values": ["cullis-admin"],
        "default_role": "org",
    }
    allowed, reason = validate_role_mapping(mapping, {"sub": "alice"})
    assert allowed is True
    assert reason == "default_allow"


def test_validate_misconfigured_mapping_fails_closed():
    """A mapping without claim_path or admin_values must deny."""
    allowed, reason = validate_role_mapping(
        {"claim_path": "groups"}, {"groups": ["x"]}
    )
    assert allowed is False
    assert reason == "mapping_misconfigured"

    allowed, reason = validate_role_mapping(
        {"admin_values": ["x"]}, {"groups": ["x"]}
    )
    assert allowed is False
    assert reason == "mapping_misconfigured"


def test_validate_dot_notation_path():
    """Nested claim path is supported (e.g. extension_attributes.role)."""
    mapping = {
        "claim_path": "ext.role.name",
        "admin_values": ["admin"],
        "default_role": "deny",
    }
    claims = {"ext": {"role": {"name": "admin"}}}
    allowed, reason = validate_role_mapping(mapping, claims)
    assert allowed is True


def test_validate_claim_invalid_type():
    """A claim that is neither string nor list (e.g. dict) is rejected."""
    mapping = {
        "claim_path": "role",
        "admin_values": ["admin"],
        "default_role": "deny",
    }
    allowed, reason = validate_role_mapping(mapping, {"role": {"foo": "bar"}})
    assert allowed is False
    assert reason == "claim_type_invalid"


def test_validate_admin_values_normalized_to_strings():
    """Numeric values in admin_values are matched as strings."""
    mapping = {
        "claim_path": "level",
        "admin_values": [5, "admin"],
        "default_role": "deny",
    }
    allowed, _ = validate_role_mapping(mapping, {"level": "5"})
    assert allowed is True


# ── DB integration tests for the org_store helpers ─────────────────────────

async def test_org_store_role_mapping_roundtrip(client: AsyncClient):
    """Setting and reading the role mapping persists correctly."""
    from app.registry.org_store import (
        update_org_oidc_role_mapping,
        get_oidc_role_mapping,
        get_org_by_id,
    )

    await client.post("/v1/registry/orgs", json={
        "org_id": "rmap-org", "display_name": "RMap", "secret": "s",
    }, headers=ADMIN_HEADERS)

    mapping = {
        "claim_path": "groups",
        "admin_values": ["cullis-admin"],
        "default_role": "deny",
    }
    async with TestSessionLocal() as db:
        await update_org_oidc_role_mapping(db, "rmap-org", mapping)
        org = await get_org_by_id(db, "rmap-org")
        assert get_oidc_role_mapping(org) == mapping

    # Clear it again
    async with TestSessionLocal() as db:
        await update_org_oidc_role_mapping(db, "rmap-org", None)
        org = await get_org_by_id(db, "rmap-org")
        assert get_oidc_role_mapping(org) is None


async def test_org_store_role_mapping_preserves_other_metadata(client: AsyncClient):
    """Setting role mapping does not clobber other metadata fields."""
    import json
    from app.registry.org_store import (
        update_org_oidc_role_mapping,
        get_org_by_id,
    )

    await client.post("/v1/registry/orgs", json={
        "org_id": "rmap-meta-org", "display_name": "RMap Meta", "secret": "s",
    }, headers=ADMIN_HEADERS)

    # Seed unrelated metadata
    async with TestSessionLocal() as db:
        org = await get_org_by_id(db, "rmap-meta-org")
        org.metadata_json = json.dumps({"unrelated": "value", "count": 42})
        await db.commit()

    async with TestSessionLocal() as db:
        await update_org_oidc_role_mapping(db, "rmap-meta-org", {
            "claim_path": "groups",
            "admin_values": ["x"],
            "default_role": "deny",
        })
        org = await get_org_by_id(db, "rmap-meta-org")
        assert org.extra["unrelated"] == "value"
        assert org.extra["count"] == 42
        assert "oidc_role_mapping" in org.extra


# ── End-to-end OIDC callback integration ────────────────────────────────────

async def _setup_org_with_oidc_and_mapping(
    client: AsyncClient,
    org_id: str,
    mapping: dict | None,
):
    """Create an org with OIDC + an optional role mapping."""
    from app.registry.org_store import (
        update_org_oidc,
        update_org_oidc_role_mapping,
        set_org_status,
    )

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_id + "-s",
    }, headers=ADMIN_HEADERS)

    async with TestSessionLocal() as db:
        await update_org_oidc(
            db, org_id,
            issuer_url="https://idp.example.com",
            client_id="test-client-id",
            client_secret="test-client-secret",
        )
        if mapping is not None:
            await update_org_oidc_role_mapping(db, org_id, mapping)
        await set_org_status(db, org_id, "active")


async def test_callback_with_mapping_grant(client: AsyncClient):
    """Callback succeeds when the IdP returns a matching claim."""
    org_id = "rmap-cb-grant"
    await _setup_org_with_oidc_and_mapping(client, org_id, {
        "claim_path": "groups",
        "admin_values": ["cullis-admin"],
        "default_role": "deny",
    })

    identity = OidcIdentity(
        sub="alice", email="alice@example.com", name="Alice",
        issuer="https://idp.example.com",
        claims={"sub": "alice", "groups": ["readonly", "cullis-admin"]},
    )
    flow_state = create_oidc_state("org", org_id)

    with patch("app.dashboard.session.get_oidc_state", return_value={
            **flow_state.to_dict(), "exp": int(time.time()) + 600}), \
         patch("app.dashboard.oidc.exchange_code_for_identity",
               new=AsyncMock(return_value=identity)), \
         patch("app.dashboard.session.clear_oidc_state"):
        resp = await client.get(
            f"/dashboard/oidc/callback?code=test-code&state={flow_state.state}",
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers.get("location") == "/dashboard"
    assert "atn_session" in resp.headers.get("set-cookie", "")


async def test_callback_with_mapping_deny_no_match(client: AsyncClient):
    """Callback denies when the IdP claim does not match admin_values."""
    org_id = "rmap-cb-deny"
    await _setup_org_with_oidc_and_mapping(client, org_id, {
        "claim_path": "groups",
        "admin_values": ["cullis-admin"],
        "default_role": "deny",
    })

    identity = OidcIdentity(
        sub="bob", email="bob@example.com", name="Bob",
        issuer="https://idp.example.com",
        claims={"sub": "bob", "groups": ["readonly", "viewer"]},
    )
    flow_state = create_oidc_state("org", org_id)

    with patch("app.dashboard.session.get_oidc_state", return_value={
            **flow_state.to_dict(), "exp": int(time.time()) + 600}), \
         patch("app.dashboard.oidc.exchange_code_for_identity",
               new=AsyncMock(return_value=identity)), \
         patch("app.dashboard.session.clear_oidc_state"):
        resp = await client.get(
            f"/dashboard/oidc/callback?code=test-code&state={flow_state.state}",
            follow_redirects=False,
        )

    # Render login error page (200), no session cookie set
    assert resp.status_code == 200
    assert b"not authorized" in resp.content
    assert "atn_session" not in resp.headers.get("set-cookie", "")


async def test_callback_with_mapping_deny_claim_missing(client: AsyncClient):
    """Callback denies when the configured claim is absent from the id_token."""
    org_id = "rmap-cb-missing"
    await _setup_org_with_oidc_and_mapping(client, org_id, {
        "claim_path": "groups",
        "admin_values": ["cullis-admin"],
        "default_role": "deny",
    })

    identity = OidcIdentity(
        sub="charlie", email="c@example.com", name="Charlie",
        issuer="https://idp.example.com",
        claims={"sub": "charlie"},  # no "groups" claim at all
    )
    flow_state = create_oidc_state("org", org_id)

    with patch("app.dashboard.session.get_oidc_state", return_value={
            **flow_state.to_dict(), "exp": int(time.time()) + 600}), \
         patch("app.dashboard.oidc.exchange_code_for_identity",
               new=AsyncMock(return_value=identity)), \
         patch("app.dashboard.session.clear_oidc_state"):
        resp = await client.get(
            f"/dashboard/oidc/callback?code=test-code&state={flow_state.state}",
            follow_redirects=False,
        )

    assert resp.status_code == 200
    assert b"not authorized" in resp.content


async def test_callback_no_mapping_legacy_behavior(client: AsyncClient):
    """An org without a role mapping retains legacy behavior (any user grants org role)."""
    org_id = "rmap-cb-legacy"
    await _setup_org_with_oidc_and_mapping(client, org_id, None)

    identity = OidcIdentity(
        sub="dave", email="dave@example.com", name="Dave",
        issuer="https://idp.example.com",
        claims={"sub": "dave"},  # no groups, no role — but mapping is None
    )
    flow_state = create_oidc_state("org", org_id)

    with patch("app.dashboard.session.get_oidc_state", return_value={
            **flow_state.to_dict(), "exp": int(time.time()) + 600}), \
         patch("app.dashboard.oidc.exchange_code_for_identity",
               new=AsyncMock(return_value=identity)), \
         patch("app.dashboard.session.clear_oidc_state"):
        resp = await client.get(
            f"/dashboard/oidc/callback?code=test-code&state={flow_state.state}",
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers.get("location") == "/dashboard"
    assert "atn_session" in resp.headers.get("set-cookie", "")
