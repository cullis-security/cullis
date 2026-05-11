"""Integration: ``culk_*`` API token resolver wired into the egress
``get_agent_from_dpop_client_cert`` dep (ADR-027 Phase 1, PR 2).

Mounts the real llm_chat router with the real dep — no override — and
hits ``GET /v1/models`` with various ``Authorization`` headers to prove
the resolver short-circuits the cert + DPoP chain when (and only when)
a valid ``culk_*`` token is presented.

The ``list_available_models`` helper is patched per-test so the suite
never reaches an upstream provider. The DB is a tmp sqlite migrated
through the full Alembic chain (including 0029) so token rows are
real, not faked.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from mcp_proxy.db import (
    dispose_db,
    init_db,
    mint_user_api_token,
    revoke_user_api_token,
)
from mcp_proxy.egress import llm_chat_router as router_module
from mcp_proxy.egress.llm_chat_router import router as llm_chat_router

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def app_with_real_dep(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.setenv("MCP_PROXY_ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("MCP_PROXY_AI_GATEWAY_BACKEND", "litellm_embedded")
    monkeypatch.setenv("MCP_PROXY_AI_GATEWAY_PROVIDER", "anthropic")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "orga")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)

    # Wave A C3 (audit 2026-05-11) — mint_user_api_token now requires
    # the principal_id to exist in ``local_user_principals``. Seed the
    # principals used by tests in this file (orga::user::<name>@orga.test).
    from tests._token_test_helpers import seed_test_principal
    for _name in (
        "alice@orga.test", "bob@orga.test", "carol@orga.test",
        "dave@orga.test", "erin@orga.test", "frank@orga.test",
        "grace@orga.test", "heidi@orga.test",
    ):
        await seed_test_principal(f"orga::user::{_name}")

    # Avoid touching upstream catalogue endpoints — return a static list
    # the assertions can verify.
    async def fake_list_available_models(enabled):
        return [
            {"id": "claude-haiku-4-5", "object": "model", "owned_by": "anthropic"},
        ]
    monkeypatch.setattr(
        router_module, "list_available_models", fake_list_available_models,
    )

    test_app = FastAPI()
    test_app.include_router(llm_chat_router)
    # IMPORTANT — no dependency override on get_agent_from_dpop_client_cert
    # here; that's the whole point of this test file.

    yield test_app

    get_settings.cache_clear()
    await dispose_db()


async def _mint_token(principal_id: str, label: str = "test") -> str:
    minted = await mint_user_api_token(
        principal_id=principal_id,
        label=label,
        created_by="orga::admin",
    )
    return minted["token"]


# ── happy path ────────────────────────────────────────────────────────


async def test_valid_api_token_grants_access(app_with_real_dep):
    token = await _mint_token("orga::user::alice@orga.test")
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.get(
            "/v1/models",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["object"] == "list"
    assert body["data"][0]["id"] == "claude-haiku-4-5"


async def test_token_auth_case_insensitive_bearer_scheme(app_with_real_dep):
    token = await _mint_token("orga::user::bob@orga.test")
    # Some clients emit "bearer" lowercase or "BEARER" upper — RFC 6750
    # §2.1 says the scheme is case-insensitive. The resolver must
    # accept both.
    for prefix in ("Bearer", "bearer", "BEARER"):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
        ) as c:
            r = await c.get(
                "/v1/models",
                headers={"Authorization": f"{prefix} {token}"},
            )
        assert r.status_code == 200, f"prefix={prefix}: {r.text}"


# ── rejection paths ──────────────────────────────────────────────────


async def test_no_authorization_header_falls_through_to_cert_layer(app_with_real_dep):
    # With no Bearer culk_ token and no client cert (test transport has
    # no TLS), the cert-layer dep raises 403. The resolver MUST decline
    # silently here, not 401 itself, so this is the chained outcome.
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.get("/v1/models")
    assert r.status_code in (401, 403), r.text


async def test_unknown_culk_token_is_rejected(app_with_real_dep):
    # Well-formed culk_ token, but never minted. Resolver returns None
    # so the cert layer kicks in and 401/403 because no cert either.
    fake = "culk_" + "a" * 52
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.get(
            "/v1/models",
            headers={"Authorization": f"Bearer {fake}"},
        )
    assert r.status_code in (401, 403), r.text


async def test_revoked_token_is_rejected(app_with_real_dep):
    token = await _mint_token("orga::user::carol@orga.test", label="will-revoke")
    # Sanity check: still works before revoke.
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r1 = await c.get(
            "/v1/models",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r1.status_code == 200

    # Find the token id and revoke it.
    from mcp_proxy.db import list_user_api_tokens
    rows = await list_user_api_tokens("orga::user::carol@orga.test")
    assert len(rows) == 1
    await revoke_user_api_token(rows[0]["id"], revoked_by="orga::admin")

    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r2 = await c.get(
            "/v1/models",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r2.status_code in (401, 403), r2.text


async def test_malformed_token_falls_through(app_with_real_dep):
    # Wrong prefix → resolver declines, cert layer kicks in → 401/403.
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.get(
            "/v1/models",
            headers={"Authorization": "Bearer sk-ant-not-a-cullis-token"},
        )
    assert r.status_code in (401, 403), r.text


# ── touch tracking ────────────────────────────────────────────────────


async def test_successful_auth_updates_last_used(app_with_real_dep):
    token = await _mint_token("orga::user::dave@orga.test", label="touch-me")

    from mcp_proxy.db import list_user_api_tokens
    pre = await list_user_api_tokens("orga::user::dave@orga.test")
    assert pre[0]["last_used_at"] is None

    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.get(
            "/v1/models",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200

    post = await list_user_api_tokens("orga::user::dave@orga.test")
    assert post[0]["last_used_at"] is not None


# ── principal type inference ─────────────────────────────────────────


async def test_user_principal_type_inferred_from_id_shape(app_with_real_dep):
    """The downstream handler sees principal_type=user when the token's
    principal_id contains ``::user::``. The simplest observable proof
    is that the request succeeds — the resolver returned an
    ``InternalAgent`` and didn't fall through. The audit row would
    carry ``principal_type=user`` but ``/v1/models`` doesn't write one,
    so we rely on the 200 here and on ``test_user_api_tokens_db.py``
    for direct shape checks.
    """
    token = await _mint_token("orga::user::erin@orga.test")
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.get(
            "/v1/models",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200
