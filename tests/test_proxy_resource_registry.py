"""ADR-007 Phase 1 PR #2 — MCP resource loader into the tool registry.

Pure unit tests for ``load_resources_into_registry``: seed rows into
``local_mcp_resources`` via SQLAlchemy, invoke the loader against a
fresh ToolRegistry, assert the resulting entries carry the right
``resource_id`` / ``endpoint_url`` and honour the conflict policy
against builtin-style pre-registered tools.

Migration tests (schema correctness) are owned by
tests/test_proxy_migrations_adr007.py — this file does NOT re-assert
table shape.
"""
from __future__ import annotations

import pytest
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.tools.context import ToolContext
from mcp_proxy.tools.registry import ToolDefinition, ToolRegistry
from mcp_proxy.tools.resource_loader import load_resources_into_registry


async def _seed_resource(
    *,
    resource_id: str,
    name: str,
    org_id: str | None = "acme",
    description: str | None = "seeded",
    endpoint_url: str = "http://mcp-svc:8080",
    required_capability: str | None = "cap.read",
    allowed_domains: str = '["mcp-svc:8080"]',
    enabled: int = 1,
) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_mcp_resources (
                    resource_id, org_id, name, description, endpoint_url,
                    auth_type, auth_secret_ref, required_capability,
                    allowed_domains, enabled, created_at, updated_at
                ) VALUES (
                    :resource_id, :org_id, :name, :description, :endpoint_url,
                    'none', NULL, :required_capability,
                    :allowed_domains, :enabled,
                    '2026-04-16T10:00:00Z', '2026-04-16T10:00:00Z'
                )
                """
            ),
            {
                "resource_id": resource_id,
                "org_id": org_id,
                "name": name,
                "description": description,
                "endpoint_url": endpoint_url,
                "required_capability": required_capability,
                "allowed_domains": allowed_domains,
                "enabled": enabled,
            },
        )


async def _builtin_handler(ctx: ToolContext) -> dict:
    return {"ok": True}


@pytest.mark.asyncio
async def test_resource_definition_has_new_fields():
    """ToolDefinition accepts resource_id + endpoint_url with sane defaults."""
    d = ToolDefinition(
        name="t",
        description="",
        required_capability="",
        allowed_domains=[],
        handler=_builtin_handler,
    )
    assert d.resource_id is None
    assert d.endpoint_url is None
    assert d.is_mcp_resource is False

    d2 = ToolDefinition(
        name="r",
        description="",
        required_capability="",
        allowed_domains=[],
        handler=_builtin_handler,
        resource_id="res-1",
        endpoint_url="http://svc",
    )
    assert d2.is_mcp_resource is True


@pytest.mark.asyncio
async def test_load_resources_empty_db(tmp_path):
    """No rows in local_mcp_resources → loader returns 0, registry empty."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'empty.db'}"
    await init_db(url)
    try:
        registry = ToolRegistry()
        loaded = await load_resources_into_registry(registry)
    finally:
        await dispose_db()

    assert loaded == 0
    assert len(registry) == 0


@pytest.mark.asyncio
async def test_load_resources_populates_registry(tmp_path):
    """Two enabled rows → two registry entries with resource_id set."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'two.db'}"
    await init_db(url)
    try:
        await _seed_resource(
            resource_id="res-a", name="postgres-prod",
            required_capability="sql.read",
        )
        await _seed_resource(
            resource_id="res-b", name="github-mcp",
            endpoint_url="http://github-mcp:9000",
            required_capability="repo.read",
            allowed_domains='["github-mcp:9000"]',
        )

        registry = ToolRegistry()
        loaded = await load_resources_into_registry(registry)
    finally:
        await dispose_db()

    assert loaded == 2
    assert len(registry) == 2

    pg = registry.get("postgres-prod")
    assert pg is not None
    assert pg.resource_id == "res-a"
    assert pg.endpoint_url == "http://mcp-svc:8080"
    assert pg.required_capability == "sql.read"
    assert pg.allowed_domains == ["mcp-svc:8080"]
    assert pg.is_mcp_resource is True

    gh = registry.get("github-mcp")
    assert gh is not None
    assert gh.resource_id == "res-b"
    assert gh.endpoint_url == "http://github-mcp:9000"


@pytest.mark.asyncio
async def test_load_resources_skip_disabled(tmp_path):
    """One enabled + one disabled → only enabled one lands in registry."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'dis.db'}"
    await init_db(url)
    try:
        await _seed_resource(resource_id="on", name="live")
        await _seed_resource(resource_id="off", name="hidden", enabled=0)

        registry = ToolRegistry()
        loaded = await load_resources_into_registry(registry)
    finally:
        await dispose_db()

    assert loaded == 1
    assert registry.get("live") is not None
    assert registry.get("hidden") is None


@pytest.mark.asyncio
async def test_load_resources_conflict_with_builtin_skips_db(tmp_path):
    """Name collision with pre-registered builtin → DB row skipped.

    Asserts the conflict policy documented in PR-2: builtins win so a
    bad dashboard entry can't silently shadow a prod tool.
    """
    url = f"sqlite+aiosqlite:///{tmp_path / 'conflict.db'}"
    await init_db(url)
    try:
        registry = ToolRegistry()
        registry.register_definition(
            ToolDefinition(
                name="shared",
                description="builtin version",
                required_capability="builtin.cap",
                allowed_domains=[],
                handler=_builtin_handler,
            )
        )

        await _seed_resource(
            resource_id="res-dup", name="shared",
            description="db version",
            required_capability="db.cap",
        )

        loaded = await load_resources_into_registry(registry)
    finally:
        await dispose_db()

    assert loaded == 0
    existing = registry.get("shared")
    assert existing is not None
    assert existing.description == "builtin version"
    assert existing.required_capability == "builtin.cap"
    assert existing.is_mcp_resource is False


@pytest.mark.asyncio
async def test_load_resources_overwrites_previous_mcp_resource(tmp_path):
    """Second load-from-DB for the same name overwrites (reload semantics)."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'reload.db'}"
    await init_db(url)
    try:
        await _seed_resource(
            resource_id="res-evolve", name="evolve",
            description="v1",
        )
        registry = ToolRegistry()
        await load_resources_into_registry(registry)
        async with get_db() as conn:
            await conn.execute(
                text(
                    "UPDATE local_mcp_resources SET description = 'v2' "
                    "WHERE resource_id = 'res-evolve'"
                )
            )
        loaded = await load_resources_into_registry(registry)
    finally:
        await dispose_db()

    assert loaded == 1
    assert registry.get("evolve").description == "v2"


@pytest.mark.asyncio
async def test_load_resources_handler_is_bound_forwarder(tmp_path):
    """PR #3: handler is the MCP forwarder bound to this ToolDefinition.

    Asserts the closure structure rather than invoking the handler
    (which would try to talk to ``endpoint_url`` over the network).
    """
    url = f"sqlite+aiosqlite:///{tmp_path / 'handler.db'}"
    await init_db(url)
    try:
        await _seed_resource(resource_id="res-nh", name="not-wired")
        registry = ToolRegistry()
        await load_resources_into_registry(registry)
    finally:
        await dispose_db()

    tool_def = registry.get("not-wired")
    assert tool_def is not None
    # Auth config stashed by the loader
    assert tool_def._auth_type == "none"
    assert tool_def._auth_secret_ref is None
    # Handler is callable and bound — not the import-time placeholder
    assert callable(tool_def.handler)
    from mcp_proxy.tools.resource_loader import _noop_placeholder
    assert tool_def.handler is not _noop_placeholder


@pytest.mark.asyncio
async def test_load_resources_empty_allowed_domains(tmp_path):
    """Non-JSON allowed_domains → empty whitelist, no crash."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'dom.db'}"
    await init_db(url)
    try:
        await _seed_resource(
            resource_id="res-bad-json", name="bad",
            allowed_domains='not-json',
        )
        registry = ToolRegistry()
        loaded = await load_resources_into_registry(registry)
    finally:
        await dispose_db()

    assert loaded == 1
    assert registry.get("bad").allowed_domains == []


@pytest.mark.asyncio
async def test_load_resources_null_required_capability(tmp_path):
    """NULL required_capability → empty string in the registry."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'cap.db'}"
    await init_db(url)
    try:
        await _seed_resource(
            resource_id="res-nocap", name="anon",
            required_capability=None,
        )
        registry = ToolRegistry()
        await load_resources_into_registry(registry)
    finally:
        await dispose_db()

    assert registry.get("anon").required_capability == ""
