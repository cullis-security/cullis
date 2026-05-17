"""Executor denied_reason_code coverage (F5 follow-up #4).

Every non-success path returns a stable token from
``mcp_proxy.policy.denied_reason_codes``. SDK consumers branch on the
code instead of substring-matching ``error``. These tests pin one
trigger per code so a future refactor that drops the field on any path
fails loud.
"""
from __future__ import annotations

import os

os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from mcp_proxy.models import TokenPayload, ToolExecuteRequest
from mcp_proxy.policy.denied_reason_codes import (
    ALL_CODES,
    CAPABILITY_DENIED,
    INSUFFICIENT_TIER,
    INTERNAL_ERROR,
    MISSING_BINDING,
    TOOL_NOT_FOUND,
)
from mcp_proxy.policy.tier_matrix import TierMatrix
from mcp_proxy.tools import executor
from mcp_proxy.tools.http_whitelist import ToolExecutionError
from mcp_proxy.tools.registry import ToolDefinition, tool_registry


_TOOL_NAME = "denied_code_fixture_tool"
_TOOL_CAP = "mcp.transfer_money"


@pytest.fixture
def clean_registry():
    saved = dict(tool_registry._tools)
    tool_registry._tools.clear()
    yield tool_registry
    tool_registry._tools.clear()
    tool_registry._tools.update(saved)


class _FakeSecrets:
    async def get_tool_secrets(self, tool_name: str) -> dict[str, str]:
        return {}


def _agent(scope: list[str] | None = None) -> TokenPayload:
    return TokenPayload(
        sub="spiffe://cullis.test/acme::daniele",
        agent_id="acme::daniele",
        org="acme",
        exp=9_999_999_999,
        iat=0,
        jti="jti-denied-codes",
        scope=scope if scope is not None else [_TOOL_CAP],
        cnf={"jkt": "fake-jkt"},
        principal_type="agent",
    )


def _request(name: str = _TOOL_NAME) -> ToolExecuteRequest:
    return ToolExecuteRequest.model_construct(
        tool=name, parameters={}, request_id="rq-denied",
    )


def _matrix(min_tier: str) -> TierMatrix:
    return TierMatrix(
        version="test",
        default_min_tier="untrusted",
        by_exact={_TOOL_CAP: min_tier},
        by_prefix=(),
        source_path="<test>",
    )


def _register_tool(
    *,
    handler: AsyncMock | None = None,
    required_capability: str = _TOOL_CAP,
    resource_id: str | None = None,
) -> AsyncMock:
    h = handler or AsyncMock(return_value={"ok": True})
    tool_registry.register_definition(ToolDefinition(
        name=_TOOL_NAME,
        description="Denied-code fixture",
        required_capability=required_capability,
        allowed_domains=[],
        handler=h,
        resource_id=resource_id,
    ))
    return h


# ── code coverage ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tool_not_found_emits_tool_not_found(clean_registry):
    with patch("mcp_proxy.tools.executor.log_audit", AsyncMock()):
        resp = await executor.run(
            request=_request("does_not_exist"),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=None,
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == TOOL_NOT_FOUND


@pytest.mark.asyncio
async def test_capability_lookup_failure_emits_capability_denied(
    clean_registry,
):
    _register_tool()
    with patch(
        "mcp_proxy.tools.executor._load_principal_capabilities",
        AsyncMock(side_effect=RuntimeError("db gone")),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=_agent(scope=[]),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=None,
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == CAPABILITY_DENIED


@pytest.mark.asyncio
async def test_missing_capability_emits_capability_denied(clean_registry):
    _register_tool()
    with patch(
        "mcp_proxy.tools.executor._load_principal_capabilities",
        AsyncMock(return_value=set()),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=_agent(scope=[]),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=None,
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == CAPABILITY_DENIED


@pytest.mark.asyncio
async def test_insufficient_tier_emits_insufficient_tier(clean_registry):
    _register_tool()
    app_state = SimpleNamespace(tier_matrix=_matrix("managed_attested"))
    with patch(
        "mcp_proxy.tools.executor.resolve_effective_tier",
        AsyncMock(return_value=("untrusted", None)),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=app_state,
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == INSUFFICIENT_TIER


@pytest.mark.asyncio
async def test_missing_binding_emits_missing_binding(clean_registry):
    _register_tool(resource_id="acme::pg-prod")
    app_state = SimpleNamespace(tier_matrix=_matrix("untrusted"))
    with patch(
        "mcp_proxy.tools.executor.resolve_effective_tier",
        AsyncMock(return_value=("managed_attested", None)),
    ), patch(
        "mcp_proxy.local.bindings.has_active_binding",
        AsyncMock(return_value=False),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=app_state,
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == MISSING_BINDING


@pytest.mark.asyncio
async def test_handler_timeout_emits_internal_error(clean_registry):
    import asyncio

    async def _slow_handler(ctx):
        await asyncio.sleep(10)
        return {"ok": True}

    handler = AsyncMock(side_effect=_slow_handler)
    _register_tool(handler=handler)
    app_state = SimpleNamespace(tier_matrix=_matrix("untrusted"))
    with patch(
        "mcp_proxy.tools.executor.resolve_effective_tier",
        AsyncMock(return_value=("managed_attested", None)),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=app_state,
            timeout=0.05,
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == INTERNAL_ERROR


@pytest.mark.asyncio
async def test_tool_execution_error_emits_internal_error(clean_registry):
    _register_tool(handler=AsyncMock(side_effect=ToolExecutionError("boom")))
    app_state = SimpleNamespace(tier_matrix=_matrix("untrusted"))
    with patch(
        "mcp_proxy.tools.executor.resolve_effective_tier",
        AsyncMock(return_value=("managed_attested", None)),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=app_state,
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == INTERNAL_ERROR


@pytest.mark.asyncio
async def test_unexpected_exception_emits_internal_error(clean_registry):
    _register_tool(handler=AsyncMock(side_effect=ValueError("kaboom")))
    app_state = SimpleNamespace(tier_matrix=_matrix("untrusted"))
    with patch(
        "mcp_proxy.tools.executor.resolve_effective_tier",
        AsyncMock(return_value=("managed_attested", None)),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=app_state,
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == INTERNAL_ERROR


# ── success path ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_success_path_leaves_denied_reason_code_none(clean_registry):
    _register_tool()
    app_state = SimpleNamespace(tier_matrix=_matrix("untrusted"))
    with patch(
        "mcp_proxy.tools.executor.resolve_effective_tier",
        AsyncMock(return_value=("managed_attested", None)),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=app_state,
        )
    assert resp.status == "success"
    assert resp.denied_reason_code is None


# ── stability contract ───────────────────────────────────────────────


def test_all_codes_are_well_formed():
    import re

    pattern = re.compile(r"^[a-z][a-z0-9_]+$")
    for code in ALL_CODES:
        assert pattern.match(code), f"malformed code: {code!r}"
        assert len(code) < 64, f"code too long: {code!r}"


def test_all_codes_unique():
    assert len(ALL_CODES) == len({
        TOOL_NOT_FOUND,
        CAPABILITY_DENIED,
        INSUFFICIENT_TIER,
        MISSING_BINDING,
        INTERNAL_ERROR,
    })
