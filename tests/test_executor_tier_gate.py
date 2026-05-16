"""ADR-032 Decision E / F5 — executor tier gate end-to-end.

The capability gate decides "is this principal allowed in principle?";
the tier gate decides "is this device in good enough shape RIGHT NOW?".
Both must fire; either denying short-circuits the call.

These tests drive ``executor.run`` with a fake registry + a mocked
``resolve_effective_tier`` so we can sweep the 5x5 actual×required
matrix without standing up a real DB. The audit emission is asserted
on a patched ``log_audit`` mock.
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
from mcp_proxy.policy.tier_matrix import TierMatrix
from mcp_proxy.tools import executor
from mcp_proxy.tools.registry import ToolDefinition, tool_registry


_TOOL_NAME = "test_tier_gated_tool"
_TOOL_CAP = "mcp.transfer_money"


@pytest.fixture
def clean_registry():
    saved = dict(tool_registry._tools)
    tool_registry._tools.clear()
    yield tool_registry
    tool_registry._tools.clear()
    tool_registry._tools.update(saved)


def _register_tool() -> AsyncMock:
    handler = AsyncMock(return_value={"ok": True})
    tool_registry.register_definition(ToolDefinition(
        name=_TOOL_NAME,
        description="Tier-gated tool fixture",
        required_capability=_TOOL_CAP,
        allowed_domains=[],
        handler=handler,
    ))
    return handler


def _agent(scope: list[str] | None = None) -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/acme::daniele",
        agent_id="acme::daniele",
        org="acme",
        exp=9_999_999_999,
        iat=0,
        jti="jti-tier-test",
        scope=scope or [_TOOL_CAP],
        cnf={"jkt": "fake-jkt"},
        principal_type="agent",
    )


class _FakeSecrets:
    async def get_tool_secrets(self, tool_name: str) -> dict[str, str]:
        return {}


def _request() -> ToolExecuteRequest:
    return ToolExecuteRequest.model_construct(
        tool=_TOOL_NAME, parameters={}, request_id="rq-tier",
    )


def _matrix(min_tier: str) -> TierMatrix:
    """Build a minimal matrix that maps the test capability to a
    chosen tier, with every other capability defaulting to
    ``untrusted`` so the test surfaces aren't surprised."""
    return TierMatrix(
        version="test",
        default_min_tier="untrusted",
        by_exact={_TOOL_CAP: min_tier},
        by_prefix=(),
        source_path="<test>",
    )


async def _run_with_tier(
    *, effective_tier: str, required_tier: str,
    audit_mock: AsyncMock | None = None,
):
    handler = _register_tool()
    agent = _agent()
    app_state = SimpleNamespace(tier_matrix=_matrix(required_tier))
    audit = audit_mock or AsyncMock()
    with patch(
        "mcp_proxy.tools.executor.resolve_effective_tier",
        AsyncMock(return_value=(effective_tier, None)),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", audit,
    ):
        resp = await executor.run(
            request=_request(),
            agent=agent,
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=app_state,
        )
    return resp, handler, audit


# ── deny path ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tier_below_requirement_denies_with_insufficient_tier(
    clean_registry,
):
    resp, handler, _ = await _run_with_tier(
        effective_tier="byod_isolated",
        required_tier="managed_attested",
    )
    assert resp.status == "error"
    err = (resp.error or "").lower()
    assert "byod_isolated" in err
    assert "managed_attested" in err
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_untrusted_device_denied_for_anything_above_untrusted(
    clean_registry,
):
    resp, handler, _ = await _run_with_tier(
        effective_tier="untrusted",
        required_tier="byod_isolated",
    )
    assert resp.status == "error"
    handler.assert_not_awaited()


# ── allow path ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tier_meets_requirement_allows_through(clean_registry):
    resp, handler, _ = await _run_with_tier(
        effective_tier="managed_attested",
        required_tier="managed",
    )
    assert resp.status == "success"
    handler.assert_awaited_once()


@pytest.mark.asyncio
async def test_tier_equal_to_requirement_allows(clean_registry):
    resp, handler, _ = await _run_with_tier(
        effective_tier="byod_attested",
        required_tier="byod_attested",
    )
    assert resp.status == "success"
    handler.assert_awaited_once()


# ── audit emission ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_deny_emits_policy_tier_evaluated_audit(clean_registry):
    audit = AsyncMock()
    resp, _, _ = await _run_with_tier(
        effective_tier="untrusted",
        required_tier="managed_attested",
        audit_mock=audit,
    )
    assert resp.status == "error"
    # Two audit rows fire on a deny: the canonical
    # ``policy.tier_evaluated`` AND the ``tool_execute`` denied event
    # that surfaces in the existing audit dashboard.
    actions = [call.kwargs.get("action") for call in audit.await_args_list]
    assert "policy.tier_evaluated" in actions
    assert "tool_execute" in actions

    tier_call = next(
        call for call in audit.await_args_list
        if call.kwargs.get("action") == "policy.tier_evaluated"
    )
    assert tier_call.kwargs["status"] == "deny"
    detail = tier_call.kwargs["detail"]
    assert "insufficient_tier" in detail
    assert "untrusted" in detail
    assert "managed_attested" in detail


@pytest.mark.asyncio
async def test_allow_emits_policy_tier_evaluated_audit(clean_registry):
    audit = AsyncMock()
    resp, _, _ = await _run_with_tier(
        effective_tier="managed_attested",
        required_tier="managed",
        audit_mock=audit,
    )
    assert resp.status == "success"
    actions = [call.kwargs.get("action") for call in audit.await_args_list]
    assert "policy.tier_evaluated" in actions

    tier_call = next(
        call for call in audit.await_args_list
        if call.kwargs.get("action") == "policy.tier_evaluated"
    )
    assert tier_call.kwargs["status"] == "allow"
    detail = tier_call.kwargs["detail"]
    # On allow there's no denied_reason_code.
    assert "denied_reason_code" not in detail


# ── matrix lookup integration ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_capability_without_matrix_entry_uses_default(clean_registry):
    """A capability not listed in the YAML falls back to
    ``default_min_tier``. With the default at ``untrusted`` the gate
    is a no-op for unlisted tools — that's the migration ramp."""
    handler = _register_tool()
    agent = _agent()
    matrix = TierMatrix(
        version="test",
        default_min_tier="untrusted",
        by_exact={},  # no entry for _TOOL_CAP
        by_prefix=(),
        source_path="<test>",
    )
    app_state = SimpleNamespace(tier_matrix=matrix)
    with patch(
        "mcp_proxy.tools.executor.resolve_effective_tier",
        AsyncMock(return_value=("untrusted", None)),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=agent,
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=app_state,
        )
    assert resp.status == "success"
    handler.assert_awaited_once()


@pytest.mark.asyncio
async def test_no_app_state_falls_back_to_load_default_matrix(
    clean_registry, monkeypatch, tmp_path,
):
    """When ``app_state`` is ``None`` (some smoke test paths), the
    executor must still resolve a matrix — falling back to the bundled
    YAML via ``load_default_tier_matrix``. We point at a permissive
    fixture so the test deterministically passes."""
    fixture = tmp_path / "tiers.yaml"
    fixture.write_text(
        'version: "1.0"\ndefault_min_tier: untrusted\ncapabilities: {}\n',
    )
    monkeypatch.setenv("MCP_PROXY_TIER_MATRIX_PATH", str(fixture))

    handler = _register_tool()
    agent = _agent()
    with patch(
        "mcp_proxy.tools.executor.resolve_effective_tier",
        AsyncMock(return_value=("untrusted", None)),
    ), patch(
        "mcp_proxy.tools.executor.log_audit", AsyncMock(),
    ):
        resp = await executor.run(
            request=_request(),
            agent=agent,
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=None,
        )
    # default_min_tier=untrusted ⇒ gate passes ⇒ handler fires.
    assert resp.status == "success"
    handler.assert_awaited_once()
