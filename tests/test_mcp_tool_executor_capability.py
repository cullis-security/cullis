"""Regression test for the typed-principal capability-bypass hotfix.

Audit ref: PR #729 post-merge subagent review finding
(https://github.com/cullis-security/cullis/pull/729#issuecomment-4463659987).

Pre-#730 the executor's capability check was guarded by
``principal_type == "agent"``. User- and workload-typed principals
silently bypassed the gate on every builtin. PR #729 added the
first privileged builtin (``cullis_send_to_agent``), making the
gap exploitable.

These tests pin the post-fix contract:

* every principal type now goes through the capability gate on
  builtins (agent / user / workload),
* the agent-typed regression path is unchanged (existing CRIT-2
  test_agent_principal_with_binding_but_no_capability_denied
  must still pass — exercised under the full suite),
* typed-principal MCP-resource access stays binding-only (the
  ADR-007 design),
* the gate fails closed when the capability-lookup helper raises.
"""
from __future__ import annotations

import os

# Mirror the conftest baseline so this file runs standalone.
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mcp_proxy.models import TokenPayload, ToolExecuteRequest
from mcp_proxy.tools import executor
from mcp_proxy.tools.registry import ToolDefinition, tool_registry


# ── Fixtures ──────────────────────────────────────────────────────────


_BUILTIN_NAME = "test_builtin_with_capability"
_BUILTIN_CAP = "test.privileged"


@pytest.fixture
def clean_registry():
    """Snapshot + restore the singleton registry to keep tests isolated."""
    saved = dict(tool_registry._tools)
    tool_registry._tools.clear()
    yield tool_registry
    tool_registry._tools.clear()
    tool_registry._tools.update(saved)


def _register_builtin(handler=None) -> AsyncMock:
    """Register a no-op builtin with a non-empty required_capability.

    Returns the AsyncMock so the test can assert whether the handler
    fired (gate passed) vs not (gate rejected).
    """
    handler_mock = AsyncMock(return_value={"ok": True})
    if handler is not None:
        handler_mock = handler

    tool_registry.register_definition(ToolDefinition(
        name=_BUILTIN_NAME,
        description="Privileged builtin used to pin the gate behaviour",
        required_capability=_BUILTIN_CAP,
        allowed_domains=[],
        handler=handler_mock,
        # is_mcp_resource stays False — builtins have no resource_id.
    ))
    return handler_mock


def _make_agent(
    *,
    agent_id: str = "acme::daniele",
    org: str = "acme",
    scope: list[str] | None = None,
    principal_type: str = "agent",
) -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/{agent_id}",
        agent_id=agent_id,
        org=org,
        exp=9_999_999_999,
        iat=0,
        jti=f"jti-{agent_id}-{principal_type}",
        scope=scope or [],
        cnf={"jkt": "fake-jkt"},
        principal_type=principal_type,
    )


class _FakeSecretProvider:
    """Minimal SecretProvider shim — returns no secrets, never raises."""

    async def get_tool_secrets(self, tool_name: str) -> dict[str, str]:
        return {}


def _exec_request(parameters: dict[str, Any] | None = None) -> ToolExecuteRequest:
    """Build a permissive ToolExecuteRequest. The aggregator uses
    ``model_construct`` to bypass the strict ``tool`` regex; mirror
    that here so the tool name's underscore convention doesn't trip
    Pydantic before we even reach the gate."""
    return ToolExecuteRequest.model_construct(
        tool=_BUILTIN_NAME,
        parameters=parameters or {},
        request_id="rq-test",
    )


async def _run_executor(agent: TokenPayload):
    """Drive ``executor.run`` with the minimum surface every test
    needs. ``log_audit`` is patched to a no-op so the test stays
    independent of the DB lifecycle."""
    with patch("mcp_proxy.tools.executor.log_audit", AsyncMock()):
        return await executor.run(
            request=_exec_request(),
            agent=agent,
            db=None,
            secret_provider=_FakeSecretProvider(),
        )


# ── Negative path: typed principals without the capability ──────────


@pytest.mark.parametrize("principal_type", ["user", "workload"])
@pytest.mark.asyncio
async def test_typed_principal_without_capability_is_rejected(
    principal_type: str, clean_registry,
) -> None:
    """REGRESSION (post-PR #729): typed principals without the tool's
    declared capability MUST be rejected, not silently authorized."""
    handler = _register_builtin()
    agent = _make_agent(scope=[], principal_type=principal_type)

    resp = await _run_executor(agent)

    assert resp.status == "error", (
        f"{principal_type} principal with empty scope should be denied; "
        f"got {resp.status}"
    )
    assert "missing capability" in (resp.error or "").lower()
    assert _BUILTIN_CAP in (resp.error or "")
    handler.assert_not_awaited()


# ── Positive path: typed principals WITH the capability ──────────────


@pytest.mark.parametrize("principal_type", ["user", "workload"])
@pytest.mark.asyncio
async def test_typed_principal_with_capability_is_allowed(
    principal_type: str, clean_registry,
) -> None:
    """Positive control: when the typed principal carries the
    capability in scope, the executor reaches the handler."""
    handler = _register_builtin()
    agent = _make_agent(scope=[_BUILTIN_CAP], principal_type=principal_type)

    resp = await _run_executor(agent)

    assert resp.status == "success", (
        f"{principal_type} principal with capability should pass the "
        f"gate; got status={resp.status} error={resp.error!r}"
    )
    handler.assert_awaited_once()


# ── Agent-typed regression (must stay unchanged) ─────────────────────


@pytest.mark.asyncio
async def test_agent_without_capability_still_rejected(clean_registry) -> None:
    """The agent-typed gate must be untouched by this change. Pre-fix
    agents without the capability were denied; post-fix the same is
    true (and the existing CRIT-2 suite also pins it)."""
    handler = _register_builtin()
    agent = _make_agent(scope=[], principal_type="agent")

    resp = await _run_executor(agent)

    assert resp.status == "error"
    assert "missing capability" in (resp.error or "").lower()
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_agent_with_capability_still_allowed(clean_registry) -> None:
    """Mirror of the negative agent test — capability in scope means
    the gate lets the handler run, no behaviour change vs pre-fix."""
    handler = _register_builtin()
    agent = _make_agent(scope=[_BUILTIN_CAP], principal_type="agent")

    resp = await _run_executor(agent)

    assert resp.status == "success", (resp.status, resp.error)
    handler.assert_awaited_once()


# ── Fail-closed when the lookup helper raises ────────────────────────


@pytest.mark.parametrize(
    "principal_type", ["agent", "user", "workload"],
)
@pytest.mark.asyncio
async def test_capability_check_fails_closed_on_provider_error(
    principal_type: str, clean_registry,
) -> None:
    """When ``_load_principal_capabilities`` raises (e.g. an ADR-021
    user-store outage once that helper grows real lookups), the
    executor MUST deny and audit "capability lookup failed". Silent
    grant on lookup failure is exactly the class of bug this hotfix
    closes — pin the fail-closed contract for every principal type."""
    handler = _register_builtin()
    agent = _make_agent(
        scope=[_BUILTIN_CAP],   # would normally pass — but the helper raises
        principal_type=principal_type,
    )

    raising = AsyncMock(side_effect=RuntimeError("user store offline"))
    with patch(
        "mcp_proxy.tools.executor._load_principal_capabilities", raising,
    ), patch("mcp_proxy.tools.executor.log_audit", AsyncMock()):
        resp = await executor.run(
            request=_exec_request(),
            agent=agent,
            db=None,
            secret_provider=_FakeSecretProvider(),
        )

    assert resp.status == "error"
    assert "capability lookup failed" in (resp.error or "").lower()
    handler.assert_not_awaited()


# ── Default helper sources from JWT scope (no behaviour drift) ──────


@pytest.mark.asyncio
async def test_load_principal_capabilities_sources_from_jwt_scope() -> None:
    """Today the helper just wraps ``agent.scope``. Pin that
    contract so a future extension (ADR-021 user store / ADR-020
    richer workload bindings) is a deliberate additive change with
    a test update, not an accidental drift."""
    agent = _make_agent(scope=["cap.a", "cap.b"], principal_type="user")
    caps = await executor._load_principal_capabilities(agent, app_state=None)
    assert caps == {"cap.a", "cap.b"}


# ── MCP resources still gated by bindings, not capability ───────────


@pytest.mark.asyncio
async def test_typed_principal_mcp_resource_not_capability_gated(
    clean_registry, monkeypatch,
) -> None:
    """ADR-007 invariant: for MCP resources, the binding table is
    authoritative. Capability is optional discovery-time metadata.
    Even after the hotfix, typed callers on MCP resources are
    gated by the binding table only — not by a capability the
    JWT happens not to carry. (Agents continue to be gated by
    BOTH on MCP resources; see CRIT-2 suite.)"""
    handler = AsyncMock(return_value={"ok": True, "via": "mcp_resource"})
    tool_registry.register_definition(ToolDefinition(
        name="mcp_resource_with_cap",
        description="Resource tool with declared capability metadata",
        required_capability="github.read",
        allowed_domains=[],
        handler=handler,
        resource_id="github",   # makes ``is_mcp_resource`` True
        endpoint_url="https://example.invalid/mcp",
    ))

    agent = _make_agent(
        scope=[],   # no github.read — but for typed callers the gate skips
        principal_type="user",
    )

    # Active binding exists, so the binding gate at step 2b lets it through.
    async def _binding_ok(*_a, **_k):
        return True

    with patch(
        "mcp_proxy.local.bindings.has_active_binding", _binding_ok,
    ), patch("mcp_proxy.tools.executor.log_audit", AsyncMock()):
        resp = await executor.run(
            request=ToolExecuteRequest.model_construct(
                tool="mcp_resource_with_cap",
                parameters={},
                request_id="rq-mcp",
            ),
            agent=agent,
            db=None,
            secret_provider=_FakeSecretProvider(),
        )

    assert resp.status == "success", (resp.status, resp.error)
    handler.assert_awaited_once()
