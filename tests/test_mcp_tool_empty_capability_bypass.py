"""Regression tests for F-A-304 — empty required_capability silent bypass.

Audit ref: ``imp/audits/2026-05-20/findings/track-a/F-A-304.md``.

Pre-fix, a builtin tool registered (or mutated) with an empty
``required_capability`` would silently bypass the executor's
capability gate for every authenticated principal type. Recommendation:

1. Builtins MUST declare a non-empty capability at registration time.
2. The executor MUST fail closed if a builtin somehow reaches it with
   an empty capability (defense in depth — see ADR-007).
3. MCP resources with no capability are still allowed (the binding
   table is authoritative per ADR-007), but the executor emits an
   explicit informational audit row so SOC can detect the shape.

These tests pin all three contracts.
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
from mcp_proxy.tools.registry import ToolDefinition, ToolRegistry, tool_registry


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def clean_registry():
    """Snapshot + restore the singleton registry to keep tests isolated."""
    saved = dict(tool_registry._tools)
    tool_registry._tools.clear()
    yield tool_registry
    tool_registry._tools.clear()
    tool_registry._tools.update(saved)


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
    async def get_tool_secrets(self, tool_name: str) -> dict[str, str]:
        return {}


def _exec_request(tool_name: str) -> ToolExecuteRequest:
    return ToolExecuteRequest.model_construct(
        tool=tool_name,
        parameters={},
        request_id="rq-test",
    )


# ── Registration-time guard ──────────────────────────────────────────


def test_register_decorator_refuses_empty_capability() -> None:
    """A builtin registered via the ``@register`` decorator without a
    capability must fail at import time. ValueError surfaces the
    misuse where it is cheapest to find — module import — not at
    runtime under a real principal."""
    reg = ToolRegistry()

    with pytest.raises(ValueError, match="F-A-304"):
        @reg.register(name="empty_cap_tool", capability="")
        async def _h(ctx):  # pragma: no cover — never called
            return {}


def test_register_decorator_refuses_whitespace_capability() -> None:
    """Whitespace-only capability is treated as empty (otherwise
    ``"   "`` would silently pass the registration check but fail
    the membership check at runtime, surfacing the bug late)."""
    reg = ToolRegistry()

    with pytest.raises(ValueError, match="F-A-304"):
        @reg.register(name="ws_cap_tool", capability="   ")
        async def _h(ctx):  # pragma: no cover
            return {}


def test_register_decorator_refuses_none_capability() -> None:
    """A None capability (e.g. a builder forgot the keyword arg) is
    rejected. The signature types ``capability: str`` but Python
    doesn't enforce that at runtime; the guard does."""
    reg = ToolRegistry()

    with pytest.raises(ValueError, match="F-A-304"):
        @reg.register(name="none_cap_tool", capability=None)  # type: ignore[arg-type]
        async def _h(ctx):  # pragma: no cover
            return {}


def test_register_definition_path_accepts_empty_capability_for_mcp_resource(
    clean_registry,
) -> None:
    """MCP resources from ``local_mcp_resources`` may carry empty
    capability — the binding table is the authz path. The lower-level
    ``register_definition`` accepts the shape; the executor will
    emit an informational audit and rely on the binding gate."""
    async def _h(ctx):
        return {}

    td = ToolDefinition(
        name="resource_no_cap",
        description="MCP resource with no capability declared",
        required_capability="",
        allowed_domains=[],
        handler=_h,
        resource_id="res-1",
        endpoint_url="https://upstream.invalid/mcp",
    )
    # Should NOT raise — recommendation #2 keeps this shape valid.
    tool_registry.register_definition(td)
    assert tool_registry.get("resource_no_cap") is td


# ── has_capability semantics ─────────────────────────────────────────


def test_has_capability_builtin_with_empty_capability_fails_closed(
    clean_registry,
) -> None:
    """``has_capability`` is a discovery-time helper. Pre-fix it
    returned True for any builtin with empty capability; post-fix
    it returns False to mirror the executor's runtime decision."""
    async def _h(ctx):
        return {}

    tool_registry.register_definition(ToolDefinition(
        name="builtin_no_cap",
        description="",
        required_capability="",
        allowed_domains=[],
        handler=_h,
    ))

    assert tool_registry.has_capability("builtin_no_cap", []) is False
    assert tool_registry.has_capability("builtin_no_cap", ["any.cap"]) is False


def test_has_capability_resource_with_empty_capability_allows(
    clean_registry,
) -> None:
    """MCP resource with empty capability still returns True from
    ``has_capability`` — discovery time, binding gate enforces."""
    async def _h(ctx):
        return {}

    tool_registry.register_definition(ToolDefinition(
        name="resource_no_cap",
        description="",
        required_capability="",
        allowed_domains=[],
        handler=_h,
        resource_id="res-1",
        endpoint_url="https://x.invalid/mcp",
    ))

    assert tool_registry.has_capability("resource_no_cap", []) is True


# ── Executor runtime fail-closed ─────────────────────────────────────


@pytest.mark.parametrize(
    "principal_type", ["agent", "user", "workload"],
)
@pytest.mark.asyncio
async def test_executor_denies_builtin_with_empty_capability(
    principal_type: str, clean_registry,
) -> None:
    """F-A-304 core regression: an empty-capability builtin reaches
    the executor (e.g. via ``register_definition`` from a test
    scaffold or future plugin path). The runtime gate MUST refuse,
    audit "missing capability declaration", and never invoke the
    handler — regardless of the caller's scope or principal type."""
    handler = AsyncMock(return_value={"ok": True})
    tool_registry.register_definition(ToolDefinition(
        name="builtin_no_cap",
        description="Empty capability builtin — fail-closed test",
        required_capability="",
        allowed_domains=[],
        handler=handler,
    ))
    # Even a maximally privileged caller must be denied.
    agent = _make_agent(
        scope=["anything", "everything"], principal_type=principal_type,
    )

    audit_mock = AsyncMock()
    with patch("mcp_proxy.tools.executor.log_audit", audit_mock):
        resp = await executor.run(
            request=_exec_request("builtin_no_cap"),
            agent=agent,
            db=None,
            secret_provider=_FakeSecretProvider(),
        )

    assert resp.status == "error", (resp.status, resp.error)
    assert resp.denied_reason_code == "capability_denied"
    assert "no capability" in (resp.error or "").lower()
    handler.assert_not_awaited()

    # The audit row carries the F-A-304 fingerprint.
    audited_details = [
        kwargs.get("detail", "") for _, kwargs in audit_mock.call_args_list
    ]
    assert any(
        "missing capability declaration" in d.lower() for d in audited_details
    ), audited_details


@pytest.mark.asyncio
async def test_executor_emits_informational_audit_for_resource_empty_capability(
    clean_registry,
) -> None:
    """Recommendation #2: MCP resource with empty capability gets an
    explicit ``policy.no_capability_required`` audit row before the
    binding gate runs. SOC sees the default-allow-by-capability
    shape; the binding gate still enforces."""
    handler = AsyncMock(return_value={"ok": True})
    tool_registry.register_definition(ToolDefinition(
        name="resource_no_cap",
        description="MCP resource with empty capability",
        required_capability="",
        allowed_domains=[],
        handler=handler,
        resource_id="res-1",
        endpoint_url="https://upstream.invalid/mcp",
    ))
    agent = _make_agent(scope=[], principal_type="agent")

    async def _binding_ok(*_a, **_k):
        return True

    audit_mock = AsyncMock()
    with patch(
        "mcp_proxy.local.bindings.has_active_binding", _binding_ok,
    ), patch("mcp_proxy.tools.executor.log_audit", audit_mock):
        resp = await executor.run(
            request=_exec_request("resource_no_cap"),
            agent=agent,
            db=None,
            secret_provider=_FakeSecretProvider(),
        )

    assert resp.status == "success", (resp.status, resp.error)
    handler.assert_awaited_once()

    actions = [
        kwargs.get("action") for _, kwargs in audit_mock.call_args_list
    ]
    assert "policy.no_capability_required" in actions, actions


@pytest.mark.asyncio
async def test_executor_resource_empty_capability_still_blocked_by_missing_binding(
    clean_registry,
) -> None:
    """Belt-and-braces: even with the new informational audit, an
    MCP resource without a binding is still denied (the binding gate
    is authoritative). Without this test a future refactor could
    silently downgrade the binding check to a log."""
    handler = AsyncMock(return_value={"ok": True})
    tool_registry.register_definition(ToolDefinition(
        name="resource_no_cap",
        description="MCP resource with empty capability",
        required_capability="",
        allowed_domains=[],
        handler=handler,
        resource_id="res-1",
        endpoint_url="https://upstream.invalid/mcp",
    ))
    agent = _make_agent(scope=[], principal_type="user")

    async def _binding_missing(*_a, **_k):
        return False

    with patch(
        "mcp_proxy.local.bindings.has_active_binding", _binding_missing,
    ), patch("mcp_proxy.tools.executor.log_audit", AsyncMock()):
        resp = await executor.run(
            request=_exec_request("resource_no_cap"),
            agent=agent,
            db=None,
            secret_provider=_FakeSecretProvider(),
        )

    assert resp.status == "error", (resp.status, resp.error)
    assert resp.denied_reason_code == "missing_binding"
    handler.assert_not_awaited()


# ── YAML override defense ────────────────────────────────────────────


def test_yaml_override_ignored_when_capability_empty(
    clean_registry, tmp_path,
) -> None:
    """``load_from_yaml`` merges YAML overrides into already-registered
    builtins. If the YAML override sets ``capability: ""``, the merge
    MUST be rejected so the live definition keeps its registration-time
    capability — otherwise an attacker (or accident) editing the YAML
    file could disable the gate without touching code."""
    async def _h(ctx):
        return {}

    # First: register a builtin with a real capability (decorator path
    # would refuse empty, so this is the established baseline).
    @tool_registry.register(
        name="yaml_target",
        capability="real.cap",
        description="baseline",
    )
    async def _real_handler(ctx):
        return {}

    yaml_file = tmp_path / "tools.yaml"
    yaml_file.write_text(
        "tools:\n"
        "  yaml_target:\n"
        "    module: tests.test_mcp_tool_empty_capability_bypass\n"
        "    capability: \"\"\n"
    )
    # Load the YAML — the loader should refuse the empty override.
    tool_registry.load_from_yaml(str(yaml_file))

    td = tool_registry.get("yaml_target")
    assert td is not None
    assert td.required_capability == "real.cap", (
        f"YAML empty-capability override should be ignored; "
        f"got {td.required_capability!r}"
    )
