"""Operator Rego policy gate on the executor's tool-call path.

The executor authorises tool calls with capability + tier + binding —
all STATIC (who you are, what device, what resource). This gate adds a
content-aware ABAC layer: the operator loads a Rego policy
(``cullis/policy/tool_call``) from the dashboard, and the executor now
consults it INLINE with the call's ``arguments`` in the input, so a rule
like "deny customer_id == CUST-00042" blocks the agent at runtime and
lands a ``status=denied`` audit row — the same surface the
``/v1/data/cullis/policy/tool_call`` bridge evaluates, but enforced on
the agent's own path (the bridge is the external PDP-as-a-service view).

The Rego ENGINE itself is covered by ``test_rego_engine`` + smoke
30/35; here ``try_rego_decision`` is mocked so these tests pin the
EXECUTOR gate behaviour:

1. decision=deny → POLICY_DENIED, handler never runs, audit denied.
2. the call's ``arguments`` reach the Rego input (the whole point — a
   rule on customer_id/name is only possible if it sees them).
3. no policy loaded (try_rego_decision → None) → call proceeds exactly
   as before (backward compatible).
4. decision=allow → call proceeds.
5. a missing capability is denied FIRST — the Rego gate is never
   reached (the more specific code wins, and a broken/permissive Rego
   can't widen a capability deny).
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
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_proxy.models import TokenPayload, ToolExecuteRequest
from mcp_proxy.policy.denied_reason_codes import (
    CAPABILITY_DENIED, INSUFFICIENT_TIER, MISSING_BINDING, POLICY_DENIED,
)
from mcp_proxy.policy.tier_matrix import TierMatrix
from mcp_proxy.tools import executor
from mcp_proxy.tools.registry import ToolDefinition, tool_registry

_TOOL_NAME = "get_customer_fixture"
_TOOL_CAP = "mcp.core_banking.read"
# A non-empty policy_rules JSON so the gate's get_config path is exercised;
# try_rego_decision is mocked, so the contents past JSON-parse don't matter.
_RULES_JSON = '{"rego_wasm_base64": "ZmFrZQ=="}'


@pytest.fixture
def clean_registry(monkeypatch):
    # Resource metadata store is readable, with delegation optional in this fixture.
    monkeypatch.setattr(executor, "_resource_requires_delegation", AsyncMock(return_value=False))
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
        jti="jti-rego-gate",
        scope=scope if scope is not None else [_TOOL_CAP],
        cnf={"jkt": "fake-jkt"},
        principal_type="agent",
    )


def _request(parameters: dict | None = None) -> ToolExecuteRequest:
    return ToolExecuteRequest.model_construct(
        tool=_TOOL_NAME,
        parameters=parameters if parameters is not None else {},
        request_id="rq-rego",
    )


def _register_tool(handler: AsyncMock | None = None, resource_id: str | None = None) -> AsyncMock:
    h = handler or AsyncMock(return_value={"ok": True})
    tool_registry.register_definition(ToolDefinition(
        name=_TOOL_NAME,
        description="Rego gate fixture",
        required_capability=_TOOL_CAP,
        allowed_domains=[],
        handler=h,
        resource_id=resource_id,
    ))
    return h


def _tier_ok():
    # Tier gate passes so execution reaches (or passes) the Rego gate.
    matrix = TierMatrix(
        version="test", default_min_tier="untrusted",
        by_exact={}, by_prefix=(), source_path="<test>",
    )
    return SimpleNamespace(tier_matrix=matrix)


@pytest.mark.asyncio
async def test_rego_deny_blocks_call_and_audits(clean_registry):
    handler = _register_tool()
    rego = MagicMock(return_value={"decision": "deny", "reason": "customer off-limits"})
    audit = AsyncMock()
    with patch("mcp_proxy.tools.executor.resolve_effective_tier",
               AsyncMock(return_value=("managed_attested", None))), \
         patch("mcp_proxy.tools.executor.get_config",
               AsyncMock(return_value=_RULES_JSON)), \
         patch("mcp_proxy.policy.try_rego_decision", rego), \
         patch("mcp_proxy.tools.executor.log_audit", audit):
        resp = await executor.run(
            request=_request({"customer_id": "CUST-00042"}),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=_tier_ok(),
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == POLICY_DENIED
    assert "customer off-limits" in resp.error
    handler.assert_not_awaited()  # tool must NOT run on a policy deny
    # audit wrote a denied row for this tool
    denied = [c for c in audit.await_args_list
              if c.kwargs.get("status") == "denied"
              and c.kwargs.get("tool_name") == _TOOL_NAME]
    assert denied, "a denied audit row must be written"


@pytest.mark.asyncio
async def test_arguments_reach_the_rego_input(clean_registry):
    _register_tool()
    captured = {}

    def _fake(rules, input_doc, *, surface):
        captured["input"] = input_doc
        captured["surface"] = surface
        return {"decision": "deny", "reason": "x"}

    with patch("mcp_proxy.tools.executor.resolve_effective_tier",
               AsyncMock(return_value=("managed_attested", None))), \
         patch("mcp_proxy.tools.executor.get_config",
               AsyncMock(return_value=_RULES_JSON)), \
         patch("mcp_proxy.policy.try_rego_decision", _fake), \
         patch("mcp_proxy.tools.executor.log_audit", AsyncMock()):
        await executor.run(
            request=_request({"customer_id": "CUST-00042", "name": "Acme SpA"}),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=_tier_ok(),
        )
    assert captured["surface"] == "tool_call"
    assert captured["input"]["arguments"] == {
        "customer_id": "CUST-00042", "name": "Acme SpA",
    }
    assert captured["input"]["tool_name"] == _TOOL_NAME
    assert captured["input"]["agent_id"] == "acme::daniele"


@pytest.mark.asyncio
async def test_no_policy_loaded_proceeds_as_before(clean_registry):
    handler = _register_tool()
    with patch("mcp_proxy.tools.executor.resolve_effective_tier",
               AsyncMock(return_value=("managed_attested", None))), \
         patch("mcp_proxy.tools.executor.get_config",
               AsyncMock(return_value=None)), \
         patch("mcp_proxy.policy.try_rego_decision", MagicMock(return_value=None)), \
         patch("mcp_proxy.tools.executor.log_audit", AsyncMock()):
        resp = await executor.run(
            request=_request({"customer_id": "CUST-00042"}),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=_tier_ok(),
        )
    assert resp.status == "success"
    assert resp.denied_reason_code is None
    handler.assert_awaited_once()


@pytest.mark.asyncio
async def test_rego_allow_proceeds(clean_registry):
    handler = _register_tool()
    with patch("mcp_proxy.tools.executor.resolve_effective_tier",
               AsyncMock(return_value=("managed_attested", None))), \
         patch("mcp_proxy.tools.executor.get_config",
               AsyncMock(return_value=_RULES_JSON)), \
         patch("mcp_proxy.policy.try_rego_decision",
               MagicMock(return_value={"decision": "allow"})), \
         patch("mcp_proxy.tools.executor.log_audit", AsyncMock()):
        resp = await executor.run(
            request=_request({"customer_id": "CUST-99999"}),
            agent=_agent(),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=_tier_ok(),
        )
    assert resp.status == "success"
    handler.assert_awaited_once()


@pytest.mark.asyncio
async def test_capability_deny_wins_before_rego_gate(clean_registry):
    """A principal without the capability is denied first; the Rego gate
    is never reached, so a permissive/broken Rego can't widen it."""
    _register_tool()
    rego = MagicMock(return_value={"decision": "allow"})
    with patch("mcp_proxy.tools.executor._load_principal_capabilities",
               AsyncMock(return_value=set())), \
         patch("mcp_proxy.policy.try_rego_decision", rego), \
         patch("mcp_proxy.tools.executor.log_audit", AsyncMock()):
        resp = await executor.run(
            request=_request({"customer_id": "CUST-1"}),
            agent=_agent(scope=[]),
            db=None,
            secret_provider=_FakeSecrets(),
            app_state=_tier_ok(),
        )
    assert resp.status == "error"
    assert resp.denied_reason_code == CAPABILITY_DENIED
    rego.assert_not_called()  # capability deny short-circuits before Rego


@pytest.mark.asyncio
@pytest.mark.parametrize("gate,expected_code", [
    ("capability", CAPABILITY_DENIED),
    ("tier", INSUFFICIENT_TIER),
    ("binding", MISSING_BINDING),
])
async def test_base_authorization_denial_never_loads_policy_or_secrets(
    clean_registry, monkeypatch, gate, expected_code,
):
    handler = _register_tool(resource_id="refunds")
    config = AsyncMock(side_effect=RuntimeError("policy store unavailable"))
    rego = MagicMock(return_value={"decision": "allow"})
    secrets = SimpleNamespace(get_tool_secrets=AsyncMock(return_value={}))
    audit = AsyncMock()
    monkeypatch.setattr(executor, "get_config", config)
    monkeypatch.setattr("mcp_proxy.policy.try_rego_decision", rego)
    monkeypatch.setattr(executor, "log_audit", audit)
    monkeypatch.setattr(executor, "resolve_effective_tier", AsyncMock(
        return_value=("untrusted" if gate == "tier" else "managed_attested", None),
    ))
    monkeypatch.setattr("mcp_proxy.local.bindings.has_active_binding", AsyncMock(
        return_value=gate != "binding",
    ))
    state = SimpleNamespace(tier_matrix=TierMatrix(
        version="test", default_min_tier="managed_attested",
        by_exact={}, by_prefix=(), source_path="<test>",
    ))
    resp = await executor.run(
        request=_request(), agent=_agent(scope=[] if gate == "capability" else None),
        db=None, secret_provider=secrets, app_state=state,
    )
    assert resp.status == "error"
    assert resp.denied_reason_code == expected_code
    config.assert_not_awaited()
    rego.assert_not_called()
    secrets.get_tool_secrets.assert_not_awaited()
    handler.assert_not_awaited()
    assert any(c.kwargs.get("status") == "denied" for c in audit.await_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize("raw,error,reason", [
    ("{broken", None, "policy_configuration_error"),
    ("[]", None, "policy_configuration_error"),
    (None, RuntimeError("synthetic-sensitive-config"), "policy_configuration_error"),
    ('{"rego":"package cullis.policy"}', None, "rego_artifact_error"),
    ('{"rego_wasm_base64":"invalid!"}', None, "rego_artifact_error"),
    (_RULES_JSON, None, "rego_evaluation_error"),
])
async def test_policy_failure_denies_before_secrets_and_handler(
    clean_registry, monkeypatch, raw, error, reason,
):
    handler = _register_tool(resource_id="refunds")
    secrets = SimpleNamespace(get_tool_secrets=AsyncMock(return_value={}))
    audit = AsyncMock()
    monkeypatch.setattr(executor, "get_config", AsyncMock(return_value=raw, side_effect=error))
    monkeypatch.setattr(executor, "log_audit", audit)
    monkeypatch.setattr(executor, "resolve_effective_tier", AsyncMock(return_value=("managed_attested", None)))
    monkeypatch.setattr("mcp_proxy.local.bindings.has_active_binding", AsyncMock(return_value=True))
    # Keep the real helper and decision normalization; an undefined rule must deny.
    monkeypatch.setattr("mcp_proxy.policy.rego_engine.RegoEngine.evaluate", lambda *a, **kw: None)
    resp = await executor.run(
        request=_request({"amount_cents": 50000}), agent=_agent(), db=None,
        secret_provider=secrets, app_state=_tier_ok(),
    )
    assert resp.status == "error"
    assert resp.denied_reason_code == POLICY_DENIED
    assert reason in resp.error
    secrets.get_tool_secrets.assert_not_awaited()
    handler.assert_not_awaited()
    denied = [c.kwargs for c in audit.await_args_list if c.kwargs.get("status") == "denied"]
    assert len(denied) == 1
    assert reason in denied[0]["detail"]
    assert "synthetic-sensitive-config" not in resp.error + str(denied)


@pytest.mark.asyncio
@pytest.mark.parametrize("declared,curr_requirement", [(True, False), (False, True)])
async def test_required_delegation_cannot_disappear_with_empty_policy(
    clean_registry, monkeypatch, declared, curr_requirement,
):
    handler = _register_tool(resource_id="refunds")
    tool_registry.get(_TOOL_NAME).requires_delegation = declared
    monkeypatch.setattr(executor, "_resource_requires_delegation", AsyncMock(return_value=curr_requirement))
    monkeypatch.setattr("mcp_proxy.local.bindings.has_active_binding", AsyncMock(return_value=True))
    monkeypatch.setattr(executor, "resolve_effective_tier", AsyncMock(return_value=("managed_attested", None)))
    monkeypatch.setattr(executor, "get_config", AsyncMock(return_value=None))
    monkeypatch.setattr(executor, "log_audit", AsyncMock())
    secrets = SimpleNamespace(get_tool_secrets=AsyncMock(return_value={}))
    response = await executor.run(request=_request(), agent=_agent(), db=None,
                                  secret_provider=secrets, app_state=_tier_ok())
    assert response.denied_reason_code == POLICY_DENIED
    assert "delegation_missing" in response.error
    handler.assert_not_awaited()
    secrets.get_tool_secrets.assert_not_awaited()
