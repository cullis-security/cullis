"""Unit tests for the plugin approval hook.

Two scopes covered:
  * Plugin base class + registry: default ``approval_required`` is False;
    ``approval_required_for`` returns the first opted-in plugin.
  * Helper ``maybe_intercept_for_approval``: returns None when no plugin
    opts in (community fast path), returns a 303 RedirectResponse when a
    plugin gates the action, and falls through to direct execution when
    a misconfigured plugin opts in but cannot submit.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from starlette.responses import RedirectResponse

from mcp_proxy import plugins as mp_plugins
from mcp_proxy.admin.approval_hook import (
    ACTION_AGENTS_DELETE,
    ACTION_MASTIO_KEY_ROTATE,
    ACTION_PKI_ROTATE_CA,
    ACTION_POLICIES_SAVE,
    ACTION_USERS_DELETE,
    ACTION_VAULT_MIGRATE_KEYS,
    maybe_intercept_for_approval,
)
from mcp_proxy.plugins import Plugin, PluginRegistry


@pytest.fixture(autouse=True)
def _reset_registry():
    """Each test starts with an empty registry; never leak global state."""
    mp_plugins.reset_registry()
    yield
    mp_plugins.reset_registry()


def _mock_session(role: str = "admin") -> Any:
    s = MagicMock()
    s.role = role
    return s


# ── Plugin base class ─────────────────────────────────────────────────────


def test_default_plugin_does_not_gate():
    """A plugin that does not override ``approval_required`` returns False."""
    p = Plugin()
    assert p.approval_required(ACTION_POLICIES_SAVE) is False
    assert p.approval_required("anything.else") is False


@pytest.mark.asyncio
async def test_default_plugin_submit_raises():
    """Default submit_approval raises NotImplementedError, naming the plugin."""
    p = Plugin()
    p.name = "test_plugin"
    with pytest.raises(NotImplementedError, match="test_plugin"):
        await p.submit_approval("policies.save", {}, "admin")


# ── Registry ──────────────────────────────────────────────────────────────


def test_registry_no_plugins_returns_none():
    registry = PluginRegistry()
    assert registry.approval_required_for(ACTION_POLICIES_SAVE) is None


def test_registry_returns_first_opted_in_plugin():
    class GatingPlugin(Plugin):
        name = "gate"

        def approval_required(self, action_type: str) -> bool:
            return action_type == ACTION_POLICIES_SAVE

    class PassthroughPlugin(Plugin):
        name = "passthrough"

    p_gate = GatingPlugin()
    p_pass = PassthroughPlugin()
    registry = PluginRegistry(plugins=[p_pass, p_gate])

    assert registry.approval_required_for(ACTION_POLICIES_SAVE) is p_gate
    assert registry.approval_required_for(ACTION_PKI_ROTATE_CA) is None


def test_registry_swallows_plugin_exceptions_in_approval_check():
    """A plugin that raises during approval_required must not break others."""
    class BrokenPlugin(Plugin):
        name = "broken"

        def approval_required(self, action_type: str) -> bool:
            raise RuntimeError("boom")

    class WorkingPlugin(Plugin):
        name = "working"

        def approval_required(self, action_type: str) -> bool:
            return True

    registry = PluginRegistry(plugins=[BrokenPlugin(), WorkingPlugin()])
    result = registry.approval_required_for(ACTION_POLICIES_SAVE)
    assert result is not None
    assert result.name == "working"


# ── Helper: maybe_intercept_for_approval ─────────────────────────────────


@pytest.mark.asyncio
async def test_intercept_returns_none_when_no_plugin_opts_in(
    monkeypatch: pytest.MonkeyPatch,
):
    """Community fast path: empty registry returns None, caller proceeds."""
    monkeypatch.setattr(
        mp_plugins, "get_registry", lambda: PluginRegistry(plugins=[]),
    )
    result = await maybe_intercept_for_approval(
        session=_mock_session(),
        action_type=ACTION_POLICIES_SAVE,
        payload={"rules_json": "{}"},
    )
    assert result is None


@pytest.mark.asyncio
async def test_intercept_redirects_when_plugin_opts_in(
    monkeypatch: pytest.MonkeyPatch,
):
    """When a plugin gates the action, helper redirects to approval page."""
    submitted_args: dict[str, Any] = {}

    class QuorumPlugin(Plugin):
        name = "quorum"

        def approval_required(self, action_type: str) -> bool:
            return True

        async def submit_approval(
            self, action_type: str, payload: dict, submitter_id: str,
        ) -> str:
            submitted_args["action_type"] = action_type
            submitted_args["payload"] = payload
            submitted_args["submitter_id"] = submitter_id
            return "01H7XYZ..."

    monkeypatch.setattr(
        mp_plugins,
        "get_registry",
        lambda: PluginRegistry(plugins=[QuorumPlugin()]),
    )
    result = await maybe_intercept_for_approval(
        session=_mock_session(role="compliance_admin"),
        action_type=ACTION_PKI_ROTATE_CA,
        payload={},
    )

    assert isinstance(result, RedirectResponse)
    assert result.status_code == 303
    assert result.headers["location"] == "/proxy/admin/approvals/01H7XYZ..."
    assert submitted_args == {
        "action_type": ACTION_PKI_ROTATE_CA,
        "payload": {},
        "submitter_id": "compliance_admin",
    }


@pytest.mark.asyncio
async def test_intercept_falls_through_on_not_implemented(
    monkeypatch: pytest.MonkeyPatch,
):
    """Plugin that gates but does not implement submit_approval = no-op."""
    class MisconfiguredPlugin(Plugin):
        name = "misconfigured"

        def approval_required(self, action_type: str) -> bool:
            return True
        # Inherits default submit_approval that raises NotImplementedError.

    monkeypatch.setattr(
        mp_plugins,
        "get_registry",
        lambda: PluginRegistry(plugins=[MisconfiguredPlugin()]),
    )
    result = await maybe_intercept_for_approval(
        session=_mock_session(),
        action_type=ACTION_USERS_DELETE,
        payload={"principal_id": "org-a::user::alice"},
    )
    assert result is None


@pytest.mark.asyncio
async def test_intercept_falls_through_on_arbitrary_exception(
    monkeypatch: pytest.MonkeyPatch,
):
    """Plugin that crashes mid-submit must not break the original endpoint."""
    class CrashyPlugin(Plugin):
        name = "crashy"

        def approval_required(self, action_type: str) -> bool:
            return True

        async def submit_approval(
            self, action_type: str, payload: dict, submitter_id: str,
        ) -> str:
            raise RuntimeError("storage backend down")

    monkeypatch.setattr(
        mp_plugins,
        "get_registry",
        lambda: PluginRegistry(plugins=[CrashyPlugin()]),
    )
    result = await maybe_intercept_for_approval(
        session=_mock_session(),
        action_type=ACTION_AGENTS_DELETE,
        payload={"agent_id": "org-a::agent::bot-1"},
    )
    assert result is None


@pytest.mark.asyncio
async def test_intercept_handles_session_without_role(
    monkeypatch: pytest.MonkeyPatch,
):
    """Session with empty role falls back to 'admin' as submitter id."""
    captured: dict[str, str] = {}

    class CapturingPlugin(Plugin):
        name = "capturing"

        def approval_required(self, action_type: str) -> bool:
            return True

        async def submit_approval(
            self, action_type: str, payload: dict, submitter_id: str,
        ) -> str:
            captured["submitter_id"] = submitter_id
            return "01H_FALLBACK"

    monkeypatch.setattr(
        mp_plugins,
        "get_registry",
        lambda: PluginRegistry(plugins=[CapturingPlugin()]),
    )
    session = _mock_session(role=None)
    result = await maybe_intercept_for_approval(
        session=session,
        action_type=ACTION_VAULT_MIGRATE_KEYS,
        payload={},
    )
    assert isinstance(result, RedirectResponse)
    assert captured["submitter_id"] == "admin"


# ── Action constant stability ────────────────────────────────────────────


def test_action_constants_are_stable_strings():
    """Plugins key on these strings. Renaming requires a coordinated release."""
    assert ACTION_POLICIES_SAVE == "policies.save"
    assert ACTION_PKI_ROTATE_CA == "pki.rotate_ca"
    assert ACTION_MASTIO_KEY_ROTATE == "mastio_key.rotate"
    assert ACTION_VAULT_MIGRATE_KEYS == "vault.migrate_keys"
    assert ACTION_USERS_DELETE == "users.delete"
    assert ACTION_AGENTS_DELETE == "agents.delete"
