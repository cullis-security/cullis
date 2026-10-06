"""Tests for the ``mcp_proxy.policy.try_rego_decision`` helper.

The helper is the single entry point both PDP routes (``/pdp/policy``,
``/v1/data/cullis/policy/*``) consume to decide whether the Rego
layer has an opinion on a request. Its contract is documented in
the docstring; these tests pin:

  * No Rego configured → returns ``None`` (caller falls through to
    legacy allowlist)
  * Configured but missing/corrupt artifact → deny + static reason
  * Rego runtime error → deny + static reason, without exception contents
  * Rego returns ``{decision, reason}`` → helper passes through verbatim
"""
from __future__ import annotations

import base64

import pytest

from mcp_proxy.policy import parse_policy_rules, try_rego_decision
from mcp_proxy.policy.rego_engine import RegoEvalError


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ── no Rego configured ────────────────────────────────────────────────────


def test_no_rules_returns_none():
    assert try_rego_decision({}, {}, surface="session") is None


def test_non_dict_rules_denied():
    assert try_rego_decision("not-a-dict", {}, surface="session") == {  # type: ignore[arg-type]
        "decision": "deny", "reason": "policy_configuration_error",
    }


def test_empty_rego_wasm_with_source_denied():
    rules = {"rego": "package cullis.policy", "rego_wasm_base64": ""}
    assert try_rego_decision(rules, {}, surface="session") == {
        "decision": "deny", "reason": "rego_artifact_error",
    }


def test_missing_rego_wasm_with_source_denied():
    """A configured policy must not disappear when its artifact is lost."""
    rules = {"rego": "package cullis.policy\nallow := true"}
    assert try_rego_decision(rules, {}, surface="session") == {
        "decision": "deny", "reason": "rego_artifact_error",
    }


# ── malformed base64 ──────────────────────────────────────────────────────


def test_malformed_base64_denied_and_logs(monkeypatch):
    # ``mcp_proxy.policy`` logger has ``propagate=False`` (logging_setup.py),
    # so pytest ``caplog`` (root-attached) never sees its records. Capture
    # the warning by monkeypatching ``_log.warning`` directly — the suite
    # convention for asserting on mcp_proxy.* log output.
    rules = {"rego_wasm_base64": "not===valid===base64==="}
    warnings: list[str] = []
    import mcp_proxy.policy as _policy_mod
    monkeypatch.setattr(
        _policy_mod._log, "warning",
        lambda msg, *a, **kw: warnings.append(str(msg) % a if a else str(msg)),
    )
    out = try_rego_decision(rules, {}, surface="session")
    assert out == {"decision": "deny", "reason": "rego_artifact_error"}
    assert any("rego_artifact_error" in w for w in warnings)


# ── Rego runtime error path ───────────────────────────────────────────────


@pytest.mark.parametrize("surface", ["session", "tool_call"])
@pytest.mark.parametrize("error_type", [RegoEvalError, TypeError, RuntimeError])
def test_rego_eval_error_denied_without_leaking_exception(monkeypatch, surface, error_type):
    rules = {"rego_wasm_base64": _b64(b"\x00asm\x01\x00\x00\x00fake")}

    def _raise(*a, **kw):
        raise error_type("synthetic-sensitive-policy-input")

    monkeypatch.setattr(
        "mcp_proxy.policy.evaluate_decision", _raise,
    )

    # See note in test_malformed_base64: capture mcp_proxy.policy warnings
    # via monkeypatch, not caplog (logger has propagate=False).
    warnings: list[str] = []
    import mcp_proxy.policy as _policy_mod
    monkeypatch.setattr(
        _policy_mod._log, "warning",
        lambda msg, *a, **kw: warnings.append(str(msg) % a if a else str(msg)),
    )
    out = try_rego_decision(rules, {}, surface=surface)
    assert out == {"decision": "deny", "reason": "rego_evaluation_error"}
    assert any("rego_evaluation_error" in w for w in warnings)
    assert "synthetic-sensitive-policy-input" not in str(out) + str(warnings)


@pytest.mark.parametrize("raw", [None, "", "{}"])
def test_absent_policy_configuration_is_empty(raw):
    assert parse_policy_rules(raw) == {}


@pytest.mark.parametrize("raw", ["{broken", "null", "[]", "true", "0", '"text"'])
def test_invalid_policy_configuration_is_not_absence(raw):
    with pytest.raises(ValueError):
        parse_policy_rules(raw)


def test_empty_source_and_artifact_mean_no_rego():
    assert try_rego_decision({"rego": "", "rego_wasm_base64": ""}, {}, surface="tool_call") is None


@pytest.mark.parametrize("artifact", [False, 0, [], {}, "not base64"])
def test_invalid_artifact_type_cannot_remove_policy(artifact):
    assert try_rego_decision({"rego_wasm_base64": artifact}, {}, surface="tool_call") == {
        "decision": "deny", "reason": "rego_artifact_error",
    }


@pytest.mark.parametrize("output", [None, {}, {"decision": []}, {"decision": "unknown"}, "allow"])
def test_malformed_runtime_decision_denied(monkeypatch, output):
    monkeypatch.setattr("mcp_proxy.policy.rego_engine.RegoEngine.evaluate", lambda *a, **kw: output)
    assert try_rego_decision({"rego_wasm_base64": _b64(b"fake")}, {}, surface="tool_call") == {
        "decision": "deny", "reason": "rego_evaluation_error",
    }


# ── happy path: Rego decision passed through ──────────────────────────────


def test_rego_decision_passthrough(monkeypatch):
    rules = {"rego_wasm_base64": _b64(b"\x00asm\x01\x00\x00\x00fake")}

    captured = {}

    def _fake_eval(policy, input_doc, *, entrypoint: str):
        captured["entrypoint"] = entrypoint
        captured["input"] = input_doc
        return {"decision": "deny", "reason": "Treasury wire denied by Rego"}

    monkeypatch.setattr("mcp_proxy.policy.evaluate_decision", _fake_eval)

    out = try_rego_decision(
        rules,
        {"agent_id": "orga::treasurer", "tool_name": "treasury_wire"},
        surface="tool_call",
    )
    assert out == {
        "decision": "deny",
        "reason": "Treasury wire denied by Rego",
    }
    # Helper picks the right entrypoint per surface so the operator's
    # Rego file can hold session + tool_call rules side by side.
    assert captured["entrypoint"] == "cullis/policy/tool_call"
    assert captured["input"]["tool_name"] == "treasury_wire"


def test_rego_decision_passthrough_session_entrypoint(monkeypatch):
    rules = {"rego_wasm_base64": _b64(b"\x00asm\x01\x00\x00\x00fake")}
    captured = {}

    def _fake_eval(policy, input_doc, *, entrypoint: str):
        captured["entrypoint"] = entrypoint
        return {"decision": "allow"}

    monkeypatch.setattr("mcp_proxy.policy.evaluate_decision", _fake_eval)

    out = try_rego_decision(
        rules,
        {"initiator_agent_id": "a", "target_agent_id": "b"},
        surface="session",
    )
    assert out == {"decision": "allow"}
    assert captured["entrypoint"] == "cullis/policy/session"
