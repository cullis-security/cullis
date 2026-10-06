"""Starter acceptance boundaries: identity preservation and bounded tool execution."""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "packaging/mastio-bundle/first-agent.py"
spec = importlib.util.spec_from_file_location("first_agent_starter", SCRIPT)
starter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(starter)


def response(*, calls=None, content="Done", finish_reason="stop"):
    return {"cullis_trace_id": "trace-test", "choices": [{
        "finish_reason": finish_reason,
        "message": {"role": "assistant", "content": content, "tool_calls": calls or []},
    }]}


def call(name="read_status", arguments='{"project": "demo"}', call_id="call-1"):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


def client_with(*responses):
    client = Mock()
    client.list_mcp_tools.return_value = [
        {"name": "read_status", "inputSchema": {"type": "object"}},
        {"name": "delete_project", "inputSchema": {"type": "object"}},
    ]
    client.chat_completion.side_effect = responses
    client.call_mcp_tool.return_value = {"content": [{"type": "text", "text": "All tasks complete"}]}
    return client


def run(client, **kwargs):
    options = dict(model="fixture-model", task="Summarise demo project", tool_names=["read_status"],
                   max_steps=5, max_tool_calls=10)
    options.update(kwargs)
    return starter.run_task(client, **options)


def test_model_tool_result_roundtrip_only_offers_selected_tools():
    client = client_with()
    sent = []
    replies = iter([response(calls=[call()], content=None), response()])

    def complete(body):
        sent.append(copy.deepcopy(body))
        return next(replies)

    client.chat_completion.side_effect = complete
    assert run(client) == "Done"
    assert [tool["function"]["name"] for tool in sent[0]["tools"]] == ["read_status"]
    client.call_mcp_tool.assert_called_once_with("read_status", {"project": "demo"})
    assert sent[1]["messages"][-1]["tool_call_id"] == "call-1"
    assert json.loads(sent[1]["messages"][-1]["content"]) == client.call_mcp_tool.return_value


def test_chat_only_needs_no_tool_permissions():
    client = client_with(response())
    assert run(client, tool_names=[]) == "Done"
    client.list_mcp_tools.assert_not_called()
    assert "tools" not in client.chat_completion.call_args.args[0]


def test_missing_binding_stops_before_model_or_tool_call():
    client = client_with()
    client.list_mcp_tools.return_value = []
    with pytest.raises(starter.AgentError, match="not visible"):
        run(client)
    client.chat_completion.assert_not_called()
    client.call_mcp_tool.assert_not_called()


@pytest.mark.parametrize("bad_call", [
    call(name="delete_project", call_id="call-2"),
    call(arguments="not json", call_id="call-2"),
    call(arguments="[]", call_id="call-2"),
    call(call_id="call-1"),
    {"id": "call-2", "function": []},
])
def test_invalid_later_call_prevents_partial_batch_execution(bad_call):
    client = client_with(response(calls=[call(), bad_call]))
    with pytest.raises(starter.AgentError):
        run(client)
    client.call_mcp_tool.assert_not_called()


@pytest.mark.parametrize("limits", [{"max_steps": 1}, {"max_tool_calls": 1}])
def test_limits_stop_before_executing_batch(limits):
    client = client_with(response(calls=[call(), call(call_id="call-2")]))
    with pytest.raises(starter.AgentError, match="limit"):
        run(client, **limits)
    client.call_mcp_tool.assert_not_called()


def test_tool_failure_is_not_retried_or_reported_as_success():
    client = client_with(response(calls=[call()]))
    client.call_mcp_tool.return_value = {"isError": True, "content": []}
    with pytest.raises(starter.AgentError, match="tool reported an error"):
        run(client)
    assert client.call_mcp_tool.call_count == client.chat_completion.call_count == 1


@pytest.mark.parametrize("reply", [response(content=""), response(finish_reason="length"), {"choices": []}])
def test_incomplete_answer_is_not_success(reply):
    with pytest.raises(starter.AgentError):
        run(client_with(reply))


@pytest.mark.parametrize("url", ["http://mastio.test", "https://mastio.test/v1", "https://user:secret@mastio.test", "https://mastio.test?key=secret"])
def test_connection_rejects_ambiguous_or_insecure_url(url):
    with pytest.raises(starter.AgentError):
        starter.mastio_url(url)


def test_existing_identity_never_overwritten(tmp_path, monkeypatch):
    key = tmp_path / "agent.key"
    key.write_text("existing-key")
    enroll = Mock()
    monkeypatch.setattr(starter.CullisClient, "enroll_via_dashboard_approval", enroll)
    with pytest.raises(starter.AgentError, match="not empty"):
        starter.connect(argparse.Namespace(url="https://mastio.test", identity=tmp_path))
    enroll.assert_not_called()
    assert key.read_text() == "existing-key"


def test_saved_identity_uses_explicit_dpop_and_server_trust(tmp_path, monkeypatch):
    for name in starter.IDENTITY_FILES:
        (tmp_path / name).write_text("fixture")
    (tmp_path / "meta.json").write_text(json.dumps({"mastio_url": "https://mastio.test:9443"}))
    (tmp_path / "server-ca.pem").write_text("fixture CA")
    factory = Mock()
    monkeypatch.setattr(starter.CullisClient, "from_identity_dir", factory)
    assert starter.load_client(tmp_path) is factory.return_value
    assert factory.call_args.kwargs["verify_tls"] is True
    assert factory.call_args.kwargs["dpop_key_path"] == tmp_path / "dpop.jwk"
    assert factory.call_args.kwargs["ca_chain_path"] == tmp_path / "server-ca.pem"


def test_mtls_only_bundle_is_rejected_before_loading_client(tmp_path):
    for name in ("agent.crt", "agent.key", "meta.json"):
        (tmp_path / name).write_text("fixture")
    with pytest.raises(starter.AgentError, match="dpop.jwk"):
        starter.load_client(tmp_path)


def test_check_does_not_spend_tokens_or_execute_tools():
    client = client_with()
    starter.check(client)
    client.login_via_proxy_with_local_key.assert_called_once()
    client.chat_completion.assert_not_called()
    client.call_mcp_tool.assert_not_called()


def test_http_failure_exits_nonzero_without_leaking_response(tmp_path, monkeypatch, caplog):
    client = client_with()
    request = httpx.Request("POST", "https://mastio.test/v1/llm/chat")
    resp = httpx.Response(403, request=request, text="private-upstream-detail")
    client.chat_completion.side_effect = httpx.HTTPStatusError("private-exception", request=request, response=resp)
    monkeypatch.setattr(starter, "load_client", lambda _: client)
    assert starter.main(["run", "--model", "fixture", "--task", "hello"]) == 1
    assert "403" in caplog.text
    assert "private-upstream-detail" not in caplog.text
    assert "private-exception" not in caplog.text
    client.close.assert_called_once()
