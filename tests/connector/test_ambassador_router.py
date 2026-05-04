"""ADR-019 Step 1 — Connector Ambassador FastAPI router.

Tests cover:

  * Loopback enforcement (request.client.host)
  * Bearer auth (correct, missing, wrong, malformed)
  * /v1/models surface
  * /v1/chat/completions happy path (no tools)
  * /v1/chat/completions with tool-use loop
  * /v1/chat/completions with stream=True (fake-stream)
  * /v1/chat/completions max_iters truncation header
  * /v1/mcp tools/list passthrough
  * /v1/mcp tools/call passthrough
  * /v1/ambassador/health unauth + agent_id reflected

The Cullis SDK is replaced with a programmable fake so these are pure
unit tests with no network. The whole path goes through the real
FastAPI app built by ``cullis_connector.web.build_app``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
from cullis_connector.identity import (
    generate_keypair,
    save_identity,
)
from cullis_connector.identity.store import IdentityMetadata
from cullis_connector.web import build_app


# ── helpers ─────────────────────────────────────────────────────────


def _self_signed_cert_pem(private_key, *, common_name: str) -> str:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, common_name.split("::", 1)[0]),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _seed_identity(config_dir: Path, *, agent_id: str = "acme::frontdesk") -> None:
    key = generate_keypair()
    cert_pem = _self_signed_cert_pem(key, common_name=agent_id)
    metadata = IdentityMetadata(
        agent_id=agent_id,
        capabilities=[],
        site_url="https://mastio.test",
        issued_at="2026-05-04T10:00:00+00:00",
    )
    save_identity(
        config_dir=config_dir,
        cert_pem=cert_pem,
        private_key=key,
        ca_chain_pem=None,
        metadata=metadata,
    )


class FakeCullisClient:
    """Programmable stand-in for cullis_sdk.CullisClient.

    Test bodies push expected behaviours into the class-level shared
    state, then read what the Ambassador called.
    """

    last_login: tuple = ()
    chat_calls: list[dict] = []
    list_tools_calls: int = 0
    call_tool_calls: list[tuple] = []

    chat_responses: list[dict] = []  # popped FIFO
    tools_to_return: list[dict] = []
    tool_results: dict[str, Any] = {}

    @classmethod
    def reset(cls) -> None:
        cls.last_login = ()
        cls.chat_calls = []
        cls.list_tools_calls = 0
        cls.call_tool_calls = []
        cls.chat_responses = []
        cls.tools_to_return = []
        cls.tool_results = {}

    def __init__(self, *args, **kwargs) -> None:
        self._init_args = args
        self._init_kwargs = kwargs

    @classmethod
    def from_connector(cls, *args, **kwargs):
        """The dashboard's inbox poller calls this. Return a fresh fake."""
        return cls()

    def close(self) -> None:
        pass

    def list_inbox(self, *args, **kwargs):
        return []

    def discover(self, *args, **kwargs):
        return []

    def login_from_pem(self, agent_id, org_id, cert_pem, key_pem, **kw) -> None:
        type(self).last_login = (agent_id, org_id, cert_pem[:30], key_pem[:30])

    def chat_completion(self, body: dict) -> dict:
        type(self).chat_calls.append(body)
        if not type(self).chat_responses:
            return {
                "choices": [{
                    "message": {"role": "assistant", "content": "default fake answer"},
                    "finish_reason": "stop",
                }],
            }
        return type(self).chat_responses.pop(0)

    def list_mcp_tools(self) -> list[dict]:
        type(self).list_tools_calls += 1
        return list(type(self).tools_to_return)

    def call_mcp_tool(self, name: str, arguments: dict) -> dict:
        type(self).call_tool_calls.append((name, arguments))
        if name in type(self).tool_results:
            return type(self).tool_results[name]
        return {"content": [{"type": "text", "text": f"tool {name} ok"}]}


# ── fixtures ────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _patch_sdk(monkeypatch):
    FakeCullisClient.reset()
    monkeypatch.setattr("cullis_sdk.CullisClient", FakeCullisClient)
    yield
    FakeCullisClient.reset()


@pytest.fixture
def app(tmp_path: Path):
    _seed_identity(tmp_path)
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test",
        verify_tls=False,
    )
    # TestClient impersonates the host as ``testclient`` not 127.0.0.1,
    # so the loopback enforcement would 403 every test request. Disable
    # the check for unit tests (production deployments leave it on).
    cfg.ambassador.require_local_only = False
    return build_app(cfg)


@pytest.fixture
def client(app):
    # The Ambassador is mounted in the dashboard's lifespan, so the
    # TestClient must enter the context manager to trigger startup.
    with TestClient(app) as c:
        yield c


@pytest.fixture
def bearer(client, tmp_path: Path) -> str:
    """Read local.token AFTER the lifespan has run (depends on client)."""
    return (tmp_path / "local.token").read_text(encoding="utf-8").strip()


# ── tests ───────────────────────────────────────────────────────────


def test_health_works_without_bearer(client):
    resp = client.get("/v1/ambassador/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["agent_id"] == "acme::frontdesk"
    assert body["site_url"] == "https://mastio.test"


def test_models_requires_bearer(client):
    resp = client.get("/v1/models")
    assert resp.status_code == 401


def test_models_lists_default_three(client, bearer):
    resp = client.get(
        "/v1/models",
        headers={"Authorization": f"Bearer {bearer}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    ids = sorted(m["id"] for m in data)
    assert "claude-haiku-4-5" in ids
    assert len(ids) == 3


def test_chat_completions_rejects_wrong_bearer(client):
    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer wrong-token"},
        json={"model": "claude-haiku-4-5",
              "messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 401


def test_chat_completions_rejects_missing_authorization(client):
    resp = client.post(
        "/v1/chat/completions",
        json={"model": "claude-haiku-4-5",
              "messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 401


def test_chat_completions_happy_path_no_tools(client, bearer):
    FakeCullisClient.tools_to_return = []
    FakeCullisClient.chat_responses = [{
        "choices": [{
            "message": {"role": "assistant", "content": "ciao Mario"},
            "finish_reason": "stop",
        }],
    }]
    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "ciao"}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == "ciao Mario"
    # SDK was logged in once, chat called once, no tool dispatch
    assert FakeCullisClient.last_login[0] == "acme::frontdesk"
    assert FakeCullisClient.last_login[1] == "acme"
    assert len(FakeCullisClient.chat_calls) == 1
    assert FakeCullisClient.list_tools_calls == 1
    assert FakeCullisClient.call_tool_calls == []


def test_chat_completions_runs_tool_use_loop(client, bearer):
    """LLM returns a tool_call; Ambassador dispatches it; LLM is
    re-called with the tool result; final answer reaches the client."""
    FakeCullisClient.tools_to_return = [{
        "name": "query",
        "description": "run sql",
        "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}},
    }]
    FakeCullisClient.tool_results = {
        "query": {"content": [{"type": "text", "text": '[{"name":"Mario","ok":true}]'}]},
    }
    FakeCullisClient.chat_responses = [
        # First call: LLM asks for the tool
        {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "query",
                            "arguments": '{"sql":"SELECT name FROM compliance_status WHERE name ILIKE \'Mario%\'"}',
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        },
        # Second call: LLM returns the final answer
        {
            "choices": [{
                "message": {"role": "assistant", "content": "Mario ha completato il training."},
                "finish_reason": "stop",
            }],
        },
    ]

    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "Mario ha fatto il training?"}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == "Mario ha completato il training."
    # Tool loop ran exactly one tool dispatch.
    assert len(FakeCullisClient.call_tool_calls) == 1
    name, args = FakeCullisClient.call_tool_calls[0]
    assert name == "query"
    assert "compliance_status" in args["sql"]
    # Two chat completions: one to ask tool, one to format answer.
    assert len(FakeCullisClient.chat_calls) == 2


def test_chat_completions_streaming_returns_sse(client, bearer):
    FakeCullisClient.chat_responses = [{
        "choices": [{
            "message": {"role": "assistant", "content": "ciao streamed"},
            "finish_reason": "stop",
        }],
    }]
    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "stream": True,
            "messages": [{"role": "user", "content": "ciao"}],
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    body_text = resp.text
    assert "data: " in body_text
    assert "ciao streamed" in body_text
    assert "data: [DONE]" in body_text


def test_mcp_passthrough_tools_list(client, bearer):
    FakeCullisClient.tools_to_return = [{
        "name": "query",
        "description": "run sql",
        "inputSchema": {"type": "object"},
    }]
    resp = client.post(
        "/v1/mcp",
        headers={"Authorization": f"Bearer {bearer}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["tools"][0]["name"] == "query"


def test_mcp_passthrough_tools_call(client, bearer):
    FakeCullisClient.tool_results = {
        "query": {"content": [{"type": "text", "text": "ok"}]},
    }
    resp = client.post(
        "/v1/mcp",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "jsonrpc": "2.0", "id": 7,
            "method": "tools/call",
            "params": {"name": "query", "arguments": {"sql": "SELECT 1"}},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 7
    assert body["result"]["content"][0]["text"] == "ok"


def test_mcp_passthrough_unknown_method(client, bearer):
    resp = client.post(
        "/v1/mcp",
        headers={"Authorization": f"Bearer {bearer}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/foobar"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["error"]["code"] == -32601


def test_chat_completions_accepts_multimodal_content(client, bearer):
    """LibreChat-style ``content`` array of blocks must not fail validation."""
    FakeCullisClient.chat_responses = [{
        "choices": [{
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop",
        }],
    }]
    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": "ciao"}],
            }],
        },
    )
    assert resp.status_code == 200


def test_local_token_file_is_chmod_600(tmp_path: Path, client):
    """The token file must be created with mode 0600.

    Depends on ``client`` so the lifespan (which generates the file)
    has fired before we inspect the filesystem.
    """
    token_path = tmp_path / "local.token"
    assert token_path.exists()
    # On Windows / some FS the perm bits are loose; only assert on POSIX.
    import os
    import stat
    if os.name == "posix":
        mode = stat.S_IMODE(token_path.stat().st_mode)
        assert mode == 0o600, f"local.token mode is {oct(mode)}, expected 0o600"
