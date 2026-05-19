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
from fastapi import HTTPException
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

    # P1 Tier B F2b streaming loop — each entry is a list of SSE frame
    # strings the fake yields from a single ``chat_completion_stream``
    # call. ``stream_chunks`` pops FIFO per loop iteration.
    stream_chunks: list[list[str]] = []
    stream_calls: list[dict] = []

    # ADR-029 Phase D, programmable PDP for tool-level tests. Each entry
    # in pdp_responses pops FIFO; pdp_raise toggles an exception path.
    pdp_calls: list[dict] = []
    pdp_responses: list[dict] = []
    pdp_raise: bool = False

    @classmethod
    def reset(cls) -> None:
        cls.last_login = ()
        cls.chat_calls = []
        cls.list_tools_calls = 0
        cls.call_tool_calls = []
        cls.chat_responses = []
        cls.tools_to_return = []
        cls.tool_results = {}
        cls.pdp_calls = []
        cls.pdp_responses = []
        cls.pdp_raise = False
        cls.stream_chunks = []
        cls.stream_calls = []

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
        # ADR-029 Phase D: ambassador reads client.agent_id to populate
        # the PDP principal field when no per-user credentials are set.
        self.agent_id = agent_id

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

    def chat_completion_stream(self, body: dict):
        """P1 Tier B F2b streaming variant. Yields SSE frame strings
        from the per-iteration ``stream_chunks`` queue. The body each
        iter receives is captured separately so a test can pin the
        tool-result messages were threaded through the next turn."""
        type(self).stream_calls.append(body)
        if not type(self).stream_chunks:
            # Default: trivial text-only stream + DONE.
            import json as _json
            yield (
                "data: " + _json.dumps({
                    "choices": [{"index": 0,
                                  "delta": {"content": "default streamed"},
                                  "finish_reason": None}],
                }) + "\n\n"
            )
            yield (
                "data: " + _json.dumps({
                    "choices": [{"index": 0,
                                  "delta": {},
                                  "finish_reason": "stop"}],
                }) + "\n\n"
            )
            yield "data: [DONE]\n\n"
            return
        for f in type(self).stream_chunks.pop(0):
            yield f

    def evaluate_tool_call_policy(self, **kwargs) -> dict:
        type(self).pdp_calls.append(kwargs)
        if type(self).pdp_raise:
            raise RuntimeError("simulated PDP transport failure")
        if type(self).pdp_responses:
            return type(self).pdp_responses.pop(0)
        return {"allowed": True, "reason": "default fake allow"}


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


# ── ADR-034 §5 — /v1/models live-only in shared mode ───────────────


def test_models_503_in_shared_mode_when_mastio_unreachable(
    client, bearer, monkeypatch,
):
    """ADR-034 §5: shared mode (Frontdesk) must fail loud when the
    live Mastio fetch fails. Returning a hardcoded ``advertised_models``
    list would advertise models the admin never configured and the
    user would only learn at chat time. The 503 lets the SPA banner
    "Cannot reach Mastio" up front.

    Single-mode (Cullis Chat desktop) behaviour is covered by
    ``test_models_lists_default_three`` above — the fallback there is
    intentional consumer UX baseline.
    """
    monkeypatch.setenv("AMBASSADOR_MODE", "shared")
    # Bust the in-process cache so the previous single-mode test's
    # cached fallback list doesn't bleed in.
    from cullis_connector.ambassador.router import _models_cache

    _models_cache.clear()

    resp = client.get(
        "/v1/models",
        headers={"Authorization": f"Bearer {bearer}"},
    )
    assert resp.status_code == 503, resp.text
    body = resp.json()
    assert body["detail"] == "mastio_unavailable"
    assert body["cullis_meta"]["source"] == "error"
    assert body["cullis_meta"]["error"]
    # Second call must also 503 — the cache write is gated past the
    # fallback branch, so a transient fetch failure doesn't pin the
    # dropdown to "error" for 30s.
    resp2 = client.get(
        "/v1/models",
        headers={"Authorization": f"Bearer {bearer}"},
    )
    assert resp2.status_code == 503, resp2.text


def test_models_live_passes_through_in_shared_mode(
    client, bearer, monkeypatch,
):
    """The 503 only fires when the live fetch yields no models.
    A working Mastio reply still goes through with ``source: live``.
    """
    monkeypatch.setenv("AMBASSADOR_MODE", "shared")
    monkeypatch.setattr(
        FakeCullisClient,
        "list_models",
        lambda self: [
            {"id": "qwen3.5:2b", "object": "model", "owned_by": "ollama",
             "created": 0},
        ],
        raising=False,
    )
    from cullis_connector.ambassador.router import _models_cache

    _models_cache.clear()

    resp = client.get(
        "/v1/models",
        headers={"Authorization": f"Bearer {bearer}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cullis_meta"]["source"] == "live"
    ids = [m["id"] for m in body["data"]]
    assert ids == ["qwen3.5:2b"]


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


# ── ADR-025 bypass for loopback + bearer when user_credentials is bound


def _make_request(*, host: str, headers: dict | None = None, user_creds=None) -> Any:
    """Build a minimal Starlette-compatible Request stand-in for unit
    testing the auth-gate helpers in isolation. Going through
    TestClient's middleware stack would have us racing the real cert
    middleware (which always resets ``user_credentials`` to None
    before our injection can take); the helpers are pure functions of
    request state so a hand-rolled stub is the right scope."""
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/v1/models",
        "headers": [
            (k.lower().encode(), v.encode())
            for k, v in (headers or {}).items()
        ],
        "client": (host, 50000),
        "app": type("_FakeApp", (), {"state": type("_S", (), {"ambassador": {
            "require_local_only": True,
            "bearer_token": "expected-bearer-token",
        }})()})(),
    }
    req = Request(scope)
    req.state.user_credentials = user_creds
    return req


def test_enforce_loopback_blocks_non_loopback_without_user_creds():
    """Baseline: existing single-user laptop contract must hold."""
    from cullis_connector.ambassador.router import _enforce_loopback
    req = _make_request(host="172.20.0.5")
    with pytest.raises(HTTPException) as excinfo:
        _enforce_loopback(req)
    assert excinfo.value.status_code == 403


def test_enforce_loopback_bypasses_when_user_credentials_set():
    """ADR-025: the cookie + cert chain authenticated the user, so the
    loopback check would only block legitimate browser traffic arriving
    via the Frontdesk reverse proxy (172.x docker bridge IP)."""
    from cullis_connector.ambassador.router import _enforce_loopback

    class _Cred:
        principal_id = "acme.test/acme/user/mario"

    req = _make_request(host="172.20.0.5", user_creds=_Cred())
    _enforce_loopback(req)  # must not raise


def test_enforce_bearer_rejects_without_token_and_without_user_creds():
    """Baseline: bearer is still the gate when there's no per-user
    binding (Cursor / LibreChat / laptop SPA single-user mode)."""
    from cullis_connector.ambassador.router import _enforce_bearer

    req = _make_request(host="127.0.0.1")
    state = {"bearer_token": "expected-bearer-token"}
    with pytest.raises(HTTPException) as excinfo:
        _enforce_bearer(req, state)
    assert excinfo.value.status_code == 401


def test_enforce_bearer_bypasses_when_user_credentials_set():
    """ADR-025: the SPA logs in via /api/auth/login (bcrypt) and rides
    the cullis_session cookie thereafter. Forcing the agent-wide bearer
    on top would defeat per-user auth — every employee would need the
    Connector secret."""
    from cullis_connector.ambassador.router import _enforce_bearer

    class _Cred:
        principal_id = "acme.test/acme/user/mario"

    req = _make_request(host="172.20.0.5", user_creds=_Cred())
    state = {"bearer_token": "expected-bearer-token"}
    _enforce_bearer(req, state)  # must not raise


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


# ── ADR-029 Phase D: per-call PDP gate inside the tool-use loop ─────


def _gdpr_chat_responses_with_tool() -> list[dict]:
    """Fixture: LLM emits one tool_call then a final answer."""
    return [
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
                            "arguments": '{"sql": "SELECT 1"}',
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        },
        {
            "choices": [{
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }],
        },
    ]


def test_pdp_off_keeps_legacy_behaviour(client, bearer, monkeypatch):
    """With CULLIS_CONNECTOR_TOOL_PDP_ENABLED unset (default off) the
    loop must not call evaluate_tool_call_policy at all and the tool
    dispatch happens unchanged."""
    monkeypatch.delenv("CULLIS_CONNECTOR_TOOL_PDP_ENABLED", raising=False)
    FakeCullisClient.tools_to_return = [{
        "name": "query",
        "description": "run sql",
        "inputSchema": {"type": "object"},
    }]
    FakeCullisClient.chat_responses = _gdpr_chat_responses_with_tool()

    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "do the thing"}],
        },
    )
    assert resp.status_code == 200
    assert FakeCullisClient.pdp_calls == []          # PDP NOT invoked
    assert len(FakeCullisClient.call_tool_calls) == 1  # tool still ran


def test_pdp_on_allow_executes_tool(client, bearer, monkeypatch):
    """With the flag on and the PDP returning allow, the tool runs
    and the PDP receives tool_name + model in the call kwargs."""
    monkeypatch.setenv("CULLIS_CONNECTOR_TOOL_PDP_ENABLED", "true")
    FakeCullisClient.tools_to_return = [{
        "name": "query",
        "description": "run sql",
        "inputSchema": {"type": "object"},
    }]
    FakeCullisClient.chat_responses = _gdpr_chat_responses_with_tool()
    FakeCullisClient.pdp_responses = [{"allowed": True, "reason": "ok"}]

    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "do the thing"}],
        },
    )
    assert resp.status_code == 200
    assert len(FakeCullisClient.pdp_calls) == 1
    pdp = FakeCullisClient.pdp_calls[0]
    assert pdp["tool_name"] == "query"
    assert pdp["model_id"] == "claude-haiku-4-5"
    assert len(FakeCullisClient.call_tool_calls) == 1


def test_pdp_on_deny_blocks_tool(client, bearer, monkeypatch):
    """When the PDP denies, the SDK call_mcp_tool is NOT invoked and
    the tool message handed back to the LLM carries `policy_denied`."""
    monkeypatch.setenv("CULLIS_CONNECTOR_TOOL_PDP_ENABLED", "true")
    FakeCullisClient.tools_to_return = [{
        "name": "query",
        "description": "run sql",
        "inputSchema": {"type": "object"},
    }]
    final_text = "Sorry, I can't run that tool."
    FakeCullisClient.chat_responses = [
        _gdpr_chat_responses_with_tool()[0],
        {
            "choices": [{
                "message": {"role": "assistant", "content": final_text},
                "finish_reason": "stop",
            }],
        },
    ]
    FakeCullisClient.pdp_responses = [{
        "allowed": False,
        "reason": "principal 'acme::frontdesk' not in tool_rules.query.allowed_principals",
    }]

    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "do the thing"}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == final_text
    # Tool was NOT executed.
    assert FakeCullisClient.call_tool_calls == []
    # The second LLM turn saw a role=tool message tagged policy_denied.
    second_call = FakeCullisClient.chat_calls[1]
    last_message = second_call["messages"][-1]
    assert last_message["role"] == "tool"
    assert "policy_denied" in last_message["content"]


def test_pdp_transport_error_fail_safe_deny(client, bearer, monkeypatch):
    """If evaluate_tool_call_policy raises, the loop treats it as a
    deny rather than running the tool unsupervised."""
    monkeypatch.setenv("CULLIS_CONNECTOR_TOOL_PDP_ENABLED", "true")
    FakeCullisClient.tools_to_return = [{
        "name": "query",
        "description": "run sql",
        "inputSchema": {"type": "object"},
    }]
    FakeCullisClient.chat_responses = [
        _gdpr_chat_responses_with_tool()[0],
        {
            "choices": [{
                "message": {"role": "assistant", "content": "blocked, retry later"},
                "finish_reason": "stop",
            }],
        },
    ]
    FakeCullisClient.pdp_raise = True

    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "do the thing"}],
        },
    )
    assert resp.status_code == 200
    assert FakeCullisClient.call_tool_calls == []
    second_call = FakeCullisClient.chat_calls[1]
    last_message = second_call["messages"][-1]
    assert last_message["role"] == "tool"
    assert "policy_denied" in last_message["content"]


# ────────────────────────────────────────────────────────────────────
# P1 Tier B F2b — streaming tool-use loop opt-in.
# Default OFF: stream=true still walks through ``fake_stream`` (the
# tests above already pin that path). The opt-in flag flips routing
# to ``stream_tool_use_loop`` so the SPA sees real SSE frames including
# named ``tool_call_start`` / ``tool_call_end`` events and a final
# aggregated ``cullis_audit`` summary.
# ────────────────────────────────────────────────────────────────────


def _split_sse_events(body: str) -> list[dict]:
    """Parse the SSE body emitted by ``stream_tool_use_loop`` into a
    list of ``{event, data}`` records. Mirrors the helper used in the
    Mastio side (tests/test_proxy_llm_chat_router.py) and tolerates
    both ``data:``-only frames and named events. ``data: [DONE]`` is
    kept verbatim as a string in ``data`` so callers can assert on
    the terminator."""
    import json as _json
    out: list[dict] = []
    for raw in body.split("\n\n"):
        block = raw.strip()
        if not block:
            continue
        event = "message"
        data_lines: list[str] = []
        for line in block.split("\n"):
            if line.startswith("event:"):
                event = line[len("event:"):].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:"):].lstrip())
        payload = "\n".join(data_lines)
        if payload == "[DONE]":
            out.append({"event": event, "data": "[DONE]"})
        else:
            try:
                out.append({"event": event, "data": _json.loads(payload)})
            except Exception:
                out.append({"event": event, "data": payload})
    return out


def test_streaming_loop_off_by_default_still_uses_fake_stream(client, bearer, monkeypatch):
    """No env flag → router still calls run_tool_use_loop and serializes
    the final answer via fake_stream. stream_chunks is never consumed."""
    monkeypatch.delenv("CULLIS_CONNECTOR_STREAMING_LOOP", raising=False)
    FakeCullisClient.chat_responses = [{
        "choices": [{
            "message": {"role": "assistant", "content": "back-compat answer"},
            "finish_reason": "stop",
        }],
    }]
    FakeCullisClient.stream_chunks = [["WOULD NEVER REACH CLIENT"]]

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
    assert "back-compat answer" in resp.text
    # Streaming surface untouched.
    assert FakeCullisClient.stream_calls == []
    assert "WOULD NEVER REACH CLIENT" not in resp.text


def test_streaming_loop_passes_frames_through_and_emits_audit(
    client, bearer, monkeypatch,
):
    """Env flag on + text-only stream → frames pass through verbatim,
    Mastio per-turn cullis_audit is swallowed, a single aggregated
    cullis_audit + [DONE] is appended at the end."""
    import json as _json
    monkeypatch.setenv("CULLIS_CONNECTOR_STREAMING_LOOP", "true")

    FakeCullisClient.stream_chunks = [[
        "data: " + _json.dumps({
            "choices": [{"index": 0,
                          "delta": {"role": "assistant"},
                          "finish_reason": None}],
        }) + "\n\n",
        "data: " + _json.dumps({
            "choices": [{"index": 0,
                          "delta": {"content": "hello there"},
                          "finish_reason": None}],
        }) + "\n\n",
        "data: " + _json.dumps({
            "choices": [{"index": 0,
                          "delta": {},
                          "finish_reason": "stop"}],
        }) + "\n\n",
        "event: cullis_audit\n"
        "data: " + _json.dumps({
            "trace_id": "trace_abc",
            "latency_ms": 250,
            "tools": [],
        }) + "\n\n",
        "data: [DONE]\n\n",
    ]]

    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "stream": True,
            "messages": [{"role": "user", "content": "ciao"}],
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/event-stream")
    events = _split_sse_events(resp.text)

    # Mastio's per-turn cullis_audit is consumed; the only one the SPA
    # sees is the aggregated one.
    audit_events = [e for e in events if e["event"] == "cullis_audit"]
    assert len(audit_events) == 1
    aud = audit_events[0]["data"]
    assert aud["trace_id"] == "trace_abc"
    assert aud["latency_ms"] == 250
    assert aud["tools"] == []

    # Token content survived the round trip.
    contents = [
        e["data"]["choices"][0]["delta"].get("content")
        for e in events
        if e["event"] == "message" and isinstance(e["data"], dict)
        and e["data"].get("choices")
    ]
    assert "hello there" in contents

    # Connector terminator is the only [DONE] on the wire (Mastio's
    # per-turn DONE was swallowed).
    done_events = [e for e in events if e["data"] == "[DONE]"]
    assert len(done_events) == 1


def test_streaming_loop_executes_tool_calls_and_aggregates_audit(
    client, bearer, monkeypatch,
):
    """A first-turn stream that ends with finish_reason='tool_calls'
    triggers MCP tool execution + a second turn. Final cullis_audit
    sums the tool list across turns and the second turn's text is the
    last content the SPA sees."""
    import json as _json
    monkeypatch.setenv("CULLIS_CONNECTOR_STREAMING_LOOP", "true")

    FakeCullisClient.tools_to_return = [{
        "name": "postgres.query",
        "description": "run sql",
        "inputSchema": {"type": "object"},
    }]
    FakeCullisClient.tool_results = {
        "postgres.query": {"content": [{"type": "text", "text": "42 rows"}]},
    }

    # Turn 1: assistant emits a tool_call block + tool_call_start/end
    # named events (as the Mastio's F1 emit would in real traffic).
    FakeCullisClient.stream_chunks = [
        [
            "event: tool_call_start\n"
            "data: " + _json.dumps({"tool": "postgres.query"}) + "\n\n",
            "data: " + _json.dumps({
                "choices": [{"index": 0, "delta": {"tool_calls": [
                    {"index": 0, "id": "call_x", "type": "function",
                     "function": {"name": "postgres.query",
                                   "arguments": "{\"sql\":\"select 1\"}"}}
                ]}, "finish_reason": None}],
            }) + "\n\n",
            "data: " + _json.dumps({
                "choices": [{"index": 0, "delta": {},
                              "finish_reason": "tool_calls"}],
            }) + "\n\n",
            "event: tool_call_end\n"
            "data: " + _json.dumps({"tool": "postgres.query",
                                     "latency_ms": 120}) + "\n\n",
            "event: cullis_audit\n"
            "data: " + _json.dumps({
                "trace_id": "trace_t1",
                "latency_ms": 200,
                "tools": [{"name": "postgres.query", "latency_ms": 120}],
            }) + "\n\n",
            "data: [DONE]\n\n",
        ],
        # Turn 2: final text answer.
        [
            "data: " + _json.dumps({
                "choices": [{"index": 0,
                              "delta": {"content": "found 42 rows"},
                              "finish_reason": None}],
            }) + "\n\n",
            "data: " + _json.dumps({
                "choices": [{"index": 0, "delta": {},
                              "finish_reason": "stop"}],
            }) + "\n\n",
            "event: cullis_audit\n"
            "data: " + _json.dumps({
                "trace_id": "trace_t2",
                "latency_ms": 150,
                "tools": [],
            }) + "\n\n",
            "data: [DONE]\n\n",
        ],
    ]

    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "stream": True,
            "messages": [{"role": "user", "content": "how many rows?"}],
        },
    )
    assert resp.status_code == 200, resp.text
    events = _split_sse_events(resp.text)

    # Tool was actually executed via the SDK aggregator.
    assert FakeCullisClient.call_tool_calls == [
        ("postgres.query", {"sql": "select 1"}),
    ]

    # Two SDK streaming calls (one per turn). Second turn's messages
    # include the role=tool reply built from the MCP result.
    assert len(FakeCullisClient.stream_calls) == 2
    second_messages = FakeCullisClient.stream_calls[1]["messages"]
    assert second_messages[-1]["role"] == "tool"
    assert "42 rows" in second_messages[-1]["content"]

    # Named events from both turns reach the SPA.
    starts = [e for e in events if e["event"] == "tool_call_start"]
    ends = [e for e in events if e["event"] == "tool_call_end"]
    assert [e["data"]["tool"] for e in starts] == ["postgres.query"]
    assert [e["data"]["tool"] for e in ends] == ["postgres.query"]

    # Single aggregated audit at end, summing both turns.
    audits = [e for e in events if e["event"] == "cullis_audit"]
    assert len(audits) == 1
    aud = audits[0]["data"]
    assert aud["trace_id"] == "trace_t2"  # last trace seen
    assert aud["latency_ms"] == 350       # 200 + 150
    assert aud["tools"] == [{"name": "postgres.query", "latency_ms": 120}]

    # Final answer text reaches the SPA.
    contents = [
        e["data"]["choices"][0]["delta"].get("content")
        for e in events
        if e["event"] == "message" and isinstance(e["data"], dict)
        and e["data"].get("choices")
    ]
    assert "found 42 rows" in contents


def test_streaming_loop_pdp_deny_skips_tool_execution(
    client, bearer, monkeypatch,
):
    """Tool-call PDP denial during streaming bypasses execution and
    feeds a ``policy_denied`` text back as the tool result, exactly
    like the non-streaming loop does."""
    import json as _json
    monkeypatch.setenv("CULLIS_CONNECTOR_STREAMING_LOOP", "true")
    monkeypatch.setenv("CULLIS_CONNECTOR_TOOL_PDP_ENABLED", "true")

    FakeCullisClient.tools_to_return = [{
        "name": "postgres.query", "description": "x",
        "inputSchema": {"type": "object"},
    }]
    FakeCullisClient.pdp_responses = [{
        "allowed": False, "reason": "tool not permitted in this session",
    }]
    FakeCullisClient.stream_chunks = [
        [
            "data: " + _json.dumps({
                "choices": [{"index": 0, "delta": {"tool_calls": [
                    {"index": 0, "id": "call_a", "type": "function",
                     "function": {"name": "postgres.query",
                                   "arguments": "{}"}}
                ]}, "finish_reason": None}],
            }) + "\n\n",
            "data: " + _json.dumps({
                "choices": [{"index": 0, "delta": {},
                              "finish_reason": "tool_calls"}],
            }) + "\n\n",
            "data: [DONE]\n\n",
        ],
        [
            "data: " + _json.dumps({
                "choices": [{"index": 0,
                              "delta": {"content": "cannot do that"},
                              "finish_reason": "stop"}],
            }) + "\n\n",
            "data: [DONE]\n\n",
        ],
    ]

    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "model": "claude-haiku-4-5",
            "stream": True,
            "messages": [{"role": "user", "content": "run the query"}],
        },
    )
    assert resp.status_code == 200, resp.text

    # Tool was NOT executed.
    assert FakeCullisClient.call_tool_calls == []
    # PDP was consulted.
    assert len(FakeCullisClient.pdp_calls) == 1
    # Second turn's last message is the policy_denied stand-in.
    second_messages = FakeCullisClient.stream_calls[1]["messages"]
    assert second_messages[-1]["role"] == "tool"
    assert "policy_denied" in second_messages[-1]["content"]
