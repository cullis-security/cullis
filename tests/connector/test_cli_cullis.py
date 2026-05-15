"""Tests for the ``cullis`` thin CLI alias.

Targets ``cullis_connector.cli.cullis_main`` and its three subcommands
(``send`` / ``inbox`` / ``health``). The CLI is intentionally a thin
HTTP wrapper around the local Ambassador, so every test mocks
``httpx.Client`` via ``httpx.MockTransport`` and asserts the wire
contract (URL, headers, JSON body) plus the user-facing exit code +
stdout/stderr behaviour. No real Connector daemon is booted.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from cullis_connector.cli import (
    _CullisCLIError,
    _cullis_build_parser,
    _get_bearer_token,
    _http_request,
    _resolve_token_path,
    cullis_main,
)


_TOKEN = "a" * 64


@pytest.fixture()
def token_file(tmp_path: Path) -> Path:
    """Write a fake loopback bearer token to a per-test path."""
    p = tmp_path / "local.token"
    p.write_text(_TOKEN + "\n", encoding="utf-8")
    return p


class _PatchedHttpx:
    """Test helper bundling captured requests + the canned response queue.

    A subclass of ``object`` (not ``list``) so tests can attach attributes
    — Python's builtin ``list`` rejects arbitrary attrs and we want both
    the request log and the response queue on one fixture.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responses: list[httpx.Response] = []

    def __len__(self) -> int:
        return len(self.requests)

    def __getitem__(self, index: int) -> httpx.Request:
        return self.requests[index]

    def __bool__(self) -> bool:
        return bool(self.requests)


@pytest.fixture()
def patched_httpx(monkeypatch: pytest.MonkeyPatch) -> _PatchedHttpx:
    """Replace ``httpx.Client(timeout=...)`` with a MockTransport-backed
    client. Tests append ``httpx.Response`` rows to ``.responses`` before
    triggering the CLI, then inspect ``.requests`` afterwards.
    """
    state = _PatchedHttpx()

    def _handler(req: httpx.Request) -> httpx.Response:
        state.requests.append(req)
        if not state.responses:
            return httpx.Response(500, json={"detail": "no canned response"})
        return state.responses.pop(0)

    transport = httpx.MockTransport(_handler)
    real_client_cls = httpx.Client

    def _factory(*args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs.setdefault("transport", transport)
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr("httpx.Client", _factory)
    return state


def _stub_args(token_path: Path, connector_url: str = "http://127.0.0.1:7777"):
    """Lightweight argparse Namespace stand-in for the helper tests."""
    import argparse
    return argparse.Namespace(
        token_file=str(token_path),
        connector_url=connector_url,
        profile=None,
        config_dir=None,
    )


# ── parser ─────────────────────────────────────────────────────────────


def test_parser_accepts_three_subcommands() -> None:
    parser = _cullis_build_parser()
    for cmd in ("send", "inbox", "health"):
        # ``health`` has no required args, the other two do — invoke
        # ``--help`` on each to confirm the subparser exists without
        # caring about which flags trip required-arg validation here.
        with pytest.raises(SystemExit) as exc:
            parser.parse_args([cmd, "--help"])
        assert exc.value.code == 0


def test_send_requires_content_or_payload_json() -> None:
    parser = _cullis_build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["send", "--to", "orga::a"])
    # argparse exits 2 on a parse error.
    assert exc.value.code == 2


def test_send_content_and_payload_json_are_mutually_exclusive() -> None:
    parser = _cullis_build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args([
            "send", "--to", "orga::a",
            "--content", "hi",
            "--payload-json", "{}",
        ])
    assert exc.value.code == 2


def test_inbox_format_validated() -> None:
    parser = _cullis_build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["inbox", "--format", "yaml"])


def test_shared_flags_apply_to_every_subcommand() -> None:
    parser = _cullis_build_parser()
    for cmd_args in (
        ["health"],
        ["inbox", "--limit", "1"],
        ["send", "--to", "x", "--content", "hi"],
    ):
        ns = parser.parse_args([
            "--connector-url", "http://localhost:9999",
            "--token-file", "/tmp/test.token",
            "--profile", "demo",
            *cmd_args,
        ])
        assert ns.connector_url == "http://localhost:9999"
        assert ns.token_file == "/tmp/test.token"
        assert ns.profile == "demo"


# ── token resolution ───────────────────────────────────────────────────


def test_get_bearer_token_reads_explicit_file(token_file: Path) -> None:
    args = _stub_args(token_file)
    assert _get_bearer_token(args) == _TOKEN


def test_get_bearer_token_strips_trailing_whitespace(tmp_path: Path) -> None:
    p = tmp_path / "local.token"
    p.write_text(f"  {_TOKEN}\n\n", encoding="utf-8")
    args = _stub_args(p)
    assert _get_bearer_token(args) == _TOKEN


def test_get_bearer_token_missing_file_prints_actionable_message(
    tmp_path: Path,
) -> None:
    args = _stub_args(tmp_path / "does-not-exist.token")
    with pytest.raises(_CullisCLIError) as exc:
        _get_bearer_token(args)
    msg = str(exc.value)
    # The user must learn (1) where we looked and (2) what to run next.
    assert "does-not-exist.token" in msg
    assert "cullis-connector" in msg


def test_get_bearer_token_empty_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "local.token"
    p.write_text("", encoding="utf-8")
    args = _stub_args(p)
    with pytest.raises(_CullisCLIError) as exc:
        _get_bearer_token(args)
    assert "empty" in str(exc.value).lower()


def test_resolve_token_path_honours_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    env_path = tmp_path / "env.token"
    monkeypatch.setenv("CULLIS_BEARER_TOKEN_FILE", str(env_path))
    import argparse
    args = argparse.Namespace(
        token_file=None, connector_url="x", profile=None, config_dir=None,
    )
    assert _resolve_token_path(args) == env_path


# ── _http_request wire contract ────────────────────────────────────────


def test_http_request_sends_bearer_header(
    token_file: Path, patched_httpx: _PatchedHttpx,
) -> None:
    patched_httpx.responses.append(
        httpx.Response(200, json={"status": "ok"})
    )
    args = _stub_args(token_file)
    body = _http_request(args, "GET", "/v1/ambassador/health")
    assert body == {"status": "ok"}
    sent = patched_httpx[0]
    assert sent.headers.get("authorization") == f"Bearer {_TOKEN}"
    assert sent.method == "GET"
    assert str(sent.url) == "http://127.0.0.1:7777/v1/ambassador/health"


def test_http_request_raises_on_4xx_with_detail(
    token_file: Path, patched_httpx: _PatchedHttpx,
) -> None:
    patched_httpx.responses.append(
        httpx.Response(400, json={"detail": "recipient_id is required"})
    )
    args = _stub_args(token_file)
    with pytest.raises(_CullisCLIError) as exc:
        _http_request(args, "POST", "/v1/inbox/send", json_body={})
    assert "400" in str(exc.value)
    assert "recipient_id is required" in str(exc.value)


def test_http_request_raises_on_connect_error(
    token_file: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _explode(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=req)

    transport = httpx.MockTransport(_explode)
    real_cls = httpx.Client
    monkeypatch.setattr(
        "httpx.Client",
        lambda *a, **k: real_cls(*a, **{**k, "transport": transport}),
    )

    args = _stub_args(token_file)
    with pytest.raises(_CullisCLIError) as exc:
        _http_request(args, "GET", "/v1/ambassador/health")
    assert "Cannot reach" in str(exc.value)
    assert "cullis-connector" in str(exc.value)


# ── end-to-end subcommand smoke ────────────────────────────────────────


def _run_cli(
    argv: list[str],
    token_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str, str]:
    rc = cullis_main([
        "--connector-url", "http://127.0.0.1:7777",
        "--token-file", str(token_file),
        *argv,
    ])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_cullis_health_happy_path(
    token_file: Path,
    patched_httpx: _PatchedHttpx,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patched_httpx.responses.append(
        httpx.Response(200, json={
            "status": "ok",
            "agent_id": "orga::ambassador",
            "site_url": "https://mastio.local:9443",
        })
    )
    rc, out, err = _run_cli(["health"], token_file, capsys)
    assert rc == 0, err
    assert "Cullis Connector OK" in out
    assert "orga::ambassador" in out
    assert "https://mastio.local:9443" in out


def test_cullis_health_daemon_down_friendly_error(
    token_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def _explode(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=req)

    transport = httpx.MockTransport(_explode)
    real_cls = httpx.Client
    monkeypatch.setattr(
        "httpx.Client",
        lambda *a, **k: real_cls(*a, **{**k, "transport": transport}),
    )
    rc, out, err = _run_cli(["health"], token_file, capsys)
    assert rc == 1
    assert "Cannot reach Cullis Connector" in err


def test_cullis_send_content_wraps_as_text_payload(
    token_file: Path,
    patched_httpx: _PatchedHttpx,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patched_httpx.responses.append(
        httpx.Response(200, json={"msg_id": "msg_123", "status": "accepted"})
    )
    rc, out, err = _run_cli(
        ["send", "--to", "orga::alice", "--content", "ciao"],
        token_file, capsys,
    )
    assert rc == 0, err
    sent = patched_httpx[0]
    assert sent.method == "POST"
    assert sent.url.path == "/v1/inbox/send"
    body = json.loads(sent.content.decode())
    assert body["recipient_id"] == "orga::alice"
    assert body["payload"] == {"text": "ciao"}
    assert body["ttl_seconds"] == 300
    # The response is rendered to stdout as pretty JSON.
    parsed = json.loads(out)
    assert parsed["msg_id"] == "msg_123"


def test_cullis_send_payload_json_passthrough(
    token_file: Path,
    patched_httpx: _PatchedHttpx,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patched_httpx.responses.append(
        httpx.Response(200, json={"status": "accepted"})
    )
    rc, out, err = _run_cli(
        [
            "send", "--to", "orga::bob",
            "--payload-json", '{"intent": "ping", "value": 7}',
            "--correlation-id", "corr-9",
            "--reply-to", "msg_prev",
            "--ttl", "60",
        ],
        token_file, capsys,
    )
    assert rc == 0, err
    sent_body = json.loads(patched_httpx[0].content.decode())
    assert sent_body["payload"] == {"intent": "ping", "value": 7}
    assert sent_body["correlation_id"] == "corr-9"
    assert sent_body["reply_to"] == "msg_prev"
    assert sent_body["ttl_seconds"] == 60


def test_cullis_send_payload_json_rejects_non_object(
    token_file: Path,
    patched_httpx: _PatchedHttpx,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, out, err = _run_cli(
        [
            "send", "--to", "orga::bob",
            "--payload-json", '"just a string"',
        ],
        token_file, capsys,
    )
    assert rc == 1
    assert "must decode to a JSON object" in err
    # No HTTP call should have been made.
    assert not patched_httpx


def test_cullis_send_payload_json_rejects_invalid_json(
    token_file: Path,
    patched_httpx: _PatchedHttpx,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, out, err = _run_cli(
        ["send", "--to", "orga::bob", "--payload-json", "{not-json}"],
        token_file, capsys,
    )
    assert rc == 1
    assert "not valid JSON" in err
    assert not patched_httpx


def test_cullis_inbox_text_format_renders_compact_table(
    token_file: Path,
    patched_httpx: _PatchedHttpx,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patched_httpx.responses.append(
        httpx.Response(200, json={
            "messages": [
                {
                    "msg_id": "msg_1",
                    "sender_id": "orga::alice",
                    "payload": {"text": "hi there"},
                },
                {
                    "msg_id": "msg_2",
                    "sender_agent_id": "orga::bob",
                    "payload": {"text": "x" * 200},
                },
            ],
        })
    )
    rc, out, err = _run_cli(
        ["inbox", "--limit", "5", "--since", "msg_0"],
        token_file, capsys,
    )
    assert rc == 0, err
    sent = patched_httpx[0]
    assert sent.url.path == "/v1/inbox"
    assert dict(sent.url.params) == {"limit": "5", "since": "msg_0"}
    assert "MSG_ID" in out
    assert "msg_1" in out
    assert "orga::alice" in out
    assert "hi there" in out
    # Long payload should be elided.
    assert "..." in out


def test_cullis_inbox_empty(
    token_file: Path,
    patched_httpx: _PatchedHttpx,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patched_httpx.responses.append(
        httpx.Response(200, json={"messages": []})
    )
    rc, out, err = _run_cli(["inbox"], token_file, capsys)
    assert rc == 0
    assert "(inbox empty)" in out


def test_cullis_inbox_json_format_dumps_raw(
    token_file: Path,
    patched_httpx: _PatchedHttpx,
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw = {"messages": [{"msg_id": "msg_1", "payload": {"text": "hi"}}]}
    patched_httpx.responses.append(
        httpx.Response(200, json=raw)
    )
    rc, out, err = _run_cli(["inbox", "--format", "json"], token_file, capsys)
    assert rc == 0
    assert json.loads(out) == raw


def test_cullis_send_propagates_server_error(
    token_file: Path,
    patched_httpx: _PatchedHttpx,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patched_httpx.responses.append(
        httpx.Response(502, json={"detail": "Mastio unreachable"})
    )
    rc, out, err = _run_cli(
        ["send", "--to", "orga::alice", "--content", "hi"],
        token_file, capsys,
    )
    assert rc == 1
    assert "502" in err
    assert "Mastio unreachable" in err
