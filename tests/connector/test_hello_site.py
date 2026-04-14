"""Tests for the hello_site diagnostic tool."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from cullis_connector.config import ConnectorConfig
from cullis_connector.state import get_state, reset_state
from cullis_connector.tools import diagnostic


class _FakeFastMCP:
    """Minimal stub capturing tool registrations without a real MCP runtime."""

    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path):
    reset_state()
    get_state().config = ConnectorConfig(
        site_url="https://site.test",
        config_dir=tmp_path,
        verify_tls=True,
        request_timeout_s=2.0,
    )
    yield
    reset_state()


@pytest.fixture
def hello_site_tool():
    mcp = _FakeFastMCP()
    diagnostic.register(mcp)
    return mcp.tools["hello_site"]


def test_hello_site_returns_error_when_url_missing(hello_site_tool):
    get_state().config = ConnectorConfig(site_url="")
    result = hello_site_tool()
    assert "not configured" in result.lower()


def test_hello_site_parses_healthy_response(hello_site_tool, monkeypatch):
    captured: dict[str, object] = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return httpx.Response(
            status_code=200,
            json={"status": "ok", "version": "0.9.9"},
        )

    monkeypatch.setattr(diagnostic.httpx, "get", fake_get)
    result = hello_site_tool()
    parsed = json.loads(result)
    assert parsed["site_status"] == "ok"
    assert parsed["site_version"] == "0.9.9"
    assert parsed["site_url"] == "https://site.test"
    assert parsed["tls_verified"] is True
    assert "latency_ms" in parsed
    assert captured["url"] == "https://site.test/health"


def test_hello_site_reports_non_200(hello_site_tool, monkeypatch):
    monkeypatch.setattr(
        diagnostic.httpx,
        "get",
        lambda url, **kw: httpx.Response(status_code=503, text="degraded"),
    )
    result = hello_site_tool()
    assert "HTTP 503" in result
    assert "degraded" in result


def test_hello_site_reports_network_failure(hello_site_tool, monkeypatch):
    def boom(url, **kw):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(diagnostic.httpx, "get", boom)
    result = hello_site_tool()
    assert "unreachable" in result.lower()
    assert "connection refused" in result


def test_hello_site_handles_non_json_response(hello_site_tool, monkeypatch):
    monkeypatch.setattr(
        diagnostic.httpx,
        "get",
        lambda url, **kw: httpx.Response(status_code=200, text="OK"),
    )
    result = hello_site_tool()
    parsed = json.loads(result)
    assert parsed["site_status"] == "unknown"
