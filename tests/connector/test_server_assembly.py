"""Smoke test: build_server wires every tool group and stores config in state."""
from __future__ import annotations

from pathlib import Path

import pytest

from cullis_connector.config import ConnectorConfig
from cullis_connector.server import build_server
from cullis_connector.state import get_state, reset_state


@pytest.fixture(autouse=True)
def _isolate_state():
    reset_state()
    yield
    reset_state()


def test_build_server_registers_tools_and_sets_state(tmp_path: Path):
    cfg = ConnectorConfig(
        site_url="https://site.test",
        config_dir=tmp_path,
    )
    mcp = build_server(cfg)

    assert get_state().config is cfg
    assert mcp.name == "Cullis"
    # FastMCP exposes registered tools via the underlying tool manager.
    tool_names = {t.name for t in mcp._tool_manager.list_tools()}
    expected = {
        "hello_site",
        "discover_agents",
        "open_session",
        "send_message",
        "check_responses",
        "list_pending_sessions",
        "accept_session",
        "close_session",
        "list_sessions",
        "select_session",
    }
    # Legacy `connect` tool removed in Phase 2b — identity now loaded from
    # ~/.cullis/identity/ populated by `cullis-connector enroll`.
    assert "connect" not in tool_names
    missing = expected - tool_names
    assert not missing, f"Missing tools: {missing}"
