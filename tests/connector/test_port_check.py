"""Tests for the port pre-flight + already-running-dashboard probe.

Drives ``cullis_connector._port_check`` against a live socket on a
kernel-chosen port (so the test never collides with a real Connector
running on 7777), and stubs ``httpx.get`` to exercise the dashboard
fingerprint detection.
"""
from __future__ import annotations

import socket
from unittest.mock import patch

import httpx

from cullis_connector._port_check import (
    EXIT_PORT_UNAVAILABLE,
    check_port_available,
    detect_running_dashboard,
)


def _bound_port() -> tuple[int, socket.socket]:
    """Bind a TCP socket to a kernel-chosen free port and keep it
    held — caller closes it when the test is done."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s.getsockname()[1], s


def test_check_port_available_true_when_port_is_free():
    """Sanity baseline — pick a port we know is free (kernel-chosen,
    then released) and confirm the probe says it's free."""
    port, holder = _bound_port()
    holder.close()
    assert check_port_available("127.0.0.1", port) is True


def test_check_port_available_false_when_port_is_busy():
    """Live binding on the port → probe must return False so the CLI
    knows to bail with EX_CONFIG instead of crashing in uvicorn."""
    port, holder = _bound_port()
    try:
        assert check_port_available("127.0.0.1", port) is False
    finally:
        holder.close()


def test_exit_code_is_ex_config_78():
    """Pinning the constant: systemd's ``RestartPreventExitStatus=78``
    in the autostart unit (autostart.py) relies on this exact value."""
    assert EXIT_PORT_UNAVAILABLE == 78


def test_detect_returns_no_response_when_port_silent():
    """Truly free port → nothing answers → ``no_response`` so the CLI
    can give the operator a generic 'check ss -ltnp' suggestion."""
    port, holder = _bound_port()
    holder.close()  # immediately free, nothing listening
    assert detect_running_dashboard("127.0.0.1", port, timeout_s=0.2) == "no_response"


def test_detect_classifies_cullis_connector_response():
    """Stub /api/ping with the dashboard's exact body shape — the
    classifier must see the ``app`` field and report cullis_connector."""
    def _fake_get(url, *, timeout):
        return httpx.Response(
            200, json={"app": "cullis-connector"},
            request=httpx.Request("GET", url),
        )
    with patch("httpx.get", _fake_get):
        kind = detect_running_dashboard("127.0.0.1", 65535)
    assert kind == "cullis_connector"


def test_detect_classifies_unknown_when_response_does_not_match():
    """Something is listening but it's not us (e.g. another tool's
    health endpoint). Operator gets the 'taken by another process'
    message rather than a misleading 'open it in your browser' one."""
    def _fake_get(url, *, timeout):
        return httpx.Response(
            200, json={"hello": "world"},
            request=httpx.Request("GET", url),
        )
    with patch("httpx.get", _fake_get):
        kind = detect_running_dashboard("127.0.0.1", 65535)
    assert kind == "unknown"


def test_detect_handles_non_200_without_raising():
    """A 404 (or 503, or anything non-200) at /api/ping → classifier
    treats it as ``unknown``, never raises."""
    def _fake_get(url, *, timeout):
        return httpx.Response(
            404, text="not found", request=httpx.Request("GET", url),
        )
    with patch("httpx.get", _fake_get):
        kind = detect_running_dashboard("127.0.0.1", 65535)
    assert kind == "unknown"


def test_detect_swallows_connection_errors():
    """A connect-refused or DNS error during probing must NOT bubble —
    the probe is best-effort and the caller uses the result for
    diagnostics, not control flow."""
    def _fake_get(url, *, timeout):
        raise httpx.ConnectError("connection refused")
    with patch("httpx.get", _fake_get):
        kind = detect_running_dashboard("127.0.0.1", 65535)
    assert kind == "no_response"


def test_cli_dashboard_exits_78_when_port_busy(tmp_path):
    """Integration: ``_cmd_dashboard`` must short-circuit with
    ``EXIT_PORT_UNAVAILABLE`` *before* uvicorn imports its loop.
    Otherwise the systemd unit's ``Restart=on-failure`` would
    crash-loop again on this exact case.
    """
    import argparse

    from cullis_connector.cli import _cmd_dashboard
    from cullis_connector.config import ConnectorConfig

    cfg = ConnectorConfig(config_dir=tmp_path)
    port, holder = _bound_port()
    try:
        args = argparse.Namespace(
            web_host="127.0.0.1",
            web_port=port,
            open_browser=False,
        )
        rc = _cmd_dashboard(cfg, args)
    finally:
        holder.close()
    assert rc == EXIT_PORT_UNAVAILABLE
