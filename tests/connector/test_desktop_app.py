"""Unit tests for the M3.1 desktop shell.

We can't actually spin up a GUI from CI — pywebview / pystray need a
display and platform backends — so the tests cover:

* The tray glyph renders at the expected sizes (Pillow only, no GUI).
* The argument parser recognizes the `desktop` subcommand.
* `run_desktop_app` returns 2 with a useful log when any of the
  optional deps (webview / pystray / Pillow) is missing.
"""
from __future__ import annotations

import builtins
import logging

import pytest

PIL = pytest.importorskip("PIL.Image")


def test_build_tray_image_produces_rgba_at_requested_size():
    from cullis_connector.desktop_app import _build_tray_image

    img = _build_tray_image(64)
    assert img.size == (64, 64)
    assert img.mode == "RGBA"


def test_build_tray_image_scales_cleanly():
    from cullis_connector.desktop_app import _build_tray_image

    small = _build_tray_image(16)
    big = _build_tray_image(128)
    assert small.size == (16, 16)
    assert big.size == (128, 128)


def test_build_tray_image_paints_with_accent_color():
    from cullis_connector.desktop_app import _ACCENT, _build_tray_image

    img = _build_tray_image(64)
    # The top header bar spans roughly y=6..10 at 64px — sample inside it.
    pixel = img.getpixel((32, 8))
    assert pixel == _ACCENT


def test_cli_parser_knows_desktop_subcommand():
    from cullis_connector.cli import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["desktop", "--port", "7788"])
    assert args.command == "desktop"
    assert args.web_port == 7788
    assert args.web_host == "127.0.0.1"


def test_run_desktop_app_returns_2_when_webview_missing(monkeypatch, caplog):
    """Simulate a wheel installed without the `desktop` extra. We
    expect an ImportError funneled into a return code of 2 plus a
    human-readable log line pointing at the correct install command."""
    original_import = builtins.__import__

    def _blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "webview" or name.startswith("webview."):
            raise ImportError(name="webview")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    from cullis_connector.desktop_app import run_desktop_app

    with caplog.at_level(logging.ERROR, logger="cullis_connector.desktop_app"):
        rc = run_desktop_app(cfg=object())

    assert rc == 2
    assert any(
        "cullis-connector[dashboard,desktop]" in rec.message for rec in caplog.records
    )


def test_run_desktop_app_returns_2_when_pystray_missing(monkeypatch, caplog):
    original_import = builtins.__import__

    def _blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pystray" or name.startswith("pystray."):
            raise ImportError(name="pystray")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    from cullis_connector.desktop_app import run_desktop_app

    with caplog.at_level(logging.ERROR, logger="cullis_connector.desktop_app"):
        rc = run_desktop_app(cfg=object())

    assert rc == 2
    assert any("missing: pystray" in rec.message for rec in caplog.records)
