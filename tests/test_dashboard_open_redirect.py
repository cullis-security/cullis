"""Tests for H-IO-1: open redirect via protocol-relative next_url.

Verifies that _safe_redirect() in app.dashboard.router rejects any
caller-supplied value that could cause a cross-origin bounce, while
passing through legitimate same-origin paths.
"""
import pytest

from app.dashboard.router import _safe_redirect


_FALLBACK = "/dashboard/orgs"


@pytest.mark.parametrize("bad_input", [
    # Protocol-relative URLs — the primary H-IO-1 vector
    "//evil.example/steal",
    "//evil.example",
    "//",
    # Backslash-relative (IE/Edge historic bypass)
    "/\\evil.example/x",
    "/\\ evil",
    # Absolute URLs
    "https://evil.example/x",
    "http://evil.example/",
    "ftp://evil.example/",
    # Scheme-less but with authority embedded after double slash
    "///triple",
    # Empty / whitespace
    "",
    "   ",
    # Non-string types
    None,
    42,
    ["list"],
    # Relative paths without leading slash
    "evil.example/x",
    "relative/path",
])
def test_safe_redirect_rejects_bad_inputs(bad_input):
    result = _safe_redirect(bad_input, fallback=_FALLBACK)
    assert result == _FALLBACK, (
        f"Expected fallback for {bad_input!r}, got {result!r}"
    )


@pytest.mark.parametrize("good_input", [
    "/dashboard/orgs",
    "/dashboard",
    "/dashboard/orgs/abc-123",
    "/dashboard/orgs?foo=bar",
    "/dashboard/orgs?foo=bar&baz=1",
    "/dashboard/orgs#section",
    "/dashboard/orgs/abc%20encoded",
    "/dashboard/login?next=%2Fdashboard%2Forgs",
])
def test_safe_redirect_allows_local_paths(good_input):
    result = _safe_redirect(good_input, fallback=_FALLBACK)
    assert result == good_input, (
        f"Expected {good_input!r} to pass through, got {result!r}"
    )


def test_safe_redirect_default_fallback():
    """When no fallback is given the module default (/dashboard) is used."""
    result = _safe_redirect("//evil.example")
    assert result == "/dashboard"


def test_safe_redirect_none_with_custom_fallback():
    result = _safe_redirect(None, fallback="/dashboard/orgs")
    assert result == "/dashboard/orgs"
