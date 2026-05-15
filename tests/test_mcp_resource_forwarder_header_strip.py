"""H3 P0.4 — explicit Authorization / Cookie strip at upstream forwarder.

Closes the gap surfaced by the 2026-05-15 threat-model verification
pass: the MCP-proxy Tampering row claimed ``mcp_proxy/tools/`` strips
``Authorization`` / ``Cookie`` headers from the upstream request, but
no explicit strip code existed. The previous behaviour was secure by
construction (the forwarder built ``request_headers`` from a fixed
set of server-known fields, never propagating client headers), but
defence-in-depth requires an explicit deny-list so a future refactor
cannot regress silently.

This file locks in:

- :func:`_strip_dangerous_upstream_headers` drops every name in the
  deny-list (case-insensitive).
- The deny-list covers the bearer-style auth headers
  (``Authorization``, ``X-API-Key``), the cookie axis
  (``Cookie``, ``Set-Cookie``), and the internal trust headers that a
  vulnerable upstream might mistake for an authority signal
  (``X-Cullis-Agent-Id``, ``X-Cullis-Org-Id``, ``X-Cullis-Admin``,
  ``X-Forwarded-User``, ``X-Forwarded-Email``, etc.).
- Innocent headers (``Accept``, ``Content-Type``, ``User-Agent``) are
  preserved.
"""
from __future__ import annotations

import pytest

from mcp_proxy.tools.mcp_resource_forwarder import (
    _DANGEROUS_UPSTREAM_HEADERS,
    _strip_dangerous_upstream_headers,
)


@pytest.mark.parametrize(
    "header_name",
    [
        "Authorization",
        "authorization",
        "AUTHORIZATION",
        "Cookie",
        "cookie",
        "Set-Cookie",
        "X-API-Key",
        "x-api-key",
        "X-Cullis-Agent-Id",
        "X-Cullis-Org-Id",
        "X-Cullis-Admin",
        "X-Cullis-Mastio-Signature",
        "X-Forwarded-User",
        "X-Forwarded-Email",
        "X-Original-Authorization",
        "Proxy-Authorization",
    ],
)
def test_strip_removes_dangerous_header(header_name: str) -> None:
    """Every entry in the deny-list must be removed regardless of case."""
    out = _strip_dangerous_upstream_headers({header_name: "secret", "Accept": "ok"})
    # The dangerous one is gone; the innocent one stays.
    assert header_name not in out
    assert header_name.lower() not in {k.lower() for k in out}
    assert out.get("Accept") == "ok"


def test_strip_preserves_innocent_headers() -> None:
    """Innocent headers must pass through untouched."""
    payload = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "cullis-mastio/0.4",
        "Accept-Language": "en",
    }
    out = _strip_dangerous_upstream_headers(payload)
    assert out == payload


def test_strip_does_not_mutate_input() -> None:
    """The helper returns a new dict; the input is not mutated."""
    payload = {"Authorization": "Bearer secret", "Accept": "ok"}
    out = _strip_dangerous_upstream_headers(payload)
    assert payload == {"Authorization": "Bearer secret", "Accept": "ok"}
    assert "Authorization" not in out


def test_server_auth_header_wins_over_strip() -> None:
    """Critical merge-order test: the per-tool ``auth_header`` (server-built
    from the registry credential) lands AFTER the strip, so it cannot be
    eaten by the deny-list even though its shape overlaps
    (``Authorization`` / ``X-API-Key``).

    Mirrors the forward_to_mcp_resource composition exactly so a future
    refactor that swaps the merge order trips this test."""
    client_headers = {
        "Authorization": "Bearer hostile-client-token",
        "X-API-Key": "hostile-client-key",
        "Cookie": "session=ghost",
    }
    server_auth = {"Authorization": "Bearer tool-registry-token"}

    sanitised_client = _strip_dangerous_upstream_headers(client_headers)
    final = {"Accept": "application/json", **sanitised_client, **server_auth}

    # The hostile client headers are gone.
    assert "Cookie" not in final
    # The server-built auth header survives and is the one that wins.
    assert final["Authorization"] == "Bearer tool-registry-token"
    # X-API-Key, which only appeared on the client side, is stripped.
    assert "X-API-Key" not in final
    # The innocent header remains.
    assert final["Accept"] == "application/json"


def test_server_apikey_header_wins_over_strip() -> None:
    """As above but with ``X-API-Key`` as the server-built auth header."""
    client_headers = {
        "Authorization": "Bearer hostile-client-token",
        "X-API-Key": "hostile-client-key",
    }
    server_auth = {"X-API-Key": "tool-registry-key"}

    sanitised_client = _strip_dangerous_upstream_headers(client_headers)
    final = {"Accept": "application/json", **sanitised_client, **server_auth}

    assert final["X-API-Key"] == "tool-registry-key"
    assert "Authorization" not in final


def test_deny_list_includes_every_trust_axis() -> None:
    """Regression guard: the deny-list MUST cover the three classes of
    headers the threat model commits to stripping. If a future refactor
    accidentally drops one of these the test fails loudly."""
    required = {
        # Bearer-style auth
        "authorization",
        "x-api-key",
        # Cookie axis
        "cookie",
        "set-cookie",
        # Internal trust headers that upstream might honour
        "x-cullis-agent-id",
        "x-cullis-org-id",
        "x-cullis-admin",
        "x-forwarded-user",
    }
    missing = required - _DANGEROUS_UPSTREAM_HEADERS
    assert missing == set(), (
        f"deny-list is missing the following names that the threat-model "
        f"commits to stripping: {sorted(missing)}"
    )
