"""ADR-007 Phase 1 PR #4 — SPIFFE 3-component parser for MCP resources.

Covers the new ``parse_resource_spiffe``, ``is_resource_spiffe``, and
``build_resource_spiffe`` helpers plus the regression guard that the
existing 2-component ``parse_spiffe`` refuses 3-component input (so the
ADR-006 routing decision can't accidentally consume a resource URI).
"""
from __future__ import annotations

import pytest

from mcp_proxy.spiffe import (
    InvalidRecipient,
    build_resource_spiffe,
    is_resource_spiffe,
    parse_recipient,
    parse_resource_spiffe,
    parse_spiffe,
)


# ── Happy path ──────────────────────────────────────────────────────

def test_parse_resource_spiffe_happy_path():
    td, org, rtype, rname = parse_resource_spiffe(
        "spiffe://cullis.test/acme/mcp/postgres-prod"
    )
    assert td == "cullis.test"
    assert org == "acme"
    assert rtype == "mcp"
    assert rname == "postgres-prod"


def test_parse_resource_spiffe_accepts_mixed_case_resource_name():
    td, org, rtype, rname = parse_resource_spiffe(
        "spiffe://cullis.test/acme/mcp/Postgres_Prod-01"
    )
    assert rname == "Postgres_Prod-01"


def test_is_resource_spiffe_true_for_valid_resource_uri():
    assert is_resource_spiffe("spiffe://cullis.test/acme/mcp/svc") is True


def test_is_resource_spiffe_false_for_agent_uri():
    assert is_resource_spiffe("spiffe://cullis.test/acme/buyer") is False


def test_is_resource_spiffe_false_for_garbage():
    assert is_resource_spiffe("not-a-spiffe-id") is False
    assert is_resource_spiffe("") is False


# ── Build round-trip ────────────────────────────────────────────────

def test_build_resource_spiffe_round_trip():
    uri = build_resource_spiffe("cullis.test", "acme", "echo")
    assert uri == "spiffe://cullis.test/acme/mcp/echo"
    td, org, rtype, rname = parse_resource_spiffe(uri)
    assert (td, org, rtype, rname) == ("cullis.test", "acme", "mcp", "echo")


def test_build_resource_spiffe_default_resource_type_is_mcp():
    uri = build_resource_spiffe("example.org", "o", "r")
    assert "/mcp/" in uri


def test_build_resource_spiffe_rejects_invalid_trust_domain():
    with pytest.raises(InvalidRecipient, match="trust domain"):
        build_resource_spiffe("UPPERCASE-TLD", "acme", "x")


def test_build_resource_spiffe_rejects_unknown_resource_type():
    with pytest.raises(InvalidRecipient, match="unknown resource_type"):
        build_resource_spiffe("cullis.test", "acme", "x", resource_type="llm")


def test_build_resource_spiffe_rejects_empty_org():
    with pytest.raises(InvalidRecipient, match="org"):
        build_resource_spiffe("cullis.test", "", "x")


def test_build_resource_spiffe_rejects_invalid_resource_name():
    with pytest.raises(InvalidRecipient, match="resource_name"):
        build_resource_spiffe("cullis.test", "acme", "bad name!")


# ── Parse rejection paths ───────────────────────────────────────────

def test_parse_resource_spiffe_rejects_non_spiffe_scheme():
    with pytest.raises(InvalidRecipient, match="not a SPIFFE URI"):
        parse_resource_spiffe("https://cullis.test/acme/mcp/x")


def test_parse_resource_spiffe_rejects_missing_trust_domain():
    with pytest.raises(InvalidRecipient, match="trust domain"):
        parse_resource_spiffe("spiffe:///acme/mcp/x")


def test_parse_resource_spiffe_rejects_two_components():
    with pytest.raises(InvalidRecipient, match="3 components"):
        parse_resource_spiffe("spiffe://cullis.test/acme/buyer")


def test_parse_resource_spiffe_rejects_four_components():
    with pytest.raises(InvalidRecipient, match="3 components"):
        parse_resource_spiffe("spiffe://cullis.test/acme/mcp/svc/extra")


def test_parse_resource_spiffe_rejects_unknown_resource_type():
    with pytest.raises(InvalidRecipient, match="unknown resource_type"):
        parse_resource_spiffe("spiffe://cullis.test/acme/llm/foo")


def test_parse_resource_spiffe_rejects_query_or_fragment():
    with pytest.raises(InvalidRecipient, match="query or fragment"):
        parse_resource_spiffe("spiffe://cullis.test/acme/mcp/x?debug=1")
    with pytest.raises(InvalidRecipient, match="query or fragment"):
        parse_resource_spiffe("spiffe://cullis.test/acme/mcp/x#frag")


# ── ADR-006 regression guard ────────────────────────────────────────

def test_parse_spiffe_still_rejects_3_component_input():
    """``parse_spiffe`` MUST stay strict at 2 components.

    ADR-006 routing uses this parser for agent IDs; allowing it to
    accept 3-component URIs would cause a resource SPIFFE to be
    silently treated as an agent destination and route to the broker
    bridge by mistake.
    """
    with pytest.raises(InvalidRecipient, match="2 components"):
        parse_spiffe("spiffe://cullis.test/acme/mcp/svc")


def test_parse_recipient_still_rejects_3_component_input():
    """``parse_recipient`` should reject resource URIs too.

    It dispatches to ``parse_spiffe`` for SPIFFE inputs, so the same
    invariant holds. Guarantees egress routing code that calls
    ``parse_recipient`` never confuses a resource for an agent.
    """
    with pytest.raises(InvalidRecipient, match="2 components"):
        parse_recipient("spiffe://cullis.test/acme/mcp/svc")


def test_parse_spiffe_still_parses_agent_id():
    """Positive control — existing 2-component parsing untouched."""
    td, org, agent = parse_spiffe("spiffe://cullis.test/acme/buyer")
    assert (td, org, agent) == ("cullis.test", "acme", "buyer")
