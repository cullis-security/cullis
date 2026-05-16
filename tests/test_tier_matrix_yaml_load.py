"""ADR-032 Decision E / F5 — capability-tiers.yaml loader.

Pins the YAML contract + the fallback semantics so a future schema
bump or a missing file never silently flips the gate from "enforce"
to "no-op" without a red test.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcp_proxy.policy.tier_matrix import (
    DEFAULT_MATRIX_PATH,
    TIER_ORDER,
    load_default_tier_matrix,
    load_tier_matrix,
    tier_meets_requirement,
)


def _yaml(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "tiers.yaml"
    p.write_text(body)
    return p


# ── happy path ────────────────────────────────────────────────────────


def test_load_bundled_default_yaml_parses_cleanly():
    """The repo-bundled default YAML must always parse — it ships with
    every Mastio container."""
    matrix = load_tier_matrix(DEFAULT_MATRIX_PATH)
    assert matrix.version == "1.0"
    assert matrix.default_min_tier == "untrusted"
    assert "mcp.transfer_money" in matrix.by_exact
    # admin.* wildcard lands in the prefix table, not the exact table.
    assert all(p[0] != "admin." or p[1] == "managed_attested" for p in matrix.by_prefix)


def test_lookup_exact_match_wins(tmp_path):
    matrix = load_tier_matrix(_yaml(tmp_path, """
version: "1.0"
default_min_tier: untrusted
capabilities:
  mcp.transfer_money:
    min_tier: managed_attested
"""))
    assert matrix.lookup("mcp.transfer_money") == "managed_attested"


def test_lookup_falls_back_to_default_when_unmatched(tmp_path):
    matrix = load_tier_matrix(_yaml(tmp_path, """
version: "1.0"
default_min_tier: byod_attested
capabilities: {}
"""))
    assert matrix.lookup("anything.else") == "byod_attested"


def test_lookup_wildcard_prefix_matches(tmp_path):
    matrix = load_tier_matrix(_yaml(tmp_path, """
version: "1.0"
default_min_tier: untrusted
capabilities:
  "admin.*":
    min_tier: managed_attested
"""))
    assert matrix.lookup("admin.read") == "managed_attested"
    assert matrix.lookup("admin.write_secret") == "managed_attested"
    # Does NOT match a different prefix.
    assert matrix.lookup("public.read") == "untrusted"


def test_lookup_longest_prefix_wins(tmp_path):
    matrix = load_tier_matrix(_yaml(tmp_path, """
version: "1.0"
default_min_tier: untrusted
capabilities:
  "admin.*":
    min_tier: managed
  "admin.financial.*":
    min_tier: managed_attested
"""))
    # The more specific prefix overrides the broader one.
    assert matrix.lookup("admin.financial.transfer") == "managed_attested"
    assert matrix.lookup("admin.read") == "managed"


def test_lookup_empty_capability_returns_default(tmp_path):
    matrix = load_tier_matrix(_yaml(tmp_path, """
version: "1.0"
default_min_tier: byod_isolated
capabilities: {}
"""))
    assert matrix.lookup(None) == "byod_isolated"
    assert matrix.lookup("") == "byod_isolated"


# ── error / fallback path ─────────────────────────────────────────────


def test_missing_file_returns_permissive_fallback(tmp_path, caplog):
    """A deployment without the YAML on disk must boot — the fallback
    matrix treats every capability as ``untrusted`` so the gate is a
    silent no-op."""
    matrix = load_tier_matrix(tmp_path / "nope.yaml")
    assert matrix.default_min_tier == "untrusted"
    assert matrix.lookup("mcp.transfer_money") == "untrusted"
    assert "fallback" in matrix.version


def test_load_default_swallows_errors_at_boot(monkeypatch, tmp_path):
    """``load_default_tier_matrix`` must never raise — boot must
    continue even when the YAML is corrupt."""
    bad = tmp_path / "broken.yaml"
    bad.write_text("not: [valid yaml")
    monkeypatch.setenv("MCP_PROXY_TIER_MATRIX_PATH", str(bad))
    matrix = load_default_tier_matrix()
    assert matrix.default_min_tier == "untrusted"


def test_invalid_tier_string_raises(tmp_path):
    with pytest.raises(ValueError, match="invalid min_tier"):
        load_tier_matrix(_yaml(tmp_path, """
version: "1.0"
default_min_tier: untrusted
capabilities:
  mcp.x:
    min_tier: super-admin
"""))


def test_invalid_default_tier_raises(tmp_path):
    with pytest.raises(ValueError, match="default_min_tier"):
        load_tier_matrix(_yaml(tmp_path, """
version: "1.0"
default_min_tier: nonsense
capabilities: {}
"""))


def test_non_mapping_top_level_raises(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("- 1\n- 2\n")
    with pytest.raises(ValueError, match="top level"):
        load_tier_matrix(p)


# ── tier_meets_requirement helper ────────────────────────────────────


@pytest.mark.parametrize("actual,required,expected", [
    # exact matches
    ("untrusted", "untrusted", True),
    ("managed_attested", "managed_attested", True),
    # actual > required → allow
    ("managed_attested", "untrusted", True),
    ("managed_attested", "byod_attested", True),
    ("managed", "byod_attested", True),
    ("byod_attested", "byod_isolated", True),
    # actual < required → deny
    ("untrusted", "byod_isolated", False),
    ("byod_isolated", "byod_attested", False),
    ("byod_attested", "managed", False),
    ("managed", "managed_attested", False),
    # untrusted is the floor — fails everything stricter
    ("untrusted", "managed_attested", False),
    # malformed actual collapses to untrusted (most restrictive)
    ("nonsense", "byod_isolated", False),
    # malformed required collapses to managed_attested (most
    # restrictive — typo in YAML must NOT silently relax the gate)
    ("managed", "nonsense", False),
    # None actual → untrusted
    (None, "byod_isolated", False),
    # None required → managed_attested (must lock down)
    ("byod_isolated", None, False),
])
def test_tier_meets_requirement_matrix(actual, required, expected):
    assert tier_meets_requirement(actual, required) is expected


def test_tier_order_is_canonical():
    """The order tuple shapes every comparison — pin it so a future
    insertion (e.g. ``byod_attested_managed_hybrid``) trips a test
    rather than silently re-ranking existing tiers."""
    assert TIER_ORDER == (
        "untrusted",
        "byod_isolated",
        "byod_attested",
        "managed",
        "managed_attested",
    )
