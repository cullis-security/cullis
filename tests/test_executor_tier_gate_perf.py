"""F5 follow-up #5 — tier gate uses cached matrix, no per-call disk read.

The executor's ``_resolve_tier_matrix`` reads ``app.state.tier_matrix``
first. With the boot-time stash in place, no disk YAML read should
happen at gate-time on the hot path.
"""
from __future__ import annotations

import os

os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mcp_proxy.policy.tier_matrix import TierMatrix
from mcp_proxy.tools import executor


def _matrix() -> TierMatrix:
    return TierMatrix(
        version="test",
        default_min_tier="untrusted",
        by_exact={},
        by_prefix=(),
        source_path="<test>",
    )


def test_gate_reads_cached_matrix_when_present_no_disk_load():
    app_state = SimpleNamespace(tier_matrix=_matrix())
    with patch(
        "mcp_proxy.policy.tier_matrix.load_default_tier_matrix",
    ) as loader:
        result = executor._resolve_tier_matrix(app_state)
        loader.assert_not_called()
        assert result is app_state.tier_matrix


def test_gate_falls_back_to_loader_when_cache_missing():
    """When `app_state.tier_matrix` is None the gate still loads from
    disk — keeps test-time loaders working when the lifespan didn't run.
    """
    app_state = SimpleNamespace(tier_matrix=None)
    fake = _matrix()
    with patch(
        "mcp_proxy.policy.tier_matrix.load_default_tier_matrix",
        return_value=fake,
    ) as loader:
        result = executor._resolve_tier_matrix(app_state)
        loader.assert_called_once()
        assert result is fake


def test_gate_handles_none_app_state():
    """Test paths that pass ``app_state=None`` still go through the
    disk loader once — they don't error out."""
    fake = _matrix()
    with patch(
        "mcp_proxy.policy.tier_matrix.load_default_tier_matrix",
        return_value=fake,
    ):
        result = executor._resolve_tier_matrix(None)
        assert result is fake
