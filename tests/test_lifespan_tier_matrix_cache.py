"""F5 follow-up #5 — tier-matrix is cached at lifespan startup.

Pre-fix the executor's tier gate fell back to ``load_default_tier_matrix()``
(disk YAML read) on every tool call because nothing populated
``app.state.tier_matrix``. These tests pin the wiring so a future
refactor that drops the stash falls red.
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

from unittest.mock import patch

import pytest

from mcp_proxy.policy.tier_matrix import TierMatrix, load_default_tier_matrix


@pytest.mark.asyncio
async def test_lifespan_stashes_tier_matrix_on_app_state():
    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        cached = getattr(app.state, "tier_matrix", None)
        assert cached is not None
        assert isinstance(cached, TierMatrix)
        # Identity with a direct load is the contract for the cache —
        # both go through the same loader, both produce the same
        # parsed matrix.
        fresh = load_default_tier_matrix()
        assert cached.version == fresh.version
        assert cached.default_min_tier == fresh.default_min_tier
        assert cached.by_exact == fresh.by_exact


@pytest.mark.asyncio
async def test_lifespan_handles_matrix_load_failure_without_crash():
    """A YAML loader failure during boot must NOT abort the lifespan —
    the executor's per-call fallback keeps the proxy permissive in
    that degraded mode (matching the existing `_resolve_tier_matrix`
    semantics)."""
    from mcp_proxy.main import app

    with patch(
        "mcp_proxy.policy.tier_matrix.load_default_tier_matrix",
        side_effect=RuntimeError("boom"),
    ):
        async with app.router.lifespan_context(app):
            assert getattr(app.state, "tier_matrix", "missing") is None
