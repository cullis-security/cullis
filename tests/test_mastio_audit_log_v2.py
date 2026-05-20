"""PR #4 audit 2026-05-20: Mastio audit_log v2 + append-only trigger.

Closes F-A-402 (BEFORE UPDATE/DELETE trigger missing on the Mastio
primary audit_log) and F-A-403 (canonical hash excluded dpop_jkt +
on_behalf_of_user_id, so attribution was forgeable via UPDATE).

These tests pin both gates so the dual-tier Court↔Mastio sister-file
pattern cannot regress on this surface.
"""
from __future__ import annotations

import pytest

from mcp_proxy.db import compute_audit_row_hash


# ─── F-A-403 v2 canonical includes dpop_jkt + on_behalf_of_user_id ────


def test_v2_canonical_includes_dpop_jkt():
    """Same v1 inputs, different dpop_jkt → different row_hash under v2.
    Pre-fix the two were equal because the canonical ignored the column."""
    base = dict(
        chain_seq=1,
        timestamp="2026-05-20T15:00:00Z",
        agent_id="acme::frontdesk",
        action="tool_call",
        tool_name="search",
        status="ok",
        detail="",
        request_id="req-1",
        prev_hash="genesis",
        on_behalf_of_user_id="alice",
        hash_format="v2",
    )
    h_a = compute_audit_row_hash(**{**base, "dpop_jkt": "thumb_a"})
    h_b = compute_audit_row_hash(**{**base, "dpop_jkt": "thumb_b"})
    assert h_a != h_b, "v2 must bind dpop_jkt into the canonical"


def test_v2_canonical_includes_on_behalf_of_user_id():
    """Same v1 inputs, different on_behalf_of_user_id → different
    row_hash under v2. Pre-fix the attacker could swap victim_user
    for attacker_user without detection."""
    base = dict(
        chain_seq=1,
        timestamp="2026-05-20T15:00:00Z",
        agent_id="acme::frontdesk",
        action="tool_call",
        tool_name="search",
        status="ok",
        detail="",
        request_id="req-1",
        prev_hash="genesis",
        dpop_jkt="thumb",
        hash_format="v2",
    )
    h_alice = compute_audit_row_hash(
        **{**base, "on_behalf_of_user_id": "alice"},
    )
    h_eve = compute_audit_row_hash(
        **{**base, "on_behalf_of_user_id": "eve"},
    )
    assert h_alice != h_eve, (
        "v2 must bind on_behalf_of_user_id (the F-A-403 attack)"
    )


def test_v1_canonical_unchanged_for_legacy_rows():
    """Legacy rows (hash_format=NULL or 'v1') must verify with the
    v1 canonical regardless of dpop_jkt / on_behalf_of_user_id values
    passed at recompute time. Backward compat invariant."""
    base = dict(
        chain_seq=1,
        timestamp="2026-05-20T15:00:00Z",
        agent_id="acme::frontdesk",
        action="tool_call",
        tool_name="search",
        status="ok",
        detail="",
        request_id="req-1",
        prev_hash="genesis",
    )
    # hash_format=None (legacy) — dpop_jkt + obo ignored.
    h_legacy_no_dpop = compute_audit_row_hash(
        **base, dpop_jkt=None, on_behalf_of_user_id=None,
    )
    h_legacy_with_dpop = compute_audit_row_hash(
        **base, dpop_jkt="thumb", on_behalf_of_user_id="alice",
    )
    assert h_legacy_no_dpop == h_legacy_with_dpop, (
        "v1 must not bind the new columns (legacy rows precede the migration)"
    )

    # Explicit "v1" string also takes the legacy path.
    h_explicit_v1 = compute_audit_row_hash(
        **base, dpop_jkt="thumb", on_behalf_of_user_id="alice",
        hash_format="v1",
    )
    assert h_explicit_v1 == h_legacy_no_dpop


def test_v2_prefix_differs_from_v1_for_same_v1_inputs():
    """A v2 row with NO attribution columns set still produces a
    different hash from its v1 equivalent, because the canonical is
    prefixed with the literal ``v2|``. Prevents downgrade-style
    attacks: an attacker who knows the v1 inputs cannot precompute
    the v2 hash without knowing the format discriminator."""
    base = dict(
        chain_seq=1,
        timestamp="2026-05-20T15:00:00Z",
        agent_id="acme::frontdesk",
        action="tool_call",
        tool_name="search",
        status="ok",
        detail="",
        request_id="req-1",
        prev_hash="genesis",
    )
    h_v1 = compute_audit_row_hash(**base)
    h_v2 = compute_audit_row_hash(
        **base, dpop_jkt=None, on_behalf_of_user_id=None, hash_format="v2",
    )
    assert h_v1 != h_v2


# ─── F-A-402 append-only trigger ──────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_log_update_blocked_by_trigger(tmp_path):
    """F-A-402: a raw SQL UPDATE on audit_log must be rejected by the
    schema trigger. Mirrors the parity test for local_audit
    (tests/test_proxy_local_audit_chain.py) and the Court equivalent
    (r8m9n0o1p2q3)."""
    from sqlalchemy import text
    from mcp_proxy.db import dispose_db, init_db, get_db, log_audit

    db_file = tmp_path / "audit_v2.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    try:
        await log_audit(
            agent_id="acme::test",
            action="tool_call",
            tool_name="search",
            status="ok",
            detail="seed",
        )

        async with get_db() as conn:
            with pytest.raises(Exception) as exc:
                await conn.execute(
                    text(
                        "UPDATE audit_log SET detail = 'tampered' "
                        "WHERE id = 1"
                    ),
                )
            assert "append-only" in str(exc.value).lower() or (
                "f-a-402" in str(exc.value).lower()
            ), f"Expected append-only trigger raise, got: {exc.value}"

        async with get_db() as conn:
            with pytest.raises(Exception) as exc:
                await conn.execute(
                    text("DELETE FROM audit_log WHERE id = 1"),
                )
            assert "append-only" in str(exc.value).lower() or (
                "f-a-402" in str(exc.value).lower()
            ), (
                f"Expected append-only trigger raise on DELETE, got: {exc.value}"
            )
    finally:
        await dispose_db()
