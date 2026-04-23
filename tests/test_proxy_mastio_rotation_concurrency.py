"""Race-safety + crash-recovery tests for ``rotate_mastio_key``.

Issue #281 — three failure modes guarded here:

* **Concurrent rotations** (in-process asyncio.gather) — exactly one
  branch wins, the other raises, and the keystore ends with exactly
  one active row.
* **Crash between propagator-ACK and local commit** — fault injection
  via ``monkeypatch`` on ``activate_staged_and_deprecate_old``; after
  the simulated crash the staged row persists, a fresh AgentManager
  detects it at boot, sign-halts, and ``complete_staged_rotation``
  recovers.
* **Admin recovery branches** — ``complete_staged_rotation`` exercised
  for ``activate`` and ``drop`` plus the no-staged error path.

All concurrency primitives use ``asyncio.Event`` + ``asyncio.gather``
— no ``time.sleep`` or timeouts-based synchronization that would
introduce flakiness. The test module is wired so a ``pytest --count=10``
run stresses the race paths without modification.
"""
from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from mcp_proxy.auth.local_keystore import LocalKeyStore
from mcp_proxy.egress.agent_manager import AgentManager


# ── Shared fixture ───────────────────────────────────────────────────


@pytest_asyncio.fixture
async def mgr(tmp_path, monkeypatch):
    """AgentManager bootstrapped against a fresh SQLite database.

    Matches the ``agent_manager_with_identity`` fixture from the main
    rotation-test module but is duplicated here to keep this module
    self-contained (pytest-repeat count-based reruns pick this file
    up independently).
    """
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.db import dispose_db, init_db

    await init_db(url)
    m = AgentManager(org_id="acme")
    await m.generate_org_ca(derive_org_id=False)
    await m.ensure_mastio_identity()
    try:
        yield m
    finally:
        await dispose_db()
        get_settings.cache_clear()


# ── Concurrency ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_rotations_exactly_one_succeeds(mgr):
    """Two rotations fired with ``asyncio.gather`` must resolve with
    exactly one success and one deterministic error — never both
    succeeding (which would leave two active rows) and never both
    failing (rotate_mastio_key should be make-progress).

    The second rotation fails on the ``_rotate_locked`` re-check
    rather than the DB UPDATE because the ``asyncio.Lock`` serializes
    them — the loser observes the active signer changed under it and
    raises before touching the DB.
    """
    old_kid = mgr._active_key.kid

    async def _rotate():
        return await mgr.rotate_mastio_key(grace_days=3, propagator=None)

    results = await asyncio.gather(_rotate(), _rotate(), return_exceptions=True)

    successes = [r for r in results if not isinstance(r, BaseException)]
    failures = [r for r in results if isinstance(r, BaseException)]
    assert len(successes) == 1, f"expected exactly 1 success, got {results!r}"
    assert len(failures) == 1, f"expected exactly 1 failure, got {results!r}"
    # The failure is the under-the-lock re-check that flags the
    # concurrent winner.
    assert isinstance(failures[0], RuntimeError)
    assert "active signer changed" in str(failures[0])

    # Exactly one active row.
    store = LocalKeyStore()
    active = await store.current_signer()
    assert active.kid == successes[0].kid
    # Old kid is deprecated-in-grace, not dangling.
    old_row = await store.find_by_kid(old_kid)
    assert old_row is not None
    assert old_row.deprecated_at is not None
    # No staged rows left over.
    assert await store.find_staged() is None


@pytest.mark.asyncio
async def test_rotate_aborts_when_staged_row_present(mgr, monkeypatch):
    """An orphaned staged row (left behind by a prior crashed
    rotation) must block a new rotation from starting. The operator
    has to resolve via ``complete_staged_rotation`` first.
    """
    # Simulate an orphaned staged row by inserting one directly.
    from mcp_proxy.db import insert_mastio_key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from mcp_proxy.auth.local_keystore import compute_kid
    from datetime import datetime, timezone

    priv = _ec.generate_private_key(_ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    staged_kid = compute_kid(pub_pem)
    await insert_mastio_key(
        kid=staged_kid,
        pubkey_pem=pub_pem,
        privkey_pem=priv_pem,
        cert_pem=None,
        created_at=datetime.now(timezone.utc).isoformat(),
        activated_at=None,  # staged marker
    )

    with pytest.raises(RuntimeError, match="staged row"):
        await mgr.rotate_mastio_key(grace_days=3, propagator=None)


# ── Crash liveness (fault injection between propagator-ACK and commit) ──


@pytest.mark.asyncio
async def test_crash_between_propagator_ack_and_activate_preserves_staged(
    mgr, monkeypatch,
):
    """Fault-inject a failure on ``activate_staged_and_deprecate_old``
    *after* the propagator has ACKed. The rotate must:

    - raise (caller sees the error).
    - leave the staged row intact so recovery is possible.
    - set ``is_sign_halted`` on the manager so subsequent countersigns
      fail fast with a clear message.
    - leave the old active row untouched (Court might still be on old
      or already on new; ``complete_staged_rotation`` resolves).
    """
    old_kid = mgr._active_key.kid
    propagator_ran = asyncio.Event()

    async def succeed_propagator(_proof, _cert):
        propagator_ran.set()

    # Monkeypatch the DB commit to fail — this simulates a crash /
    # DB drop between the propagator ACK and the atomic activation.
    import mcp_proxy.egress.agent_manager as agent_mgr_mod

    async def exploding_activate(**_kwargs):
        raise RuntimeError("simulated DB failure mid-commit")

    monkeypatch.setattr(
        agent_mgr_mod,
        "activate_staged_and_deprecate_old",
        exploding_activate,
    )

    with pytest.raises(RuntimeError, match="simulated DB failure"):
        await mgr.rotate_mastio_key(
            grace_days=3, propagator=succeed_propagator,
        )

    # Propagator did run — we're past Court-ACK.
    assert propagator_ran.is_set()

    store = LocalKeyStore()

    # Staged row still on disk for recovery.
    staged = await store.find_staged()
    assert staged is not None
    assert staged.kid != old_kid
    assert staged.activated_at is None

    # Old active row untouched — still the current signer.
    current = await store.current_signer()
    assert current.kid == old_kid

    # Manager is sign-halted and exposes the staged kid.
    assert mgr.is_sign_halted is True
    assert mgr.staged_kid == staged.kid

    # Countersign now fails fast with a clear message.
    with pytest.raises(RuntimeError, match="signing halted"):
        mgr.countersign(b"payload")


@pytest.mark.asyncio
async def test_boot_detects_staged_and_halts_signing(tmp_path, monkeypatch):
    """A fresh AgentManager pointed at a DB containing a staged row
    (as if the previous process crashed mid-rotation) must detect the
    staged row during ``ensure_mastio_identity`` and flip
    ``is_sign_halted = True``. ``LocalIssuer`` construction in
    ``main.py`` gates on that flag, so no unsigned local tokens are
    emitted while the operator resolves.
    """
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import dispose_db, init_db, insert_mastio_key

    try:
        await init_db(url)

        # Bootstrap a first AgentManager to mint the real Org CA +
        # active Mastio leaf, then orphan a staged row.
        first = AgentManager(org_id="acme")
        await first.generate_org_ca(derive_org_id=False)
        await first.ensure_mastio_identity()

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from mcp_proxy.auth.local_keystore import compute_kid
        from datetime import datetime, timezone

        priv = _ec.generate_private_key(_ec.SECP256R1())
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        staged_kid = compute_kid(pub_pem)
        await insert_mastio_key(
            kid=staged_kid,
            pubkey_pem=pub_pem,
            privkey_pem=priv_pem,
            cert_pem=None,
            created_at=datetime.now(timezone.utc).isoformat(),
            activated_at=None,
        )

        # Fresh AgentManager — simulates a process restart. Should
        # detect the staged row and sign-halt.
        second = AgentManager(org_id="acme")
        await second.load_org_ca_from_config()
        await second.ensure_mastio_identity()

        assert second.is_sign_halted is True
        assert second.staged_kid == staged_kid

        with pytest.raises(RuntimeError, match="signing halted"):
            second.countersign(b"payload")
    finally:
        await dispose_db()
        get_settings.cache_clear()


# ── complete_staged_rotation — recovery endpoint branches ────────────


@pytest.mark.asyncio
async def test_complete_staged_drop_clears_halt(mgr, monkeypatch):
    """``decision='drop'``: the staged row is deleted, the active
    signer is unchanged, sign-halt flag clears.
    """
    # Arrive at a halted state the same way #281's crash path does.
    import mcp_proxy.egress.agent_manager as agent_mgr_mod

    async def exploding_activate(**_kwargs):
        raise RuntimeError("simulated DB failure mid-commit")

    monkeypatch.setattr(
        agent_mgr_mod,
        "activate_staged_and_deprecate_old",
        exploding_activate,
    )

    async def propagator_ok(_p, _c):
        return None

    with pytest.raises(RuntimeError):
        await mgr.rotate_mastio_key(
            grace_days=3, propagator=propagator_ok,
        )
    assert mgr.is_sign_halted

    # Drop recovery — clear the halt and remove the staged row.
    monkeypatch.undo()  # restore real activate_staged_and_deprecate_old
    old_kid = mgr._active_key.kid
    result = await mgr.complete_staged_rotation("drop")

    assert result["decision"] == "drop"
    assert result["kid"] == mgr._staged_kid or result["kid"] is not None
    assert mgr.is_sign_halted is False
    assert mgr.staged_kid is None

    # Active signer unchanged.
    store = LocalKeyStore()
    current = await store.current_signer()
    assert current.kid == old_kid
    assert await store.find_staged() is None

    # Countersign works again.
    mgr.countersign(b"payload-after-drop")


@pytest.mark.asyncio
async def test_complete_staged_activate_completes_rotation(mgr, monkeypatch):
    """``decision='activate'``: the staged row becomes the active
    signer, the previous active row is deprecated-in-grace, sign-halt
    flag clears.
    """
    import mcp_proxy.egress.agent_manager as agent_mgr_mod

    async def exploding_activate(**_kwargs):
        raise RuntimeError("simulated DB failure mid-commit")

    monkeypatch.setattr(
        agent_mgr_mod,
        "activate_staged_and_deprecate_old",
        exploding_activate,
    )

    async def propagator_ok(_p, _c):
        return None

    old_kid = mgr._active_key.kid
    with pytest.raises(RuntimeError):
        await mgr.rotate_mastio_key(
            grace_days=3, propagator=propagator_ok,
        )
    assert mgr.is_sign_halted
    staged_kid_snapshot = mgr.staged_kid
    assert staged_kid_snapshot is not None

    monkeypatch.undo()  # restore real DB helper

    result = await mgr.complete_staged_rotation("activate")

    assert result["decision"] == "activate"
    assert result["kid"] == staged_kid_snapshot
    assert result["old_kid"] == old_kid
    assert mgr.is_sign_halted is False
    assert mgr.staged_kid is None

    # Active signer swapped.
    store = LocalKeyStore()
    current = await store.current_signer()
    assert current.kid == staged_kid_snapshot

    # Old row deprecated but still verifiable for the grace window.
    old_row = await store.find_by_kid(old_kid)
    assert old_row is not None
    assert old_row.is_active is False
    assert old_row.deprecated_at is not None
    assert old_row.is_valid_for_verification is True

    # Countersign works and uses the new key.
    mgr.countersign(b"payload-after-activate")


@pytest.mark.asyncio
async def test_complete_staged_no_staged_row_raises(mgr):
    """``complete_staged_rotation`` called without an outstanding
    staged row must raise — the halt flag might be stale, but the
    endpoint cannot invent a row to operate on.
    """
    assert mgr.is_sign_halted is False
    with pytest.raises(RuntimeError, match="no staged row"):
        await mgr.complete_staged_rotation("drop")


@pytest.mark.asyncio
async def test_complete_staged_rejects_invalid_decision(mgr):
    with pytest.raises(ValueError, match="activate.*drop"):
        await mgr.complete_staged_rotation("")
    with pytest.raises(ValueError, match="activate.*drop"):
        await mgr.complete_staged_rotation("rollback")


# ── Cleanup on propagator failure (regression) ───────────────────────


@pytest.mark.asyncio
async def test_staged_row_cleaned_up_when_propagator_raises(mgr):
    """The existing ``test_rotate_aborts_when_propagator_raises``
    asserts state-unchanged. Extending it: after the new stage-first
    flow, the cleanup path must DELETE the staged row we inserted
    before calling the propagator. Otherwise a retry would hit the
    ``staged row already present`` guard.
    """
    old_kid = mgr._active_key.kid

    async def failing(_p, _c):
        raise RuntimeError("court rejected the proof")

    with pytest.raises(RuntimeError, match="court rejected"):
        await mgr.rotate_mastio_key(grace_days=3, propagator=failing)

    store = LocalKeyStore()
    assert await store.find_staged() is None, \
        "propagator-failure path left a staged row behind — retry would block"
    assert mgr.is_sign_halted is False
    current = await store.current_signer()
    assert current.kid == old_kid

    # A retry with a good propagator should work (no staged row blocking).
    new_active = await mgr.rotate_mastio_key(grace_days=3, propagator=None)
    assert new_active.kid != old_kid
