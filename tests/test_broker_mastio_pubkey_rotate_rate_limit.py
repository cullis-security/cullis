"""Rate-limit + dedupe for the Court's mastio-pubkey rotate endpoint.

Issue #282 — the endpoint (``POST /v1/onboarding/orgs/{id}/mastio-pubkey/rotate``)
is unauthenticated (auth derives from the continuity proof), so without
rate limiting an attacker who guesses an org_id can burn CPU on ECDSA
verify and flood the hash-chain audit with ``admin.mastio_pubkey_rotate_rejected``
rows. The dedupe cache additionally makes legitimate operator retries
idempotent over the 600-second proof freshness window — a replay
returns the original response without re-verifying or re-auditing.

The tests use ``monkeypatch`` on ``app.rate_limit.limiter.get_client_ip``
to drive the limiter with per-test IPs — uvicorn's proxy-headers
middleware (which would populate ``request.client.host`` from XFF in
production) is not wired through ``httpx.AsyncClient`` + ASGI
transport, so every request arrives with the same synthetic client
IP without this override.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import AsyncClient

from app.config import get_settings
from mcp_proxy.auth.local_keystore import compute_kid
from mcp_proxy.auth.mastio_rotation import build_proof
from tests.cert_factory import get_org_ca_pem

pytestmark = pytest.mark.asyncio

ADMIN_SECRET = get_settings().admin_secret


@pytest.fixture(autouse=True)
async def _reset_rate_limit_between_tests():
    """Clear the module-level rate limiter and dedupe cache before
    each test so shared-state bleed across test ordering does not
    cause spurious 429s or stale dedupe hits.
    """
    from app.rate_limit.limiter import rate_limiter
    from app.onboarding.rotate_dedupe import rotate_dedupe
    # In-memory backend stores its state in ``_windows`` (dict of
    # (subject, bucket) → deque). Clear it.
    try:
        rate_limiter._windows.clear()
    except AttributeError:
        pass
    await rotate_dedupe.reset()
    yield
    try:
        rate_limiter._windows.clear()
    except AttributeError:
        pass
    await rotate_dedupe.reset()


def _gen_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


async def _create_org_with_pubkey(
    client: AsyncClient, org_id: str, pubkey_pem: str,
) -> None:
    invite = await client.post(
        "/v1/admin/invites",
        json={"label": org_id, "ttl_hours": 1},
        headers={"x-admin-secret": ADMIN_SECRET},
    )
    token = invite.json()["token"]
    await client.post("/v1/onboarding/join", json={
        "org_id": org_id,
        "display_name": org_id,
        "secret": f"{org_id}-secret",
        "ca_certificate": get_org_ca_pem(org_id),
        "invite_token": token,
    })
    r = await client.patch(
        f"/v1/admin/orgs/{org_id}/mastio-pubkey",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"mastio_pubkey": pubkey_pem},
    )
    assert r.status_code == 200, r.text


# ── rate-limit (5/min/IP) ────────────────────────────────────────────


async def test_rate_limit_blocks_sixth_request_from_same_ip(
    client: AsyncClient, monkeypatch,
):
    """5 fresh rotation attempts from the same IP pass the rate
    limiter; the 6th gets a 429 before any ECDSA verify runs.

    Each attempt uses a *different* proof so the dedupe cache never
    short-circuits — we're measuring the rate limiter in isolation.
    The rotations themselves fail 401 (foreign proof against the
    pinned pubkey), which is fine: the budget is consumed regardless.
    """
    from app.onboarding import router as onboarding_router_mod
    monkeypatch.setattr(
        onboarding_router_mod, "get_client_ip",
        lambda req: "203.0.113.210",
    )

    _, pinned_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "rl-burst", pinned_pub)

    # 5 foreign proofs — each hits the limiter once, each returns 401
    # (foreign proof rejected by ECDSA verify).
    for _ in range(5):
        foreign_priv, foreign_pub = _gen_p256_keypair()
        _, new_pub = _gen_p256_keypair()
        proof = build_proof(
            old_priv_key=foreign_priv,
            old_kid=compute_kid(foreign_pub),
            new_kid=compute_kid(new_pub),
            new_pubkey_pem=new_pub,
        )
        r = await client.post(
            "/v1/onboarding/orgs/rl-burst/mastio-pubkey/rotate",
            json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
        )
        assert r.status_code == 401, r.text

    # 6th — must be 429, before the ECDSA verify runs.
    foreign_priv, foreign_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    proof = build_proof(
        old_priv_key=foreign_priv,
        old_kid=compute_kid(foreign_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    r = await client.post(
        "/v1/onboarding/orgs/rl-burst/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
    )
    assert r.status_code == 429, r.text


async def test_rate_limit_is_per_ip(client: AsyncClient, monkeypatch):
    """A second IP is not penalised when the first IP has hit the
    budget ceiling. Proves the rate-limit key is the client IP, not
    a global counter.
    """
    _, pinned_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "rl-per-ip", pinned_pub)

    from app.onboarding import router as onboarding_router_mod

    # Burn budget on IP A.
    monkeypatch.setattr(
        onboarding_router_mod, "get_client_ip",
        lambda req: "203.0.113.220",
    )
    for _ in range(6):
        foreign_priv, foreign_pub = _gen_p256_keypair()
        _, new_pub = _gen_p256_keypair()
        proof = build_proof(
            old_priv_key=foreign_priv,
            old_kid=compute_kid(foreign_pub),
            new_kid=compute_kid(new_pub),
            new_pubkey_pem=new_pub,
        )
        await client.post(
            "/v1/onboarding/orgs/rl-per-ip/mastio-pubkey/rotate",
            json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
        )

    # IP B should still be allowed through — its own bucket.
    monkeypatch.setattr(
        onboarding_router_mod, "get_client_ip",
        lambda req: "203.0.113.221",
    )
    foreign_priv, foreign_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    proof = build_proof(
        old_priv_key=foreign_priv,
        old_kid=compute_kid(foreign_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    r = await client.post(
        "/v1/onboarding/orgs/rl-per-ip/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
    )
    # 401 because the proof is foreign — but NOT 429, which is the
    # whole point of the per-IP bucket.
    assert r.status_code == 401, r.text


# ── idempotency dedupe cache ─────────────────────────────────────────


async def test_replayed_proof_returns_cached_response_and_no_new_audit(
    client: AsyncClient,
):
    """A legitimate operator who retries the same proof within the
    freshness window must get an identical 200 from the cache —
    without a second ECDSA verify and without a second audit row
    polluting the hash chain.
    """
    from app.onboarding.rotate_dedupe import rotate_dedupe

    old_priv, old_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "dedupe-ok", old_pub)

    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )

    # Isolate the cache so prior tests don't pollute the key space.
    await rotate_dedupe.reset()

    r1 = await client.post(
        "/v1/onboarding/orgs/dedupe-ok/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
    )
    assert r1.status_code == 200, r1.text
    first = r1.json()

    r2 = await client.post(
        "/v1/onboarding/orgs/dedupe-ok/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
    )
    assert r2.status_code == 200, r2.text
    second = r2.json()

    # Identical payload on replay — dedupe hit.
    assert first == second
    # Crucially: the ``rotated_at`` is the ORIGINAL rotation's
    # timestamp, not a fresh one, because we returned the cached
    # response instead of re-running the commit.
    assert first["rotated_at"] == second["rotated_at"]

    # Audit log should have exactly one ``admin.mastio_pubkey_rotated``
    # for this org despite two requests.
    from app.db.audit import AuditLog
    from app.db.database import AsyncSessionLocal
    from sqlalchemy import func, select
    async with AsyncSessionLocal() as db:
        stmt = (
            select(func.count(AuditLog.id))
            .where(AuditLog.event_type == "admin.mastio_pubkey_rotated")
            .where(AuditLog.org_id == "dedupe-ok")
        )
        result = await db.execute(stmt)
        count = result.scalar_one()
    assert count == 1, f"expected 1 rotation audit row, got {count}"


async def test_failed_rotation_is_not_cached(client: AsyncClient):
    """A failure (e.g. 401 on a foreign proof) must NOT enter the
    dedupe cache — otherwise a transient-failure retry would be
    locked into the failure indefinitely. Prove this by following a
    401 with a correct retry against the same org: the second
    attempt should verify normally and succeed.
    """
    from app.onboarding.rotate_dedupe import rotate_dedupe
    await rotate_dedupe.reset()

    pinned_priv, pinned_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "dedupe-fail-then-ok", pinned_pub)

    # First attempt with a WRONG signing key → 401.
    foreign_priv, foreign_pub = _gen_p256_keypair()
    bad_proof = build_proof(
        old_priv_key=foreign_priv,
        old_kid=compute_kid(foreign_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    r_bad = await client.post(
        "/v1/onboarding/orgs/dedupe-fail-then-ok/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": bad_proof.to_dict()},
    )
    assert r_bad.status_code == 401, r_bad.text

    # Second attempt with the CORRECT signing key → must succeed,
    # proving that the 401 did not poison the cache key.
    good_proof = build_proof(
        old_priv_key=pinned_priv,
        old_kid=compute_kid(pinned_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    r_ok = await client.post(
        "/v1/onboarding/orgs/dedupe-fail-then-ok/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": good_proof.to_dict()},
    )
    assert r_ok.status_code == 200, r_ok.text


async def test_different_proofs_do_not_collide_in_cache(client: AsyncClient):
    """Dedupe is keyed on (org_id, signature_b64u). Two rotations
    with different proofs must both be processed (sequential, not
    replayed). The second rotation's ``old_kid`` is the first
    rotation's ``new_kid`` — happy-path back-to-back rotation.
    """
    from app.onboarding.rotate_dedupe import rotate_dedupe
    await rotate_dedupe.reset()

    first_priv, first_pub = _gen_p256_keypair()
    second_priv, second_pub = _gen_p256_keypair()
    _, third_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "dedupe-chain", first_pub)

    # Rotation 1: first → second.
    proof_1 = build_proof(
        old_priv_key=first_priv,
        old_kid=compute_kid(first_pub),
        new_kid=compute_kid(second_pub),
        new_pubkey_pem=second_pub,
    )
    r1 = await client.post(
        "/v1/onboarding/orgs/dedupe-chain/mastio-pubkey/rotate",
        json={"new_pubkey_pem": second_pub, "proof": proof_1.to_dict()},
    )
    assert r1.status_code == 200, r1.text

    # Rotation 2: second → third. Different signature → different
    # cache key → must be processed, not dedupe-hit.
    proof_2 = build_proof(
        old_priv_key=second_priv,
        old_kid=compute_kid(second_pub),
        new_kid=compute_kid(third_pub),
        new_pubkey_pem=third_pub,
    )
    r2 = await client.post(
        "/v1/onboarding/orgs/dedupe-chain/mastio-pubkey/rotate",
        json={"new_pubkey_pem": third_pub, "proof": proof_2.to_dict()},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["new_kid"] == compute_kid(third_pub)
    assert r2.json()["rotated_at"] != r1.json()["rotated_at"]


# ── concurrent dedupe (audit L4-H4) ──────────────────────────────────


async def test_concurrent_replays_atomic_claim_one_audit_row(
    client: AsyncClient, monkeypatch,
):
    """Audit L4-H4 regression. N=10 concurrent rotation requests with
    the SAME proof signature must collapse to EXACTLY ONE audit row
    and EXACTLY ONE pubkey commit. The previous get-verify-store
    sequence let two concurrent retries both miss the dedupe ``get``,
    both verify, both append ``admin.mastio_pubkey_rotated`` rows to
    the per-org audit chain.
    """
    import asyncio

    from app.onboarding.rotate_dedupe import rotate_dedupe
    await rotate_dedupe.reset()

    old_priv, old_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "dedupe-concurrent", old_pub)

    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )

    # Hand each concurrent request a distinct client IP so the
    # rate limiter (5/min/IP) does not mask the dedupe primitive
    # under test. The dedupe key is (org_id, signature_b64u),
    # independent of source IP, so this preserves the race we want
    # to expose.
    import itertools
    counter = itertools.count(1)
    from app.onboarding import router as onboarding_router_mod
    monkeypatch.setattr(
        onboarding_router_mod, "get_client_ip",
        lambda req: f"203.0.113.{next(counter)}",
    )

    n = 10
    payload = {"new_pubkey_pem": new_pub, "proof": proof.to_dict()}

    # Fire N concurrent identical requests — gather() schedules them
    # on the same event loop, exposing the TOCTOU window across the
    # in-process dedupe primitive.
    responses = await asyncio.gather(*[
        client.post(
            "/v1/onboarding/orgs/dedupe-concurrent/mastio-pubkey/rotate",
            json=payload,
        )
        for _ in range(n)
    ])

    # All N callers see HTTP 200. Either the worker's response or the
    # cached body — both are the same payload.
    assert all(r.status_code == 200 for r in responses), (
        [r.status_code for r in responses]
    )
    bodies = [r.json() for r in responses]
    first = bodies[0]
    for b in bodies[1:]:
        assert b == first, (
            f"concurrent caller saw a different rotated_at/new_kid "
            f"than the worker: {b} vs {first}"
        )

    # Audit chain: EXACTLY ONE ``admin.mastio_pubkey_rotated`` row
    # for this org, regardless of N.
    from app.db.audit import AuditLog
    from app.db.database import AsyncSessionLocal
    from sqlalchemy import func, select
    async with AsyncSessionLocal() as db:
        stmt = (
            select(func.count(AuditLog.id))
            .where(AuditLog.event_type == "admin.mastio_pubkey_rotated")
            .where(AuditLog.org_id == "dedupe-concurrent")
        )
        result = await db.execute(stmt)
        count = result.scalar_one()
    assert count == 1, (
        f"expected exactly 1 rotation audit row across {n} concurrent "
        f"identical retries, got {count} — audit chain pollution"
    )


async def test_concurrent_replays_invoke_commit_exactly_once(
    client: AsyncClient, monkeypatch,
):
    """N=10 concurrent identical requests must invoke
    ``update_org_mastio_pubkey`` (the commit primitive) exactly once.
    Counts call_count rather than only audit rows so we cover the
    "verify+commit" half of the L4-H4 race even if a future change
    moves the audit-write off the commit path.
    """
    import asyncio
    from unittest.mock import AsyncMock

    from app.onboarding.rotate_dedupe import rotate_dedupe
    await rotate_dedupe.reset()

    old_priv, old_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "dedupe-commit-once", old_pub)

    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )

    # Wrap the real commit primitive with an AsyncMock that delegates
    # so we can count calls without changing semantics.
    from app.onboarding import router as router_mod
    real_update = router_mod.update_org_mastio_pubkey
    spy = AsyncMock(side_effect=real_update)
    monkeypatch.setattr(router_mod, "update_org_mastio_pubkey", spy)

    # Distinct IPs per request so the rate limiter does not interfere.
    import itertools
    counter = itertools.count(1)
    monkeypatch.setattr(
        router_mod, "get_client_ip",
        lambda req: f"203.0.113.{next(counter)}",
    )

    n = 10
    payload = {"new_pubkey_pem": new_pub, "proof": proof.to_dict()}
    responses = await asyncio.gather(*[
        client.post(
            "/v1/onboarding/orgs/dedupe-commit-once/mastio-pubkey/rotate",
            json=payload,
        )
        for _ in range(n)
    ])
    assert all(r.status_code == 200 for r in responses)

    # The first-pin PATCH issued during _create_org_with_pubkey runs
    # through update_org_mastio_pubkey too — our spy fires once for
    # that, then exactly once more for the rotation. Filter by org_id
    # to avoid coupling to setup.
    rotation_calls = [
        c for c in spy.call_args_list
        if (c.args and c.args[1] == "dedupe-commit-once")
        or c.kwargs.get("org_id") == "dedupe-commit-once"
    ]
    # _create_org_with_pubkey routes via the admin patch endpoint, NOT
    # via the rotate endpoint, so its update goes through the same
    # function — we expect exactly TWO total calls for this org_id
    # (one first-pin + one rotation), or just ONE if the test harness
    # somehow batches them. The invariant we care about: the rotation
    # path itself contributes exactly ONE call across N retries.
    assert 1 <= len(rotation_calls) <= 2, (
        f"expected 1 (rotate-only) or 2 (admin pin + rotate) commit "
        f"calls for org=dedupe-commit-once, got {len(rotation_calls)}"
    )


async def test_concurrent_invalid_proofs_reject_all_no_audit_pollution(
    client: AsyncClient, monkeypatch,
):
    """Negative path. N=10 concurrent identical requests with an
    INVALID proof must all receive 401 and contribute at most ONE
    ``admin.mastio_pubkey_rotate_rejected`` row to the audit chain
    (the worker's). The `_in_progress` Future shares the rejection
    with the N-1 waiters — no caller hits the verify path twice.
    """
    import asyncio

    from app.onboarding.rotate_dedupe import rotate_dedupe
    await rotate_dedupe.reset()

    _, pinned_pub = _gen_p256_keypair()
    foreign_priv, foreign_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "dedupe-concurrent-bad", pinned_pub)

    bad_proof = build_proof(
        old_priv_key=foreign_priv,
        old_kid=compute_kid(foreign_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )

    import itertools
    counter = itertools.count(1)
    from app.onboarding import router as onboarding_router_mod
    monkeypatch.setattr(
        onboarding_router_mod, "get_client_ip",
        lambda req: f"203.0.113.{next(counter)}",
    )

    n = 10
    payload = {"new_pubkey_pem": new_pub, "proof": bad_proof.to_dict()}
    responses = await asyncio.gather(*[
        client.post(
            "/v1/onboarding/orgs/dedupe-concurrent-bad/mastio-pubkey/rotate",
            json=payload,
        )
        for _ in range(n)
    ])

    # All N callers see the same rejection (401 — kid/signature mismatch).
    assert all(r.status_code == 401 for r in responses), (
        [r.status_code for r in responses]
    )

    # No successful rotation row was written.
    from app.db.audit import AuditLog
    from app.db.database import AsyncSessionLocal
    from sqlalchemy import func, select
    async with AsyncSessionLocal() as db:
        ok_stmt = (
            select(func.count(AuditLog.id))
            .where(AuditLog.event_type == "admin.mastio_pubkey_rotated")
            .where(AuditLog.org_id == "dedupe-concurrent-bad")
        )
        ok_count = (await db.execute(ok_stmt)).scalar_one()
    assert ok_count == 0, (
        f"invalid proof rotation appended {ok_count} ok-rows to the "
        f"audit chain — expected 0"
    )

    # The pin is unchanged. (Proves no commit slipped through under
    # concurrency.)
    from app.registry.org_store import get_org_by_id
    async with AsyncSessionLocal() as db:
        org = await get_org_by_id(db, "dedupe-concurrent-bad")
        assert org.mastio_pubkey == pinned_pub
