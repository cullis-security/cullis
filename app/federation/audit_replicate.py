"""ADR-008 amendment / Wave B PR8 (audit D1) — Mastio audit replication.

Each Mastio publishes its ``local_audit`` chain to the Court via
``POST /v1/federation/audit/replicate``. The Court verifies the
publisher's signature, enforces chain_seq continuity, and stores a
verbatim copy in ``mastio_audit_replica`` (append-only via
``alembic/versions/s9n0o1p2q3r4_mastio_audit_replica.py``).

Threat model:
  * **Repudiation** — every batch carries an ECDSA-P256 countersig
    over the raw body (same primitive as ``federation/publish.py``).
    Pinned in ``organizations.mastio_pubkey`` at onboarding. A Mastio
    cannot deny it published a given batch.
  * **Forgery** — the Mastio's per-org hash chain (each row carries
    ``previous_hash``) provides forward integrity within the chain.
    The receiver also enforces ``previous_hash[i] == entry_hash[i-1]``
    on inbound rows so an attacker can't inject a synthetic row
    without breaking the chain.
  * **Replay** — ``UNIQUE(mastio_org_id, chain_seq)`` makes the
    receiver idempotent: re-submitting the same batch produces a
    200 with ``stored=0, already_present=N`` instead of duplicate
    rows.
  * **Cross-tenant injection** — the body's ``mastio_org_id`` must
    match the org whose pubkey verified the countersig. A Mastio
    publishing into another org's namespace gets a 403.

Auth: mTLS gate (``enforce_mastio_mtls``) + countersig over the raw
body. Same pattern as the existing ``federation/publish-agent``.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.mastio_countersig import COUNTERSIG_HEADER, verify_mastio_countersig
from app.auth.mastio_mtls import enforce_if_required as enforce_mastio_mtls
from app.db.audit import MastioAuditReplica, log_event
from app.db.database import get_db
from app.rate_limit.limiter import get_client_ip, rate_limiter
from app.registry.org_store import get_org_by_id


_log = logging.getLogger("agent_trust.federation.audit_replicate")

router = APIRouter(prefix="/v1/federation", tags=["federation"])


class ReplicaEntry(BaseModel):
    chain_seq: int = Field(..., ge=1)
    entry_hash: str = Field(..., min_length=64, max_length=64)
    previous_hash: str | None = Field(None, min_length=64, max_length=64)
    timestamp: str = Field(..., max_length=64)
    event_type: str = Field(..., max_length=128)
    agent_id: str | None = Field(None, max_length=256)
    session_id: str | None = Field(None, max_length=128)
    details: str | None = None
    result: str = Field(..., max_length=32)
    principal_type: str | None = Field(None, max_length=32)
    hash_format: str | None = Field(None, max_length=8)


class ReplicateRequest(BaseModel):
    mastio_org_id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    entries: list[ReplicaEntry] = Field(..., min_length=1, max_length=1000)


class ReplicateResponse(BaseModel):
    mastio_org_id: str
    stored: int
    already_present: int
    last_chain_seq: int


@router.post(
    "/audit/replicate",
    response_model=ReplicateResponse,
    status_code=status.HTTP_200_OK,
)
async def replicate_audit_batch(
    request: Request,
    body: ReplicateRequest,
    mastio_signature: str | None = Header(
        default=None, alias=COUNTERSIG_HEADER,
    ),
    db: AsyncSession = Depends(get_db),
) -> ReplicateResponse:
    """Receive a Mastio audit batch and persist it after verification."""
    # Security review F-002 — rate-limit by client IP before any
    # ECDSA verify or audit append. Mirrors the
    # ``onboarding.rotate_mastio_pubkey`` bucket (issue #282).
    await rate_limiter.check(
        get_client_ip(request), "federation.audit_replicate",
    )

    # 1. Resolve the publishing org + its pinned pubkey.
    org = await get_org_by_id(db, body.mastio_org_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="organization not found",
        )
    if not org.mastio_pubkey:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "organization has no pinned mastio_pubkey — onboarding "
                "incomplete. Cannot verify audit replication signature."
            ),
        )

    # 2. mTLS gate (Phase 2 of Wave 3 U4). Verify-if-present unless
    #    organizations.require_mastio_mtls=true, mirroring publish.py.
    enforce_mastio_mtls(
        request, org.mastio_pubkey,
        require=bool(org.require_mastio_mtls),
    )

    # 3. Verify the countersig over the raw body bytes. Same primitive
    #    as ``federation/publish-agent``.
    raw = await request.body()
    try:
        raw_text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="body is not valid UTF-8",
        ) from exc
    verify_mastio_countersig(
        client_assertion=raw_text,
        signature_b64=mastio_signature,
        mastio_pubkey_pem=org.mastio_pubkey,
    )

    # 4. Sort entries by chain_seq and enforce continuity within the
    #    batch (previous_hash[i] == entry_hash[i-1]).
    entries = sorted(body.entries, key=lambda e: e.chain_seq)
    for i in range(1, len(entries)):
        if entries[i].chain_seq != entries[i - 1].chain_seq + 1:
            await log_event(
                db, "federation.audit_replicate_rejected", "denied",
                org_id=body.mastio_org_id,
                details={
                    "reason": "chain_seq_gap",
                    "expected": entries[i - 1].chain_seq + 1,
                    "got": entries[i].chain_seq,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"chain_seq gap: expected "
                    f"{entries[i - 1].chain_seq + 1}, got {entries[i].chain_seq}"
                ),
            )
        if entries[i].previous_hash != entries[i - 1].entry_hash:
            await log_event(
                db, "federation.audit_replicate_rejected", "denied",
                org_id=body.mastio_org_id,
                details={
                    "reason": "previous_hash_break",
                    "chain_seq": entries[i].chain_seq,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"previous_hash break at chain_seq={entries[i].chain_seq}"
                ),
            )

    # 5. Enforce continuity against the existing tail (no gap between
    #    last stored row and the first new row). This blocks a Mastio
    #    from skipping rows after a network blip — the publisher MUST
    #    resume from its last cursor.
    tail_row = (
        await db.execute(
            select(MastioAuditReplica)
            .where(MastioAuditReplica.mastio_org_id == body.mastio_org_id)
            .order_by(MastioAuditReplica.chain_seq.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    if tail_row is not None:
        # We allow re-submission of already-stored rows (idempotency)
        # so the publisher can retry safely. Just require that the
        # FIRST not-yet-stored row's previous_hash links to the tail's
        # entry_hash. Rows with chain_seq <= tail get diff'd later
        # against the existing rows and quietly counted as "already
        # present" if they match byte-for-byte.
        future = [e for e in entries if e.chain_seq > tail_row.chain_seq]
        if future:
            head = future[0]
            if head.chain_seq != tail_row.chain_seq + 1:
                await log_event(
                    db, "federation.audit_replicate_rejected", "denied",
                    org_id=body.mastio_org_id,
                    details={
                        "reason": "tail_gap",
                        "stored_tail": tail_row.chain_seq,
                        "batch_head": head.chain_seq,
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"chain_seq gap with stored tail: stored last "
                        f"{tail_row.chain_seq}, batch starts at "
                        f"{head.chain_seq}"
                    ),
                )
            if head.previous_hash != tail_row.entry_hash:
                await log_event(
                    db, "federation.audit_replicate_rejected", "denied",
                    org_id=body.mastio_org_id,
                    details={
                        "reason": "previous_hash_break_with_tail",
                        "chain_seq": head.chain_seq,
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"previous_hash on chain_seq={head.chain_seq} does "
                        f"not link to stored tail's entry_hash"
                    ),
                )

    # 6. Persist. Each entry stores the batch signature (one sig per
    #    batch is the per-row attribution: the row was in this signed
    #    batch). On UNIQUE collision (already present), check content
    #    equality and count as "already_present" — divergence is fatal.
    sig_to_store = mastio_signature or ""
    received_at = datetime.now(timezone.utc).isoformat()

    stored_count = 0
    already_present = 0
    last_seq = tail_row.chain_seq if tail_row else 0
    for e in entries:
        replica = MastioAuditReplica(
            mastio_org_id=body.mastio_org_id,
            chain_seq=e.chain_seq,
            entry_hash=e.entry_hash,
            previous_hash=e.previous_hash,
            timestamp=e.timestamp,
            event_type=e.event_type,
            agent_id=e.agent_id,
            session_id=e.session_id,
            details=e.details,
            result=e.result,
            principal_type=e.principal_type,
            hash_format=e.hash_format,
            signature_b64=sig_to_store,
            received_at=received_at,
        )
        try:
            async with db.begin_nested():
                db.add(replica)
                await db.flush()
            stored_count += 1
            last_seq = max(last_seq, e.chain_seq)
        except IntegrityError:
            # Already present — check for divergence (different
            # entry_hash on the same chain_seq = a Mastio is forking
            # its own chain, which is a fatal signal).
            existing = (
                await db.execute(
                    select(MastioAuditReplica).where(
                        MastioAuditReplica.mastio_org_id == body.mastio_org_id,
                        MastioAuditReplica.chain_seq == e.chain_seq,
                    )
                )
            ).scalar_one()
            if existing.entry_hash != e.entry_hash:
                await log_event(
                    db, "federation.audit_replicate_rejected", "denied",
                    org_id=body.mastio_org_id,
                    details={
                        "reason": "chain_fork",
                        "chain_seq": e.chain_seq,
                        "stored_hash": existing.entry_hash,
                        "submitted_hash": e.entry_hash,
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"chain fork at chain_seq={e.chain_seq}: stored "
                        f"hash differs from submitted hash"
                    ),
                ) from None
            already_present += 1
            last_seq = max(last_seq, e.chain_seq)

    await db.commit()

    await log_event(
        db, "federation.audit_replicate_accepted", "ok",
        org_id=body.mastio_org_id,
        details={
            "stored": stored_count,
            "already_present": already_present,
            "last_chain_seq": last_seq,
        },
    )

    return ReplicateResponse(
        mastio_org_id=body.mastio_org_id,
        stored=stored_count,
        already_present=already_present,
        last_chain_seq=last_seq,
    )
