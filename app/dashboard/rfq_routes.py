"""Court dashboard — RFQ sub-router.

Sprint 2 / F-B-202 PR-9 of 10. Extracts the request-for-quote
list / detail / approval surface (section 15 of router.py).

Mounted via ``router.include_router(rfq_routes.router)``.

Routes (3):

  GET  /dashboard/rfqs               list (last 100)
  GET  /dashboard/rfq/{rfq_id}       detail + responses
  POST /dashboard/rfq/{rfq_id}/approve  approve a quote + mint txn token

The approve endpoint mints a transaction token and pushes it over the
broker WS to the initiator agent — same path the API uses, kept inline
here so the dashboard and API stay behaviour-equivalent.
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.auth.transaction_token import compute_payload_hash, create_transaction_token
from app.broker.db_models import RfqRecord, RfqResponseRecord
from app.broker.ws_manager import ws_manager
from app.dashboard._helpers import _ctx
from app.dashboard._template_env import build_templates
from app.dashboard.session import require_login, verify_csrf
from app.db.audit import log_event
from app.db.database import get_db

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-rfq"])


@router.get("/rfqs", response_class=HTMLResponse)
async def rfq_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(RfqRecord).order_by(RfqRecord.created_at.desc()).limit(100)
    rfqs = (await db.execute(q)).scalars().all()

    return templates.TemplateResponse("rfqs.html",
        _ctx(request, session, active="rfq", rfqs=rfqs)
    )


@router.get("/rfq/{rfq_id}", response_class=HTMLResponse)
async def rfq_detail(request: Request, rfq_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    rfq = (await db.execute(
        select(RfqRecord).where(RfqRecord.rfq_id == rfq_id)
    )).scalar_one_or_none()
    if not rfq:
        raise HTTPException(status_code=404, detail="RFQ not found")

    responses = (await db.execute(
        select(RfqResponseRecord).where(RfqResponseRecord.rfq_id == rfq_id)
    )).scalars().all()

    return templates.TemplateResponse("rfq_detail.html",
        _ctx(request, session, active="rfq", rfq=rfq, responses=responses,
             success=None, error=None)
    )


@router.post("/rfq/{rfq_id}/approve", response_class=HTMLResponse)
async def rfq_approve(request: Request, rfq_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    rfq = (await db.execute(
        select(RfqRecord).where(RfqRecord.rfq_id == rfq_id)
    )).scalar_one_or_none()
    if not rfq:
        raise HTTPException(status_code=404, detail="RFQ not found")

    form = await request.form()
    response_id = form.get("response_id")
    responder_agent_id = form.get("responder_agent_id", "")

    if not response_id:
        raise HTTPException(status_code=400, detail="Missing response_id")

    quote = (await db.execute(
        select(RfqResponseRecord).where(
            RfqResponseRecord.id == int(response_id),
            RfqResponseRecord.rfq_id == rfq_id,
        )
    )).scalar_one_or_none()
    if not quote:
        raise HTTPException(status_code=404, detail="Quote not found")

    payload_hash = compute_payload_hash(quote.payload)
    token_id, token_record = await create_transaction_token(
        db,
        agent_id=rfq.initiator_agent_id,
        org_id=rfq.initiator_org_id,
        txn_type="CREATE_ORDER",
        resource_id=rfq_id,
        payload_hash=payload_hash,
        approved_by="admin",
        rfq_id=rfq_id,
        target_agent_id=responder_agent_id,
    )

    rfq.status = "approved"
    await db.commit()

    try:
        await ws_manager.send_to_agent(rfq.initiator_agent_id, {
            "type": "transaction_token",
            "token_id": token_id,
            "rfq_id": rfq_id,
            "txn_type": "CREATE_ORDER",
            "target_agent_id": responder_agent_id,
            "payload_hash": payload_hash,
        })
    except Exception:
        _log.warning("Could not deliver transaction token to agent %s via WS",
                      rfq.initiator_agent_id)

    await log_event(db, "rfq.approved", "ok",
                    agent_id=rfq.initiator_agent_id, org_id=rfq.initiator_org_id,
                    details={"rfq_id": rfq_id, "approved_quote_id": response_id,
                             "responder_agent_id": responder_agent_id, "token_id": token_id})

    responses = (await db.execute(
        select(RfqResponseRecord).where(RfqResponseRecord.rfq_id == rfq_id)
    )).scalars().all()
    await db.refresh(rfq)

    return templates.TemplateResponse("rfq_detail.html",
        _ctx(request, session, active="rfq", rfq=rfq, responses=responses,
             success=f"Quote approved. Transaction token issued to agent {rfq.initiator_agent_id}.",
             error=None)
    )
