"""
RFQ (Request for Quote) broadcast — lets an agent query all matching suppliers
and collect quotes within a timeout window.

Flow:
  1. Initiator calls POST /broker/rfq with capability filter + payload
  2. Broker discovers matching agents, evaluates policy for each
  3. Broadcasts the RFQ to approved agents via WebSocket + persistent notification
  4. Collects responses via POST /broker/rfq/{rfq_id}/respond
  5. Returns aggregated quotes when timeout fires or all agents respond
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import TokenPayload
from app.broker.db_models import RfqRecord, RfqResponseRecord
from app.broker.models import RfqRequest, RfqQuote, RfqResponse
from app.broker.ws_manager import ws_manager
from app.broker.notifications import create_notification
from app.db.audit import log_event
from app.policy.backend import evaluate_session_policy
from app.registry.store import search_agents_by_capabilities, AgentRecord
from app.registry.org_store import get_org_by_id

_log = logging.getLogger("agent_trust")

# In-flight RFQ collection queues: rfq_id → asyncio.Queue
_rfq_queues: dict[str, asyncio.Queue] = {}


async def broadcast_rfq(
    db: AsyncSession,
    initiator: TokenPayload,
    request: RfqRequest,
) -> RfqResponse:
    """Execute the full RFQ lifecycle: discover, policy-check, broadcast, collect."""
    rfq_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # 1. Discover matching agents
    candidates = await search_agents_by_capabilities(
        db,
        capabilities=request.capability_filter,
        exclude_org_id=initiator.org,
    )
    if not candidates:
        record = RfqRecord(
            rfq_id=rfq_id, initiator_agent_id=initiator.agent_id,
            initiator_org_id=initiator.org,
            capability_filter=json.dumps(request.capability_filter),
            payload_json=json.dumps(request.payload),
            status="closed", timeout_seconds=request.timeout_seconds,
            matched_agents_json="[]", created_at=now, closed_at=now,
        )
        db.add(record)
        await db.commit()
        return RfqResponse(
            rfq_id=rfq_id, status="closed", matched_agents=[],
            quotes=[], created_at=now, closed_at=now,
        )

    # 2. Policy check per candidate
    approved: list[AgentRecord] = []
    initiator_org = await get_org_by_id(db, initiator.org)

    for agent in candidates:
        target_org = await get_org_by_id(db, agent.org_id)
        decision = await evaluate_session_policy(
            initiator_org_id=initiator.org,
            initiator_webhook_url=initiator_org.webhook_url if initiator_org else None,
            target_org_id=agent.org_id,
            target_webhook_url=target_org.webhook_url if target_org else None,
            initiator_agent_id=initiator.agent_id,
            target_agent_id=agent.agent_id,
            capabilities=request.capability_filter,
            # ADR-029 Phase B: RFQ candidate eligibility is still
            # a session-open style decision (we're filtering who is
            # reachable, not invoking a tool yet).
            invocation={
                "kind": "session_open",
                "capabilities_requested": request.capability_filter,
            },
        )
        if decision.allowed:
            approved.append(agent)
        else:
            await log_event(
                db, "rfq.policy_denied", "denied",
                agent_id=initiator.agent_id, org_id=initiator.org,
                details={"rfq_id": rfq_id, "target": agent.agent_id,
                         "reason": decision.reason},
            )

    matched_ids = [a.agent_id for a in approved]

    # 3. Persist RFQ record
    record = RfqRecord(
        rfq_id=rfq_id,
        initiator_agent_id=initiator.agent_id,
        initiator_org_id=initiator.org,
        capability_filter=json.dumps(request.capability_filter),
        payload_json=json.dumps(request.payload),
        status="open",
        timeout_seconds=request.timeout_seconds,
        matched_agents_json=json.dumps(matched_ids),
        created_at=now,
    )
    db.add(record)
    await db.commit()

    await log_event(
        db, "rfq.created", "ok",
        agent_id=initiator.agent_id, org_id=initiator.org,
        details={"rfq_id": rfq_id, "matched": len(matched_ids),
                 "capabilities": request.capability_filter},
    )

    if not approved:
        record.status = "closed"
        record.closed_at = datetime.now(timezone.utc)
        await db.commit()
        return RfqResponse(
            rfq_id=rfq_id, status="closed", matched_agents=matched_ids,
            quotes=[], created_at=now, closed_at=record.closed_at,
        )

    # 4. Broadcast to approved agents
    queue: asyncio.Queue = asyncio.Queue()
    _rfq_queues[rfq_id] = queue

    rfq_message = {
        "type": "rfq_request",
        "rfq_id": rfq_id,
        "initiator_agent_id": initiator.agent_id,
        "initiator_org_id": initiator.org,
        "capabilities": request.capability_filter,
        "payload": request.payload,
        "timeout_seconds": request.timeout_seconds,
    }

    for agent in approved:
        await ws_manager.send_to_agent(agent.agent_id, rfq_message)
        await create_notification(
            db,
            recipient_type="agent",
            recipient_id=agent.agent_id,
            notification_type="rfq_request",
            title=f"RFQ from {initiator.agent_id}",
            body=f"Capabilities: {', '.join(request.capability_filter)}",
            reference_id=rfq_id,
            org_id=agent.org_id,
        )
        await log_event(
            db, "rfq.broadcast", "ok",
            agent_id=agent.agent_id, org_id=agent.org_id,
            details={"rfq_id": rfq_id, "initiator": initiator.agent_id},
        )

    # 5. Collect responses with timeout
    quotes: list[RfqQuote] = []
    try:
        deadline = asyncio.get_event_loop().time() + request.timeout_seconds
        while len(quotes) < len(approved):
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                quote = await asyncio.wait_for(queue.get(), timeout=remaining)
                quotes.append(quote)
            except asyncio.TimeoutError:
                break
    finally:
        _rfq_queues.pop(rfq_id, None)

    # 6. Close RFQ
    closed_at = datetime.now(timezone.utc)
    rfq_status = "closed" if len(quotes) == len(approved) else "timeout"
    record.status = rfq_status
    record.closed_at = closed_at
    await db.commit()

    await log_event(
        db, "rfq.closed", "ok",
        agent_id=initiator.agent_id, org_id=initiator.org,
        details={"rfq_id": rfq_id, "status": rfq_status,
                 "quotes_received": len(quotes), "matched": len(matched_ids)},
    )

    return RfqResponse(
        rfq_id=rfq_id,
        status=rfq_status,
        matched_agents=matched_ids,
        quotes=quotes,
        created_at=now,
        closed_at=closed_at,
    )


async def submit_rfq_response(
    db: AsyncSession,
    rfq_id: str,
    responder: TokenPayload,
    payload: dict,
) -> bool:
    """Submit a quote response to an open RFQ. Returns True if accepted."""
    from sqlalchemy import select

    # Verify RFQ exists and is open
    result = await db.execute(
        select(RfqRecord).where(RfqRecord.rfq_id == rfq_id)
    )
    rfq = result.scalar_one_or_none()
    if not rfq:
        return False

    if rfq.status != "open":
        return False

    # Verify responder was in the matched set
    matched = json.loads(rfq.matched_agents_json)
    if responder.agent_id not in matched:
        return False

    # Check for duplicate response
    existing = await db.execute(
        select(RfqResponseRecord).where(
            RfqResponseRecord.rfq_id == rfq_id,
            RfqResponseRecord.responder_agent_id == responder.agent_id,
        )
    )
    if existing.scalar_one_or_none():
        return False

    now = datetime.now(timezone.utc)

    # Persist response
    response_record = RfqResponseRecord(
        rfq_id=rfq_id,
        responder_agent_id=responder.agent_id,
        responder_org_id=responder.org,
        response_payload=json.dumps(payload),
        received_at=now,
    )
    db.add(response_record)
    await db.commit()

    await log_event(
        db, "rfq.response_received", "ok",
        agent_id=responder.agent_id, org_id=responder.org,
        details={"rfq_id": rfq_id},
    )

    # Push quote to the collection queue
    quote = RfqQuote(
        responder_agent_id=responder.agent_id,
        responder_org_id=responder.org,
        payload=payload,
        received_at=now,
    )
    queue = _rfq_queues.get(rfq_id)
    if queue:
        await queue.put(quote)

    return True


async def get_rfq(db: AsyncSession, rfq_id: str) -> dict | None:
    """Get RFQ status and collected responses."""
    from sqlalchemy import select

    result = await db.execute(
        select(RfqRecord).where(RfqRecord.rfq_id == rfq_id)
    )
    rfq = result.scalar_one_or_none()
    if not rfq:
        return None

    responses = await db.execute(
        select(RfqResponseRecord).where(RfqResponseRecord.rfq_id == rfq_id)
    )
    quotes = [
        RfqQuote(
            responder_agent_id=r.responder_agent_id,
            responder_org_id=r.responder_org_id,
            payload=json.loads(r.response_payload),
            received_at=r.received_at,
        )
        for r in responses.scalars().all()
    ]

    return RfqResponse(
        rfq_id=rfq.rfq_id,
        status=rfq.status,
        matched_agents=json.loads(rfq.matched_agents_json),
        quotes=quotes,
        created_at=rfq.created_at,
        closed_at=rfq.closed_at,
    )
