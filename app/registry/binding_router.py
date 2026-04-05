from datetime import datetime
from typing import Annotated
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.audit import log_event
from app.registry.org_store import get_org_by_id, verify_org_credentials, OrganizationRecord
from app.registry.binding_store import (
    create_binding,
    get_binding,
    get_binding_by_org_agent,
    approve_binding,
    revoke_binding,
    list_bindings,
)
from app.registry.store import invalidate_agent_tokens, get_agent_by_id

router = APIRouter(prefix="/registry", tags=["registry"])


# ---------------------------------------------------------------------------
# Dependency — organization authentication via header
# ---------------------------------------------------------------------------

async def get_current_org(
    x_org_id: Annotated[str, Header()],
    x_org_secret: Annotated[str, Header()],
    db: AsyncSession = Depends(get_db),
) -> OrganizationRecord:
    """
    Verify organization credentials from the X-Org-Id + X-Org-Secret headers.
    """
    org = await get_org_by_id(db, x_org_id)
    if not verify_org_credentials(org, x_org_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid organization credentials",
        )
    return org


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class BindingCreateRequest(BaseModel):
    org_id: str
    agent_id: str
    scope: list[str] = []


class BindingResponse(BaseModel):
    id: int
    org_id: str
    agent_id: str
    status: str
    scope: list[str]
    approved_at: datetime | None
    approved_by: str | None
    created_at: datetime


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/bindings", response_model=BindingResponse, status_code=status.HTTP_201_CREATED)
async def create_agent_binding(
    body: BindingCreateRequest,
    org: OrganizationRecord = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a binding (status: pending) between an agent and an organization.
    The authenticated organization must match the org_id in the body.
    """
    if org.org_id != body.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot create a binding for another organization",
        )

    # Validate scope is a subset of the agent's registered capabilities
    agent = await get_agent_by_id(db, body.agent_id)
    if not agent or agent.org_id != body.org_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found or does not belong to this organization",
        )
    agent_caps = set(agent.capabilities)
    invalid_scope = [s for s in body.scope if s not in agent_caps]
    if invalid_scope:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope {invalid_scope} not in agent capabilities: {sorted(agent_caps)}",
        )

    existing = await get_binding_by_org_agent(db, body.org_id, body.agent_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Binding already exists for this agent and organization",
        )

    binding = await create_binding(db, body.org_id, body.agent_id, body.scope)

    await log_event(
        db, "binding.created", "ok",
        agent_id=body.agent_id, org_id=body.org_id,
        details={"binding_id": binding.id, "scope": body.scope},
    )

    return BindingResponse(
        id=binding.id,
        org_id=binding.org_id,
        agent_id=binding.agent_id,
        status=binding.status,
        scope=binding.scope,
        approved_at=binding.approved_at,
        approved_by=binding.approved_by,
        created_at=binding.created_at,
    )


@router.post("/bindings/{binding_id}/approve", response_model=BindingResponse)
async def approve_agent_binding(
    binding_id: int,
    org: OrganizationRecord = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Approve a pending binding. Only the owning organization."""
    binding = await get_binding(db, binding_id)
    if not binding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Binding not found")

    if binding.org_id != org.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not the owning organization of this binding",
        )

    binding = await approve_binding(db, binding_id, approved_by=org.org_id)

    await log_event(
        db, "binding.approved", "ok",
        agent_id=binding.agent_id, org_id=binding.org_id,
        details={"binding_id": binding_id},
    )

    return BindingResponse(
        id=binding.id,
        org_id=binding.org_id,
        agent_id=binding.agent_id,
        status=binding.status,
        scope=binding.scope,
        approved_at=binding.approved_at,
        approved_by=binding.approved_by,
        created_at=binding.created_at,
    )


@router.post("/bindings/{binding_id}/revoke", response_model=BindingResponse)
async def revoke_agent_binding(
    binding_id: int,
    org: OrganizationRecord = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a binding. Only the owning organization."""
    binding = await get_binding(db, binding_id)
    if not binding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Binding not found")

    if binding.org_id != org.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not the owning organization of this binding",
        )

    binding = await revoke_binding(db, binding_id)

    # Invalidate all currently active access tokens for this agent so that
    # revoked bindings take effect immediately without waiting for token expiry.
    await invalidate_agent_tokens(db, binding.agent_id)

    # Close all active sessions for this agent and persist the change.
    from app.broker.session import get_session_store
    from app.broker.persistence import save_session
    from app.broker.ws_manager import ws_manager

    store = get_session_store()
    closed_sessions = store.close_all_for_agent(binding.agent_id)
    for s in closed_sessions:
        await save_session(db, s)

    # Force-disconnect the agent's WebSocket connection (if any)
    if ws_manager.is_connected(binding.agent_id):
        await ws_manager.disconnect(binding.agent_id)

    await log_event(
        db, "binding.revoked", "ok",
        agent_id=binding.agent_id, org_id=binding.org_id,
        details={"binding_id": binding_id, "sessions_closed": len(closed_sessions)},
    )

    return BindingResponse(
        id=binding.id,
        org_id=binding.org_id,
        agent_id=binding.agent_id,
        status=binding.status,
        scope=binding.scope,
        approved_at=binding.approved_at,
        approved_by=binding.approved_by,
        created_at=binding.created_at,
    )


@router.get("/bindings", response_model=list[BindingResponse])
async def list_agent_bindings(
    org_id: str,
    org: OrganizationRecord = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """List bindings for an organization. Own org only."""
    if org.org_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot view bindings of another organization",
        )

    bindings = await list_bindings(db, org_id)
    return [
        BindingResponse(
            id=b.id,
            org_id=b.org_id,
            agent_id=b.agent_id,
            status=b.status,
            scope=b.scope,
            approved_at=b.approved_at,
            approved_by=b.approved_by,
            created_at=b.created_at,
        )
        for b in bindings
    ]
