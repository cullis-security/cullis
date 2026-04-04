from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.database import get_db
from app.db.audit import log_event
from app.registry.binding_router import get_current_org
from app.registry.org_store import OrganizationRecord
from app.policy.models import PolicyCreateRequest, PolicyResponse
from app.policy.store import create_policy, get_policy, list_policies, deactivate_policy

router = APIRouter(prefix="/policy", tags=["policy"])


# ---------------------------------------------------------------------------
# Dependency — autenticazione admin tramite header
# ---------------------------------------------------------------------------

async def get_admin(
    x_admin_secret: Annotated[str, Header()],
) -> None:
    if x_admin_secret != get_settings().admin_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin secret non valido",
        )


@router.post("/rules", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: PolicyCreateRequest,
    org: OrganizationRecord = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new policy for the authenticated organization.
    Authentication: X-Org-Id + X-Org-Secret.
    """
    if org.org_id != body.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot create a policy for another organization",
        )

    if body.policy_type not in ("session", "message"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="policy_type must be 'session' or 'message'",
        )

    existing = await get_policy(db, body.policy_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="policy_id already exists",
        )

    record = await create_policy(db, body.policy_id, body.org_id, body.policy_type, body.rules)

    await log_event(
        db, "policy.created", "ok",
        org_id=body.org_id,
        details={"policy_id": body.policy_id, "policy_type": body.policy_type},
    )

    return PolicyResponse(
        id=record.id,
        policy_id=record.policy_id,
        org_id=record.org_id,
        policy_type=record.policy_type,
        rules=record.rules,
        is_active=record.is_active,
        created_at=record.created_at,
    )


@router.get("/rules", response_model=list[PolicyResponse])
async def list_rules(
    org_id: str,
    policy_type: str | None = None,
    org: OrganizationRecord = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """List active policies for an organization. Own org only."""
    if org.org_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot view policies of another organization",
        )

    records = await list_policies(db, org_id, policy_type=policy_type)
    return [
        PolicyResponse(
            id=r.id,
            policy_id=r.policy_id,
            org_id=r.org_id,
            policy_type=r.policy_type,
            rules=r.rules,
            is_active=r.is_active,
            created_at=r.created_at,
        )
        for r in records
    ]


@router.get("/rules/{policy_id}", response_model=PolicyResponse)
async def get_rule(
    policy_id: str,
    org: OrganizationRecord = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Policy detail. Own org only."""
    record = await get_policy(db, policy_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")

    if record.org_id != org.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot view policies of another organization",
        )

    return PolicyResponse(
        id=record.id,
        policy_id=record.policy_id,
        org_id=record.org_id,
        policy_type=record.policy_type,
        rules=record.rules,
        is_active=record.is_active,
        created_at=record.created_at,
    )


@router.delete("/rules/{policy_id}", response_model=PolicyResponse)
async def delete_rule(
    policy_id: str,
    org: OrganizationRecord = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a policy (is_active → false). Does not delete the row."""
    record = await get_policy(db, policy_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")

    if record.org_id != org.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot modify policies of another organization",
        )

    record = await deactivate_policy(db, policy_id)

    await log_event(
        db, "policy.deactivated", "ok",
        org_id=org.org_id,
        details={"policy_id": policy_id},
    )

    return PolicyResponse(
        id=record.id,
        policy_id=record.policy_id,
        org_id=record.org_id,
        policy_type=record.policy_type,
        rules=record.rules,
        is_active=record.is_active,
        created_at=record.created_at,
    )
