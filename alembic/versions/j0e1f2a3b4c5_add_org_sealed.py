"""add org.sealed flag — audit F-B-2 guardrail

Revision ID: j0e1f2a3b4c5
Revises: i9d0e1f2a3b4
Create Date: 2026-04-17 12:00:00.000000

Introduces a nullable-boolean ``sealed`` column on ``organizations``.

Background
----------
The broker dashboard authenticates a single ``admin`` session cookie. Until
this change every mutation on an org (approve/revoke binding, delete org,
unlock CA, rotate agent cert, register agent) trusted that cookie alone —
with no cross-check that the operator actually represents the tenant whose
identity plane is being modified.

Audit finding F-B-2 (`imp/audit_2026_04_17/phase1_B_authz.md`) marked this
as CRITICAL: the network admin can unilaterally tamper with any tenant's
CA, agents and bindings.

Fix
---
When an org is onboarded via the ``attach-ca`` invite flow (the proxy-first
onboarding path), it is considered "tenant-sealed": mutations on that org
from the broker dashboard require a short-lived per-org re-auth gate on
top of the admin session.

This migration adds the column. Default ``False`` — existing orgs stay in
legacy mode (grandfathered); new attach-ca consumes flip it to ``True``;
new create-org flows leave it ``False`` unless the admin explicitly seals
the org from the dashboard. The enforcement itself lives in
``app/dashboard/router.py``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'j0e1f2a3b4c5'
down_revision: Union[str, Sequence[str], None] = 'i9d0e1f2a3b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'organizations',
        sa.Column(
            'sealed',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('organizations', 'sealed')
