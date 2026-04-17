"""F-B-11 Phase 3b — ``pending_enrollments.dpop_jkt`` carries the
agent's DPoP JWK thumbprint from start-of-enrollment to approval.

Revision ID: 0015_enrollment_dpop_jkt
Revises: 0014_internal_agents_dpop_jkt
Create Date: 2026-04-18 00:00:00.000000

Phase 2 (#204) added ``internal_agents.dpop_jkt`` + Phase 3a (#206)
added the admin endpoint to populate it post-enrollment. This phase
threads the JWK through the device-code enrollment flow so approvals
auto-populate the column — the operator no longer has to hit the
admin endpoint by hand for every new Connector.

Lifecycle:
  * ``start_enrollment`` accepts an optional ``dpop_jwk`` field on
    the request body. The server validates it (public only, supported
    kty), computes the RFC 7638 thumbprint, and stores it here.
  * ``approve`` copies ``pending_enrollments.dpop_jkt`` to
    ``internal_agents.dpop_jkt`` alongside the rest of the enrolled
    agent's record.

Nullable because the field is optional on the request — pre-Phase-3c
SDKs will skip it and legacy agents remain governed by the egress mode
flag's grace path.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0015_enrollment_dpop_jkt"
down_revision: Union[str, Sequence[str], None] = "0014_internal_agents_dpop_jkt"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotent — matches 0013/0014 pattern. ``init_db`` calls
    # ``metadata.create_all`` before stamping on legacy-unstamped
    # SQLite deploys, in which case the column is already present
    # from the current model.
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("pending_enrollments")}
    if "dpop_jkt" in existing:
        return
    with op.batch_alter_table("pending_enrollments") as batch_op:
        batch_op.add_column(
            sa.Column("dpop_jkt", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("pending_enrollments")}
    if "dpop_jkt" not in existing:
        return
    with op.batch_alter_table("pending_enrollments") as batch_op:
        batch_op.drop_column("dpop_jkt")
