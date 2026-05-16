"""ADR-032 F6: audit_log device_attestation + effective_tier + revocation columns.

Revision ID: 0037_audit_dev_attest
Revises: 0036_pending_attestation
Create Date: 2026-05-17 12:00:00.000000

F6 (Intune continuous evaluation + cert revocation) extends three tables:

1. ``audit_log.device_attestation`` (TEXT NULL) — JSON-serialised claim
   captured at policy decision time. Lets forensic queries answer
   "what device posture did we observe when this request was authorised?"
   without having to join back to a possibly-stale ``mdm_device_state``
   row. The schema doc (sez. 4.1) reserves the column shape.

2. ``audit_log.effective_tier`` (TEXT NULL) — the computed tier value
   at evaluation time. Same forensic motivation: a customer reviewing
   a denied request needs to see the tier the gate consumed, not the
   tier the row has now.

3. ``internal_agents.revoked_at`` (DateTime tz=True NULL) +
   ``revoked_reason`` (TEXT NULL) — explicit revocation surface for
   the F6 polling-driven cert revocation flow. Pre-existing
   ``is_active=0`` already locks the agent out at the next handshake;
   the dedicated columns give the dashboard + audit trail a place to
   show ``why`` (e.g. ``insufficient_compliance``) and ``when`` without
   parsing every audit row.

4. ``internal_agents.last_stale_event_at`` (DateTime tz=True NULL) —
   dedupe marker for the stale-watcher daemon. Without it, a device
   that crosses the staleness threshold and stays there would emit a
   ``device_attestation_stale`` audit row on every watcher tick. The
   column records the last time we emitted; the watcher only re-emits
   on a transition.

All columns are nullable so the migration is safe to apply to
populated tables. ``device_attestation`` and ``effective_tier`` are
populated lazily by the policy gate; legacy audit rows stay NULL.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0037_audit_dev_attest"
down_revision: Union[str, Sequence[str], None] = "0036_pending_attestation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_AUDIT = "audit_log"
_AGENTS = "internal_agents"


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if table not in set(insp.get_table_names()):
        return False
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    if not _has_column(_AUDIT, "device_attestation"):
        with op.batch_alter_table(_AUDIT) as batch_op:
            batch_op.add_column(
                sa.Column("device_attestation", sa.Text(), nullable=True),
            )

    if not _has_column(_AUDIT, "effective_tier"):
        with op.batch_alter_table(_AUDIT) as batch_op:
            batch_op.add_column(
                sa.Column("effective_tier", sa.String(length=32), nullable=True),
            )

    if not _has_column(_AGENTS, "revoked_at"):
        with op.batch_alter_table(_AGENTS) as batch_op:
            batch_op.add_column(
                sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            )

    if not _has_column(_AGENTS, "revoked_reason"):
        with op.batch_alter_table(_AGENTS) as batch_op:
            batch_op.add_column(
                sa.Column("revoked_reason", sa.String(length=128), nullable=True),
            )

    if not _has_column(_AGENTS, "last_stale_event_at"):
        with op.batch_alter_table(_AGENTS) as batch_op:
            batch_op.add_column(
                sa.Column(
                    "last_stale_event_at",
                    sa.DateTime(timezone=True),
                    nullable=True,
                ),
            )


def downgrade() -> None:
    if _has_column(_AGENTS, "last_stale_event_at"):
        with op.batch_alter_table(_AGENTS) as batch_op:
            batch_op.drop_column("last_stale_event_at")

    if _has_column(_AGENTS, "revoked_reason"):
        with op.batch_alter_table(_AGENTS) as batch_op:
            batch_op.drop_column("revoked_reason")

    if _has_column(_AGENTS, "revoked_at"):
        with op.batch_alter_table(_AGENTS) as batch_op:
            batch_op.drop_column("revoked_at")

    if _has_column(_AUDIT, "effective_tier"):
        with op.batch_alter_table(_AUDIT) as batch_op:
            batch_op.drop_column("effective_tier")

    if _has_column(_AUDIT, "device_attestation"):
        with op.batch_alter_table(_AUDIT) as batch_op:
            batch_op.drop_column("device_attestation")
