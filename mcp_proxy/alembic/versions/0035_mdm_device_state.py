"""ADR-032 Layer 1 — MDM device-state cache + agent attestation column.

Revision ID: 0035_mdm_device_state
Revises: 0034_user_sessions_obo
Create Date: 2026-05-17 09:00:00.000000

Two schema changes for the F2 Intune spike:

1. ``mdm_device_state`` table. Cache of the inventory Mastio fetches
   from each MDM (Phase 1: Intune only; the ``mdm`` PK column
   makes Jamf / WS1 additions a drop-in). Composite primary key
   ``(mdm, device_id)`` so a customer migrating Connectors between
   MDMs does not collide. ``raw_payload`` keeps the full Graph row
   for forensic queries; the projected columns are the cheap-query
   subset (``compliance``, ``azure_ad_device_id``, ``user_principal_name``,
   etc.).

2. ``internal_agents.last_attestation`` (TEXT NULL, JSON-serialised
   claim). The Connector device IS the agent under ADR-014, so the
   ``device_attestation`` claim sticks to the agent row. F4 R2's
   ``user_sessions`` row can later denormalise the same claim for
   the shared-mode Frontdesk case (multi-user behind one workload);
   that lives in a follow-up migration so this spike stays focused.

Note on placement vs. the spike spec: the prompt suggested
``local_user_principals.last_attestation``. The principal is a
durable identity (sso_subject, idp_issuer) that outlives any
specific device; the attestation is a per-device claim. Putting it
on the agent row keeps the lifetime correct and matches where the
enrollment hook actually writes (``mcp_proxy/enrollment/service.py``
upserts internal_agents). The ADR will follow up with a similar
column on ``user_sessions`` once F4 R2 wires that flow end-to-end.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0035_mdm_device_state"
down_revision: Union[str, Sequence[str], None] = "0034_user_sessions_obo"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_MDM = "mdm_device_state"
_AGENTS = "internal_agents"


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in set(sa.inspect(bind).get_table_names())


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return column in {c["name"] for c in insp.get_columns(table)}


def _has_index(table: str, index: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return index in {i["name"] for i in insp.get_indexes(table)}


def upgrade() -> None:
    # 1. mdm_device_state ---------------------------------------------------
    if not _has_table(_MDM):
        op.create_table(
            _MDM,
            # 'intune', 'jamf', 'ws1'. Composite PK with device_id
            # so the same device under a different MDM does not
            # silently overwrite.
            sa.Column("mdm", sa.String(length=16), primary_key=True),
            sa.Column("device_id", sa.String(length=128), primary_key=True),
            # Claim values: 'compliant' | 'non_compliant' | 'unknown'.
            # Stored as String(32) for the typical query "WHERE
            # compliance = 'compliant'"; the projection layer enforces
            # the enum.
            sa.Column("compliance", sa.String(length=32), nullable=False),
            sa.Column("azure_ad_device_id", sa.String(length=128), nullable=True),
            sa.Column("user_principal_name", sa.String(length=255), nullable=True),
            sa.Column("device_name", sa.String(length=255), nullable=True),
            sa.Column("manufacturer", sa.String(length=64), nullable=True),
            sa.Column("serial_number", sa.String(length=128), nullable=True),
            # Full Graph row as JSON text so future projections can be
            # backfilled without re-polling Microsoft.
            sa.Column("raw_payload", sa.Text(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    if not _has_index(_MDM, "ix_mdm_device_state_last_seen"):
        op.create_index(
            "ix_mdm_device_state_last_seen", _MDM, ["last_seen_at"],
        )

    if not _has_index(_MDM, "ix_mdm_device_state_azure_ad"):
        op.create_index(
            "ix_mdm_device_state_azure_ad", _MDM, ["azure_ad_device_id"],
        )

    if not _has_index(_MDM, "ix_mdm_device_state_upn"):
        op.create_index(
            "ix_mdm_device_state_upn", _MDM, ["user_principal_name"],
        )

    # 2. internal_agents.last_attestation ----------------------------------
    if not _has_column(_AGENTS, "last_attestation"):
        with op.batch_alter_table(_AGENTS) as batch_op:
            batch_op.add_column(
                sa.Column("last_attestation", sa.Text(), nullable=True),
            )


def downgrade() -> None:
    if _has_column(_AGENTS, "last_attestation"):
        with op.batch_alter_table(_AGENTS) as batch_op:
            batch_op.drop_column("last_attestation")

    if _has_index(_MDM, "ix_mdm_device_state_upn"):
        op.drop_index("ix_mdm_device_state_upn", table_name=_MDM)
    if _has_index(_MDM, "ix_mdm_device_state_azure_ad"):
        op.drop_index("ix_mdm_device_state_azure_ad", table_name=_MDM)
    if _has_index(_MDM, "ix_mdm_device_state_last_seen"):
        op.drop_index("ix_mdm_device_state_last_seen", table_name=_MDM)
    if _has_table(_MDM):
        op.drop_table(_MDM)
