"""ADR-032 F3: pending_enrollments.device_attestation_json.

Revision ID: 0036_pending_attestation
Revises: 0035_mdm_device_state
Create Date: 2026-05-17 09:00:00.000000

F3 Phase 1 (Linux TPM BYOD) extends the enrollment flow with an optional
``tpm_quote`` field. When the Connector ships one, the server verifies it
against the public key in the CSR + the server-issued nonce, derives the
hardware-side attestation claim (``hardware=tpm_2.0`` +
``strength=hw_attested``/``hw_isolated`` + ``manufacturer=<vendor>``) and
persists the JSON-serialised claim on the pending row. Approval copies
the claim onto ``internal_agents.last_attestation`` (added by
``0035_mdm_device_state`` for the F2 Intune path; F3 reuses the same
column so the agent row has one canonical place for the merged claim).

NOT touched here:

* ``internal_agents.last_attestation`` (owned by F2 migration
  ``0035_mdm_device_state``).
* ``audit_log.device_attestation`` + ``audit_log.effective_tier`` (owned
  by the future F6 audit migration).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0036_pending_attestation"
down_revision: Union[str, Sequence[str], None] = "0035_mdm_device_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_PENDING = "pending_enrollments"
_COL = "device_attestation_json"


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if table not in set(insp.get_table_names()):
        return False
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    if not _has_column(_PENDING, _COL):
        with op.batch_alter_table(_PENDING) as batch_op:
            batch_op.add_column(sa.Column(_COL, sa.Text(), nullable=True))


def downgrade() -> None:
    if _has_column(_PENDING, _COL):
        with op.batch_alter_table(_PENDING) as batch_op:
            batch_op.drop_column(_COL)
