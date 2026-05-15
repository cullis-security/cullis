"""P1.2 — denormalize DPoP jkt into ``audit_log``.

Revision ID: 0033_audit_dpop_jkt
Revises: 0032_ai_creds_at_rest_enc
Create Date: 2026-05-15 13:30:00.000000

``audit_log.dpop_jkt`` carries the JWK thumbprint of the DPoP key
that authenticated the request that produced the row. Today the same
identity bits live in the egress / request log only and a forensic
query has to JOIN against a different table by ``request_id``; the
forensic gap closes once the thumbprint lives next to the action.

Schema:

  * ``dpop_jkt`` nullable so calls without a DPoP-bound auth context
    (boot-time housekeeping, system actions, pre-rollout rows) keep
    inserting cleanly.
  * Indexed for the typical forensic query ("show me every action
    signed by this key") so the lookup stays flat as the log grows.

Not included in the audit hash chain. The chain locks the
authoritative action fields (timestamp, agent_id, action, status,
detail, request_id, …); ``dpop_jkt`` is auxiliary correlation
metadata, derivable from the authenticated principal at write time,
not a fact about the action itself. Including it would re-anchor
every pre-rollout row's hash and force a chain rewrite, which is
neither cheap nor risk-free for an append-only ledger. The
``compute_audit_row_hash`` invariant therefore stays untouched.
"""
from alembic import op
import sqlalchemy as sa


revision = "0033_audit_dpop_jkt"
down_revision = "0032_ai_creds_at_rest_enc"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    """Defensive check so re-running the migration on a partially
    upgraded schema (alembic stamp / manual SQL recovery) is a no-op
    rather than a duplicate-column error."""
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return column in {c["name"] for c in insp.get_columns(table)}


def _has_index(table: str, index: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return index in {i["name"] for i in insp.get_indexes(table)}


def upgrade() -> None:
    if not _has_column("audit_log", "dpop_jkt"):
        with op.batch_alter_table("audit_log") as batch_op:
            # 64 hex chars = SHA-256 thumbprint (RFC 7638). nullable
            # because plenty of audit rows have no DPoP context.
            batch_op.add_column(
                sa.Column("dpop_jkt", sa.String(length=64), nullable=True),
            )

    if not _has_index("audit_log", "idx_audit_log_dpop_jkt"):
        op.create_index(
            "idx_audit_log_dpop_jkt",
            "audit_log",
            ["dpop_jkt"],
        )


def downgrade() -> None:
    if _has_index("audit_log", "idx_audit_log_dpop_jkt"):
        op.drop_index("idx_audit_log_dpop_jkt", table_name="audit_log")
    if _has_column("audit_log", "dpop_jkt"):
        with op.batch_alter_table("audit_log") as batch_op:
            batch_op.drop_column("dpop_jkt")
