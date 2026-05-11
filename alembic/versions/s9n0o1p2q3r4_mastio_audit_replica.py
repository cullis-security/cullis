"""Court-side mastio_audit_replica table (Wave B PR8 / D1).

Revision ID: s9n0o1p2q3r4_replica
Revises: r8m9n0o1p2q3_audit
Create Date: 2026-05-12 00:00:00.000000

Closes audit finding D1 (Wave B PR8) from
imp/audits/2026-05-11-track-3-audit-pdp.md F-3 and
imp/audits/2026-05-11-MASTER.md.

Pre-fix posture: CLAUDE.md + ADR-008 claim "non-ripudio cross-org dal
dual-write Mastio". Federation publisher only forwarded agent records
(``federation.publish-agent``). Cross-org dispute had no second source
of truth: an assessor reading the ADR and grep-ing for the evidence
would find nothing.

Post-fix posture: each Mastio replicates its ``local_audit`` chain to
the Court via ``POST /v1/federation/audit/replicate``. Each row carries
an ECDSA signature by the Mastio's pinned leaf key. The Court stores
a verbatim copy in ``mastio_audit_replica`` (append-only via the same
trigger pattern as audit_log). On dispute, an admin queries
``/v1/admin/audit/cross-org-verify`` which compares the Court's
broker-observed audit_log row against both Mastios' replica rows and
flags any divergence.

Schema:
  * ``mastio_org_id``     — the Mastio publishing this row
  * ``chain_seq``         — Mastio's per-org local_audit chain_seq
  * ``entry_hash``        — Mastio's local_audit row hash (verbatim)
  * ``previous_hash``     — for chain continuity verification
  * ``timestamp``         — Mastio's local timestamp (ISO8601 UTC)
  * ``event_type, agent_id, session_id, details, result,
     principal_type``  — verbatim Mastio fields for content-side
     comparison
  * ``hash_format``       — 'v1' or 'v2' (inherits Mastio's choice)
  * ``signature_b64``     — ECDSA-P256 signature of the canonical
                             payload, signed by the Mastio leaf key
                             pinned in ``organizations.mastio_pubkey``
  * ``received_at``       — Court's receive timestamp (audit trail)

UNIQUE (mastio_org_id, chain_seq) — one row per Mastio chain slot,
makes the receiver idempotent under retry.

Append-only: BEFORE UPDATE OR DELETE trigger raises an error in both
Postgres and SQLite, mirroring the ``audit_log`` trigger from
PR5 (r8m9n0o1p2q3_audit).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "s9n0o1p2q3r4_replica"
down_revision: Union[str, Sequence[str], None] = "r8m9n0o1p2q3_audit"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_PG_TRIGGER_FN = """
CREATE OR REPLACE FUNCTION mastio_audit_replica_no_mutate()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'mastio_audit_replica is append-only — UPDATE/DELETE blocked'
      USING ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;
"""

_PG_TRIGGER = """
CREATE TRIGGER mastio_audit_replica_no_update_or_delete
BEFORE UPDATE OR DELETE ON mastio_audit_replica
FOR EACH ROW EXECUTE FUNCTION mastio_audit_replica_no_mutate();
"""

_SQLITE_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS mastio_audit_replica_no_update
BEFORE UPDATE ON mastio_audit_replica
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT,
        'mastio_audit_replica is append-only — UPDATE blocked');
END;
"""

_SQLITE_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS mastio_audit_replica_no_delete
BEFORE DELETE ON mastio_audit_replica
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT,
        'mastio_audit_replica is append-only — DELETE blocked');
END;
"""


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "mastio_audit_replica" not in existing:
        op.create_table(
            "mastio_audit_replica",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("mastio_org_id", sa.String(128), nullable=False),
            sa.Column("chain_seq", sa.Integer(), nullable=False),
            sa.Column("entry_hash", sa.String(64), nullable=False),
            sa.Column("previous_hash", sa.String(64), nullable=True),
            sa.Column("timestamp", sa.String(64), nullable=False),
            sa.Column("event_type", sa.String(128), nullable=False),
            sa.Column("agent_id", sa.String(256), nullable=True),
            sa.Column("session_id", sa.String(128), nullable=True),
            sa.Column("details", sa.Text(), nullable=True),
            sa.Column("result", sa.String(32), nullable=False),
            sa.Column("principal_type", sa.String(32), nullable=True),
            sa.Column("hash_format", sa.String(8), nullable=True),
            sa.Column("signature_b64", sa.Text(), nullable=False),
            sa.Column("received_at", sa.String(64), nullable=False),
            sa.UniqueConstraint(
                "mastio_org_id", "chain_seq",
                name="uq_mastio_audit_replica_org_seq",
            ),
        )
        op.create_index(
            "idx_mastio_audit_replica_org",
            "mastio_audit_replica", ["mastio_org_id"],
        )
        op.create_index(
            "idx_mastio_audit_replica_session",
            "mastio_audit_replica", ["session_id"],
        )

    # Install triggers (idempotent shape per dialect).
    is_pg = bind.dialect.name == "postgresql"
    if is_pg:
        op.execute(
            "DROP TRIGGER IF EXISTS mastio_audit_replica_no_update_or_delete "
            "ON mastio_audit_replica"
        )
        op.execute(_PG_TRIGGER_FN)
        op.execute(_PG_TRIGGER)
    else:
        op.execute(_SQLITE_UPDATE_TRIGGER)
        op.execute(_SQLITE_DELETE_TRIGGER)


def downgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"
    if is_pg:
        op.execute(
            "DROP TRIGGER IF EXISTS mastio_audit_replica_no_update_or_delete "
            "ON mastio_audit_replica"
        )
        op.execute("DROP FUNCTION IF EXISTS mastio_audit_replica_no_mutate()")
    else:
        op.execute("DROP TRIGGER IF EXISTS mastio_audit_replica_no_update")
        op.execute("DROP TRIGGER IF EXISTS mastio_audit_replica_no_delete")

    inspector = sa.inspect(bind)
    if "mastio_audit_replica" in set(inspector.get_table_names()):
        op.drop_table("mastio_audit_replica")
