"""``internal_agents`` — previous cert + dpop_jkt grace period columns.

Revision ID: 0039_agent_cert_grace
Revises: 0038_pki_key_store
Create Date: 2026-05-18 14:00:00.000000

Wave 2 fix 7+8 — agent leaf cert rotation grace period + DPoP pinning
fallback. Pre-fix, rotating ``internal_agents.cert_pem`` (re-enrollment
flow in ``mcp_proxy/enrollment/service.py``) or ``dpop_jkt`` (admin
endpoint ``POST /v1/admin/agents/{id}/dpop-jwk``) cuts mid-flight
requests instantly: any in-progress connection signed with the OLD
keypair sees a 401 ``client_cert_pin_mismatch`` (or DPoP jkt mismatch)
the moment the row flips. With agents that maintain long-lived MCP
connections or stream chat completions, that is an SLA hole.

The columns introduced here let the rotate writer stash the old
credentials before overwriting, and let the pinning verifier accept
the previous values during a bounded grace window
(``MCP_PROXY_AGENT_CERT_GRACE_PERIOD_HOURS`` default 48h). A background
cleanup task (``mcp_proxy.lifespan.agent_cert_grace_cleanup``) sweeps
expired rows and clears the previous fields so the grace surface stays
bounded.

Columns added:

* ``previous_cert_pem TEXT NULL`` — stashed x509 PEM the verifier
  falls back to on pin mismatch.
* ``previous_dpop_jkt TEXT NULL`` — stashed RFC 7638 JWK thumbprint
  the DPoP dep falls back to on jkt mismatch.
* ``previous_grace_period_expires_at TEXT NULL`` — ISO-8601 UTC. The
  fallback applies only when ``now() < this``. Stored as text to match
  the rest of the timestamp columns on this table (``created_at``,
  ``enrolled_at``) and stay portable across SQLite + Postgres without
  a TIMESTAMP-vs-TIMESTAMPTZ binding gotcha (see
  ``feedback_postgres_type_binding``).

Indexed on ``previous_grace_period_expires_at`` so the cleanup sweep
can range-scan instead of full-tabling — keeps the weekly tick cheap
even on a 10k-agent registry.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0039_agent_cert_grace"
down_revision: Union[str, Sequence[str], None] = "0038_pki_key_store"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_cols = {col["name"] for col in inspector.get_columns("internal_agents")}

    if "previous_cert_pem" not in existing_cols:
        op.add_column(
            "internal_agents",
            sa.Column("previous_cert_pem", sa.Text(), nullable=True),
        )
    if "previous_dpop_jkt" not in existing_cols:
        op.add_column(
            "internal_agents",
            sa.Column("previous_dpop_jkt", sa.Text(), nullable=True),
        )
    if "previous_grace_period_expires_at" not in existing_cols:
        op.add_column(
            "internal_agents",
            sa.Column("previous_grace_period_expires_at", sa.Text(), nullable=True),
        )

    existing_indexes = {idx["name"] for idx in inspector.get_indexes("internal_agents")}
    if "idx_internal_agents_grace_expiry" not in existing_indexes:
        op.create_index(
            "idx_internal_agents_grace_expiry",
            "internal_agents",
            ["previous_grace_period_expires_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_indexes = {idx["name"] for idx in inspector.get_indexes("internal_agents")}
    if "idx_internal_agents_grace_expiry" in existing_indexes:
        op.drop_index(
            "idx_internal_agents_grace_expiry",
            table_name="internal_agents",
        )
    existing_cols = {col["name"] for col in inspector.get_columns("internal_agents")}
    if "previous_grace_period_expires_at" in existing_cols:
        op.drop_column("internal_agents", "previous_grace_period_expires_at")
    if "previous_dpop_jkt" in existing_cols:
        op.drop_column("internal_agents", "previous_dpop_jkt")
    if "previous_cert_pem" in existing_cols:
        op.drop_column("internal_agents", "previous_cert_pem")
