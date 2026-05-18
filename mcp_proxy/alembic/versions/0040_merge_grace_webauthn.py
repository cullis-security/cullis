"""Merge agent_cert_grace + webauthn_credentials heads.

Revision ID: 0040_merge_grace_webauthn
Revises: 0039_agent_cert_grace, 0039_webauthn_credentials
Create Date: 2026-05-18 14:30:00.000000

Multi-head emerged after Wave 2 fix 7+8 (PR #790, agent leaf cert
rotation grace period) and Wave 1-E WebAuthn (PR #789, ADR-033 Phase 2
user assertion binding) both targeted ``0038_pki_key_store`` as
``down_revision`` during parallel development on 2026-05-18. Neither PR
rebased against the other before merge, so ``alembic upgrade head``
refuses with ``Multiple head revisions are present`` and the Mastio
``proxy-*-init`` container in ``sandbox/`` exits 1 at boot.

The two migrations touch disjoint schema:

* ``0039_agent_cert_grace`` adds three nullable columns
  (``previous_cert_pem``, ``previous_dpop_jkt``,
  ``previous_grace_period_expires_at``) to ``internal_agents``.
* ``0039_webauthn_credentials`` creates the new
  ``user_webauthn_credentials`` table plus indices.

Because the two upgrade DAGs commute, this is a pure structural merge:
no DDL is needed, the revision exists only to re-collapse the head set
back to a single ``0040_merge_grace_webauthn`` so downstream migrations
can resume linear numbering.
"""
from typing import Sequence, Union


revision: str = "0040_merge_grace_webauthn"
down_revision: Union[str, Sequence[str], None] = (
    "0039_agent_cert_grace",
    "0039_webauthn_credentials",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """No-op structural merge of the two 0039_* heads."""


def downgrade() -> None:
    """No-op structural merge of the two 0039_* heads."""
