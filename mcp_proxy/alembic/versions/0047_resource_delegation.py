"""Persist mandatory delegation independently of editable operator policies."""
from alembic import op
import sqlalchemy as sa

revision = "0047_resource_delegation"
down_revision = "0046_agent_llm_budgets"
branch_labels = None
depends_on = None


def upgrade():
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("local_mcp_resources")}
    if "requires_delegation" not in columns:
        op.add_column("local_mcp_resources", sa.Column(
            "requires_delegation", sa.Integer(), nullable=False, server_default="0",
        ))


def downgrade():
    op.drop_column("local_mcp_resources", "requires_delegation")
