"""Add the audit-anchor backlog observability index.

Revision ID: 0007_audit_anchor_observability
Revises: 0006_audit_anchor_security_gate
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_audit_anchor_observability"
down_revision = "0006_audit_anchor_security_gate"
branch_labels = None
depends_on = None

TABLE_NAME = "sentinelops_audit_anchor_outbox"
INDEX_NAME = "ix_sentinelops_audit_anchor_outbox_status_created_at"


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    indexes = {
        item["name"]: tuple(item.get("column_names") or ())
        for item in inspector.get_indexes(TABLE_NAME)
    }
    existing = indexes.get(INDEX_NAME)
    if existing is not None:
        if existing != ("status", "created_at"):
            raise RuntimeError(
                f"{INDEX_NAME} 结构不匹配：实际={existing}"
            )
        return
    op.create_index(
        INDEX_NAME,
        TABLE_NAME,
        ["status", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(INDEX_NAME, table_name=TABLE_NAME)
