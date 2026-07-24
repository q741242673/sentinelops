"""Add the persistent external-anchor security gate.

Revision ID: 0006_audit_anchor_security_gate
Revises: 0005_audit_anchor_outbox
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_audit_anchor_security_gate"
down_revision = "0005_audit_anchor_outbox"
branch_labels = None
depends_on = None

TABLE_NAME = "sentinelops_audit_anchor_security_state"
EXPECTED_COLUMNS = {
    "scope_id",
    "status",
    "generation",
    "write_blocked",
    "reason_sha256",
    "last_attempt_at",
    "last_success_at",
    "updated_at",
}


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if TABLE_NAME in inspector.get_table_names():
        actual = {
            column["name"] for column in inspector.get_columns(TABLE_NAME)
        }
        if actual != EXPECTED_COLUMNS:
            raise RuntimeError(
                f"{TABLE_NAME} 结构不匹配："
                f"应为={sorted(EXPECTED_COLUMNS)}，实际={sorted(actual)}"
            )
        primary_key = tuple(
            inspector.get_pk_constraint(TABLE_NAME).get(
                "constrained_columns"
            )
            or ()
        )
        if primary_key != ("scope_id",):
            raise RuntimeError(
                f"{TABLE_NAME} 主键不匹配：实际={primary_key}"
            )
        return
    op.create_table(
        TABLE_NAME,
        sa.Column("scope_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("write_blocked", sa.Integer(), nullable=False),
        sa.Column("reason_sha256", sa.String(length=64), nullable=True),
        sa.Column("last_attempt_at", sa.String(length=40), nullable=False),
        sa.Column("last_success_at", sa.String(length=40), nullable=True),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("scope_id"),
    )


def downgrade() -> None:
    op.drop_table(TABLE_NAME)
