"""Add the two-person audit-anchor unlock workflow.

Revision ID: 0008_anchor_unlock_workflow
Revises: 0007_audit_anchor_observability
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0008_anchor_unlock_workflow"
down_revision = "0007_audit_anchor_observability"
branch_labels = None
depends_on = None

REQUESTS_TABLE = "sentinelops_audit_anchor_unlock_requests"
DECISIONS_TABLE = "sentinelops_audit_anchor_unlock_decisions"
EPOCH_TABLE = "sentinelops_audit_anchor_inventory_epoch"


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())
    if EPOCH_TABLE not in existing_tables:
        epoch = op.create_table(
            EPOCH_TABLE,
            sa.Column("scope_id", sa.String(length=64), nullable=False),
            sa.Column("revision", sa.BigInteger(), nullable=False),
            sa.Column("updated_at", sa.String(length=40), nullable=False),
            sa.PrimaryKeyConstraint("scope_id"),
        )
        op.bulk_insert(
            epoch,
            [
                {
                    "scope_id": "external-audit-anchor",
                    "revision": 1,
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            ],
        )
    if REQUESTS_TABLE not in existing_tables:
        op.create_table(
            REQUESTS_TABLE,
            sa.Column("request_id", sa.String(length=64), nullable=False),
            sa.Column("scope_id", sa.String(length=64), nullable=False),
            sa.Column("active_scope_id", sa.String(length=64), nullable=True),
            sa.Column("blocked_generation", sa.BigInteger(), nullable=False),
            sa.Column("unlock_generation", sa.BigInteger(), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("version", sa.BigInteger(), nullable=False),
            sa.Column(
                "requester_principal_hash",
                sa.String(length=64),
                nullable=False,
            ),
            sa.Column(
                "requester_issuer_hash",
                sa.String(length=64),
                nullable=False,
            ),
            sa.Column(
                "change_ticket_sha256",
                sa.String(length=64),
                nullable=False,
            ),
            sa.Column(
                "justification_sha256",
                sa.String(length=64),
                nullable=False,
            ),
            sa.Column("created_at", sa.String(length=40), nullable=False),
            sa.Column("expires_at", sa.String(length=40), nullable=False),
            sa.Column("approved_at", sa.String(length=40), nullable=True),
            sa.Column("lease_owner", sa.String(length=200), nullable=True),
            sa.Column("lease_generation", sa.BigInteger(), nullable=False),
            sa.Column("lease_until", sa.String(length=40), nullable=True),
            sa.Column(
                "local_snapshot_hash",
                sa.String(length=64),
                nullable=True,
            ),
            sa.Column(
                "remote_snapshot_id",
                sa.String(length=64),
                nullable=True,
            ),
            sa.Column(
                "remote_snapshot_root",
                sa.String(length=64),
                nullable=True,
            ),
            sa.Column(
                "challenge_sha256",
                sa.String(length=64),
                nullable=True,
            ),
            sa.Column("attested_at", sa.String(length=40), nullable=True),
            sa.Column("completed_at", sa.String(length=40), nullable=True),
            sa.Column(
                "terminal_reason_sha256",
                sa.String(length=64),
                nullable=True,
            ),
            sa.PrimaryKeyConstraint("request_id"),
            sa.UniqueConstraint(
                "active_scope_id",
                name="uq_anchor_unlock_active_scope",
            ),
        )
        op.create_index(
            "ix_sentinelops_anchor_unlock_scope_status_expires",
            REQUESTS_TABLE,
            ["scope_id", "status", "expires_at"],
            unique=False,
        )

    existing_tables = set(sa.inspect(op.get_bind()).get_table_names())
    if DECISIONS_TABLE not in existing_tables:
        op.create_table(
            DECISIONS_TABLE,
            sa.Column("decision_id", sa.String(length=200), nullable=False),
            sa.Column("request_id", sa.String(length=64), nullable=False),
            sa.Column("request_version", sa.BigInteger(), nullable=False),
            sa.Column("principal_hash", sa.String(length=64), nullable=False),
            sa.Column("issuer_hash", sa.String(length=64), nullable=False),
            sa.Column("role", sa.String(length=24), nullable=False),
            sa.Column("decision", sa.String(length=24), nullable=False),
            sa.Column("assurance", sa.String(length=24), nullable=False),
            sa.Column("note_sha256", sa.String(length=64), nullable=False),
            sa.Column("decided_at", sa.String(length=40), nullable=False),
            sa.PrimaryKeyConstraint("decision_id"),
            sa.UniqueConstraint(
                "request_id",
                "principal_hash",
                name="uq_anchor_unlock_request_principal",
            ),
        )
        op.create_index(
            "ix_sentinelops_audit_anchor_unlock_decisions_request_id",
            DECISIONS_TABLE,
            ["request_id"],
            unique=False,
        )


def downgrade() -> None:
    op.drop_index(
        "ix_sentinelops_audit_anchor_unlock_decisions_request_id",
        table_name=DECISIONS_TABLE,
    )
    op.drop_table(DECISIONS_TABLE)
    op.drop_index(
        "ix_sentinelops_anchor_unlock_scope_status_expires",
        table_name=REQUESTS_TABLE,
    )
    op.drop_table(REQUESTS_TABLE)
    op.drop_table(EPOCH_TABLE)
