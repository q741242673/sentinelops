"""Add immutable change proposals and the GitOps delivery outbox.

Revision ID: 0009_gitops_proposal_outbox
Revises: 0008_anchor_unlock_workflow
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_gitops_proposal_outbox"
down_revision = "0008_anchor_unlock_workflow"
branch_labels = None
depends_on = None

PROPOSALS_TABLE = "sentinelops_change_proposals"
OUTBOX_TABLE = "sentinelops_gitops_proposal_outbox"


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())
    if PROPOSALS_TABLE not in existing_tables:
        op.create_table(
            PROPOSALS_TABLE,
            sa.Column("proposal_id", sa.String(length=64), nullable=False),
            sa.Column(
                "proposal_digest",
                sa.String(length=64),
                nullable=False,
            ),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("version", sa.BigInteger(), nullable=False),
            sa.Column("preview", sa.JSON(), nullable=False),
            sa.Column("submitted_by", sa.String(length=200), nullable=False),
            sa.Column(
                "submitted_assurance",
                sa.String(length=24),
                nullable=False,
            ),
            sa.Column("created_at", sa.String(length=40), nullable=False),
            sa.Column("updated_at", sa.String(length=40), nullable=False),
            sa.Column("published_at", sa.String(length=40), nullable=True),
            sa.Column("receipt", sa.JSON(), nullable=True),
            sa.PrimaryKeyConstraint("proposal_id"),
            sa.UniqueConstraint(
                "proposal_digest",
                name="uq_sentinelops_change_proposal_digest",
            ),
        )
        op.create_index(
            "ix_sentinelops_change_proposals_incident_id",
            PROPOSALS_TABLE,
            ["incident_id"],
            unique=False,
        )
        op.create_index(
            "ix_sentinelops_change_proposals_status",
            PROPOSALS_TABLE,
            ["status"],
            unique=False,
        )
    existing_tables = set(sa.inspect(op.get_bind()).get_table_names())
    if OUTBOX_TABLE not in existing_tables:
        op.create_table(
            OUTBOX_TABLE,
            sa.Column("proposal_id", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("attempt_count", sa.Integer(), nullable=False),
            sa.Column("next_attempt_at", sa.String(length=40), nullable=False),
            sa.Column("claimed_by", sa.String(length=200), nullable=True),
            sa.Column("claim_generation", sa.BigInteger(), nullable=False),
            sa.Column("attempt_id", sa.String(length=64), nullable=True),
            sa.Column("claim_until", sa.String(length=40), nullable=True),
            sa.Column(
                "last_error_sha256",
                sa.String(length=64),
                nullable=True,
            ),
            sa.Column("created_at", sa.String(length=40), nullable=False),
            sa.Column("updated_at", sa.String(length=40), nullable=False),
            sa.PrimaryKeyConstraint("proposal_id"),
            sa.UniqueConstraint(
                "attempt_id",
                name="uq_sentinelops_gitops_outbox_attempt",
            ),
        )
        op.create_index(
            "ix_sentinelops_gitops_outbox_status",
            OUTBOX_TABLE,
            ["status"],
            unique=False,
        )
        op.create_index(
            "ix_sentinelops_gitops_outbox_status_next_attempt",
            OUTBOX_TABLE,
            ["status", "next_attempt_at"],
            unique=False,
        )


def downgrade() -> None:
    op.drop_index(
        "ix_sentinelops_gitops_outbox_status_next_attempt",
        table_name=OUTBOX_TABLE,
    )
    op.drop_index(
        "ix_sentinelops_gitops_outbox_status",
        table_name=OUTBOX_TABLE,
    )
    op.drop_table(OUTBOX_TABLE)
    op.drop_index(
        "ix_sentinelops_change_proposals_status",
        table_name=PROPOSALS_TABLE,
    )
    op.drop_index(
        "ix_sentinelops_change_proposals_incident_id",
        table_name=PROPOSALS_TABLE,
    )
    op.drop_table(PROPOSALS_TABLE)
