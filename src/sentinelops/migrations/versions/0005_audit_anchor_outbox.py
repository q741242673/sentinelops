"""Add the durable external audit-anchor outbox.

Revision ID: 0005_audit_anchor_outbox
Revises: 0004_audit_chain
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from sentinelops.storage.anchor import anchor_id

revision = "0005_audit_anchor_outbox"
down_revision = "0004_audit_chain"
branch_labels = None
depends_on = None

TABLE_NAME = "sentinelops_audit_anchor_outbox"
EXPECTED_COLUMNS = {
    "anchor_id",
    "incident_id",
    "sequence",
    "head_hash",
    "previous_anchor_id",
    "audit_key_id",
    "audit_auth_algorithm",
    "audit_auth_tag",
    "audit_committed_at",
    "status",
    "attempt_count",
    "next_attempt_at",
    "claimed_by",
    "claim_generation",
    "attempt_id",
    "claim_until",
    "last_error_sha256",
    "receipt",
    "created_at",
    "updated_at",
    "delivered_at",
}


def _validate_existing_table(inspector: sa.Inspector) -> None:
    actual_columns = {
        column["name"] for column in inspector.get_columns(TABLE_NAME)
    }
    if actual_columns != EXPECTED_COLUMNS:
        raise RuntimeError(
            f"{TABLE_NAME} 结构不匹配："
            f"应为={sorted(EXPECTED_COLUMNS)}，实际={sorted(actual_columns)}"
        )
    primary_key = tuple(
        inspector.get_pk_constraint(TABLE_NAME).get("constrained_columns") or ()
    )
    if primary_key != ("anchor_id",):
        raise RuntimeError(
            f"{TABLE_NAME} 主键不匹配：实际={primary_key}"
        )
    unique_constraints = {
        tuple(item.get("column_names") or ())
        for item in inspector.get_unique_constraints(TABLE_NAME)
    }
    required_unique = {("attempt_id",), ("incident_id", "sequence")}
    if not required_unique.issubset(unique_constraints):
        raise RuntimeError(
            f"{TABLE_NAME} 缺少唯一约束："
            f"{sorted(required_unique - unique_constraints)}"
        )
    indexes = {
        tuple(item.get("column_names") or ())
        for item in inspector.get_indexes(TABLE_NAME)
        if not item.get("unique")
    }
    required_indexes = {("incident_id",), ("status",)}
    if not required_indexes.issubset(indexes):
        raise RuntimeError(
            f"{TABLE_NAME} 缺少索引："
            f"{sorted(required_indexes - indexes)}"
        )


def _create_table() -> None:
    op.create_table(
        TABLE_NAME,
        sa.Column("anchor_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("head_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_anchor_id", sa.String(length=64), nullable=True),
        sa.Column("audit_key_id", sa.String(length=64), nullable=False),
        sa.Column("audit_auth_algorithm", sa.String(length=24), nullable=False),
        sa.Column("audit_auth_tag", sa.String(length=64), nullable=True),
        sa.Column("audit_committed_at", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.String(length=40), nullable=False),
        sa.Column("claimed_by", sa.String(length=200), nullable=True),
        sa.Column("claim_generation", sa.BigInteger(), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=True),
        sa.Column("claim_until", sa.String(length=40), nullable=True),
        sa.Column("last_error_sha256", sa.String(length=64), nullable=True),
        sa.Column("receipt", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.Column("delivered_at", sa.String(length=40), nullable=True),
        sa.PrimaryKeyConstraint("anchor_id"),
        sa.UniqueConstraint(
            "incident_id",
            "sequence",
            name="uq_audit_anchor_incident_sequence",
        ),
        sa.UniqueConstraint(
            "attempt_id",
            name="uq_audit_anchor_attempt_id",
        ),
    )
    op.create_index(
        "ix_sentinelops_audit_anchor_outbox_incident_id",
        TABLE_NAME,
        ["incident_id"],
    )
    op.create_index(
        "ix_sentinelops_audit_anchor_outbox_status",
        TABLE_NAME,
        ["status"],
    )


def _backfill_current_heads(connection: sa.Connection) -> None:
    metadata = sa.MetaData()
    heads = sa.Table(
        "sentinelops_audit_heads",
        metadata,
        autoload_with=connection,
    )
    events = sa.Table(
        "sentinelops_audit_events",
        metadata,
        autoload_with=connection,
    )
    outbox = sa.Table(TABLE_NAME, metadata, autoload_with=connection)
    existing = set(
        connection.execute(sa.select(outbox.c.anchor_id)).scalars()
    )
    for head in connection.execute(sa.select(heads)).mappings():
        incident_id = str(head["incident_id"])
        sequence = int(head["last_sequence"])
        head_hash = str(head["last_hash"])
        identifier = anchor_id(incident_id, sequence, head_hash)
        if identifier in existing:
            continue
        event = connection.execute(
            sa.select(events).where(
                events.c.incident_id == incident_id,
                events.c.sequence == sequence,
            )
        ).mappings().one()
        committed_at = str(event["committed_at"])
        connection.execute(
            sa.insert(outbox).values(
                anchor_id=identifier,
                incident_id=incident_id,
                sequence=sequence,
                head_hash=head_hash,
                # Existing chains start as one externally anchored checkpoint.
                previous_anchor_id=None,
                audit_key_id=event["key_id"],
                audit_auth_algorithm=event["auth_algorithm"],
                audit_auth_tag=event["auth_tag"],
                audit_committed_at=committed_at,
                status="pending",
                attempt_count=0,
                next_attempt_at="1970-01-01T00:00:00+00:00",
                claimed_by=None,
                claim_generation=0,
                attempt_id=None,
                claim_until=None,
                last_error_sha256=None,
                receipt=None,
                created_at=committed_at,
                updated_at=committed_at,
                delivered_at=None,
            )
        )


def upgrade() -> None:
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    if TABLE_NAME in inspector.get_table_names():
        _validate_existing_table(inspector)
    else:
        _create_table()
    _backfill_current_heads(connection)


def downgrade() -> None:
    op.drop_index(
        "ix_sentinelops_audit_anchor_outbox_status",
        table_name=TABLE_NAME,
    )
    op.drop_index(
        "ix_sentinelops_audit_anchor_outbox_incident_id",
        table_name=TABLE_NAME,
    )
    op.drop_table(TABLE_NAME)
