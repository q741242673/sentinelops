"""Add per-incident tamper-evident audit chains.

Revision ID: 0004_audit_chain
Revises: 0003_alert_bindings
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

from sentinelops.storage.audit import (
    CANONICALIZATION,
    SCHEMA_VERSION,
    audit_entry_hash,
    canonical_audit_document,
    canonical_payload_hash,
    genesis_hash,
)

revision = "0004_audit_chain"
down_revision = "0003_alert_bindings"
branch_labels = None
depends_on = None


def _audit_heads() -> sa.Table:
    return sa.table(
        "sentinelops_audit_heads",
        sa.column("incident_id", sa.String(64)),
        sa.column("last_sequence", sa.BigInteger()),
        sa.column("last_hash", sa.String(64)),
        sa.column("updated_at", sa.String(40)),
    )


def _audit_events() -> sa.Table:
    return sa.table(
        "sentinelops_audit_events",
        sa.column("incident_id", sa.String(64)),
        sa.column("sequence", sa.BigInteger()),
        sa.column("operation_id", sa.String(200)),
        sa.column("event_type", sa.String(100)),
        sa.column("source_component", sa.String(32)),
        sa.column("actor_type", sa.String(32)),
        sa.column("actor_id", sa.String(200)),
        sa.column("actor_assurance", sa.String(24)),
        sa.column("subject_type", sa.String(32)),
        sa.column("subject_id", sa.String(200)),
        sa.column("payload", sa.JSON()),
        sa.column("occurred_at", sa.String(40)),
        sa.column("committed_at", sa.String(40)),
        sa.column("previous_hash", sa.String(64)),
        sa.column("entry_hash", sa.String(64)),
        sa.column("auth_tag", sa.String(64)),
        sa.column("auth_algorithm", sa.String(24)),
        sa.column("key_id", sa.String(64)),
        sa.column("canonicalization", sa.String(24)),
        sa.column("schema_version", sa.Integer()),
    )


def _validate_existing_tables(inspector: sa.Inspector) -> None:
    expected = {
        "sentinelops_audit_heads": {
            "incident_id",
            "last_sequence",
            "last_hash",
            "updated_at",
        },
        "sentinelops_audit_events": {
            "id",
            "incident_id",
            "sequence",
            "operation_id",
            "event_type",
            "source_component",
            "actor_type",
            "actor_id",
            "actor_assurance",
            "subject_type",
            "subject_id",
            "payload",
            "occurred_at",
            "committed_at",
            "previous_hash",
            "entry_hash",
            "auth_tag",
            "auth_algorithm",
            "key_id",
            "canonicalization",
            "schema_version",
        },
    }
    for table_name, expected_columns in expected.items():
        actual = {
            column["name"] for column in inspector.get_columns(table_name)
        }
        if actual != expected_columns:
            raise RuntimeError(
                f"{table_name} 结构不匹配："
                f"应为={sorted(expected_columns)}，实际={sorted(actual)}"
            )


def _create_tables() -> None:
    op.create_table(
        "sentinelops_audit_heads",
        sa.Column("incident_id", sa.String(length=64), primary_key=True),
        sa.Column("last_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
    )
    op.create_table(
        "sentinelops_audit_events",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("operation_id", sa.String(length=200), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("source_component", sa.String(length=32), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=200), nullable=False),
        sa.Column("actor_assurance", sa.String(length=24), nullable=False),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=200), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.String(length=40), nullable=False),
        sa.Column("committed_at", sa.String(length=40), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("auth_tag", sa.String(length=64), nullable=True),
        sa.Column("auth_algorithm", sa.String(length=24), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("canonicalization", sa.String(length=24), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.UniqueConstraint(
            "incident_id",
            "sequence",
            name="uq_audit_event_sequence",
        ),
        sa.UniqueConstraint(
            "incident_id",
            "operation_id",
            name="uq_audit_event_operation",
        ),
    )
    op.create_index(
        "ix_sentinelops_audit_events_incident_id",
        "sentinelops_audit_events",
        ["incident_id"],
        unique=False,
    )


def _rows_for_incident(
    connection: sa.Connection,
    table_name: str,
    incident_id: str,
) -> list[dict[str, Any]]:
    inspector = sa.inspect(connection)
    if table_name not in inspector.get_table_names():
        return []
    table = sa.Table(table_name, sa.MetaData(), autoload_with=connection)
    if "incident_id" not in table.c:
        return []
    rows = connection.execute(
        sa.select(table).where(table.c.incident_id == incident_id)
    ).mappings()
    return [dict(row) for row in rows]


def _backfill_checkpoints(connection: sa.Connection) -> None:
    inspector = sa.inspect(connection)
    if "sentinelops_incidents" not in inspector.get_table_names():
        return
    incidents = sa.Table(
        "sentinelops_incidents",
        sa.MetaData(),
        autoload_with=connection,
    )
    heads = _audit_heads()
    events = _audit_events()
    existing_heads = set(
        connection.execute(sa.select(heads.c.incident_id)).scalars()
    )
    for row in connection.execute(sa.select(incidents)).mappings():
        incident_id = row["id"]
        if incident_id in existing_heads:
            continue
        approvals = _rows_for_incident(
            connection,
            "sentinelops_approvals",
            incident_id,
        )
        actions = _rows_for_incident(
            connection,
            "sentinelops_action_intents",
            incident_id,
        )
        payload = {
            "source": "migration_checkpoint",
            "historical_transitions_verified": False,
            "incident_version": int(row["version"]),
            "incident_record_sha256": canonical_payload_hash(row["record"]),
            "graph_state_sha256": canonical_payload_hash(row["graph_state"]),
            "approvals_sha256": canonical_payload_hash(approvals),
            "action_intents_sha256": canonical_payload_hash(actions),
        }
        occurred_at = row["updated_at"]
        previous_hash = genesis_hash(incident_id)
        operation_id = f"migration:{incident_id}:checkpoint:0004"
        document = canonical_audit_document(
            incident_id=incident_id,
            sequence=1,
            operation_id=operation_id,
            event_type="legacy.migration_checkpoint",
            source_component="migration",
            actor_type="system",
            actor_id="alembic-0004",
            actor_assurance="migration",
            subject_type="incident",
            subject_id=incident_id,
            payload=payload,
            occurred_at=occurred_at,
            committed_at=occurred_at,
            previous_hash=previous_hash,
            auth_algorithm="none",
            key_id="migration-unkeyed",
        )
        entry_hash = audit_entry_hash(document)
        connection.execute(
            sa.insert(events).values(
                incident_id=incident_id,
                sequence=1,
                operation_id=operation_id,
                event_type="legacy.migration_checkpoint",
                source_component="migration",
                actor_type="system",
                actor_id="alembic-0004",
                actor_assurance="migration",
                subject_type="incident",
                subject_id=incident_id,
                payload=payload,
                occurred_at=occurred_at,
                committed_at=occurred_at,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                auth_tag=None,
                auth_algorithm="none",
                key_id="migration-unkeyed",
                canonicalization=CANONICALIZATION,
                schema_version=SCHEMA_VERSION,
            )
        )
        connection.execute(
            sa.insert(heads).values(
                incident_id=incident_id,
                last_sequence=1,
                last_hash=entry_hash,
                updated_at=occurred_at,
            )
        )


def upgrade() -> None:
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    existing = set(inspector.get_table_names())
    audit_table_names = {
        "sentinelops_audit_heads",
        "sentinelops_audit_events",
    }
    present = existing.intersection(audit_table_names)
    if present and present != audit_table_names:
        raise RuntimeError(
            "审计表只存在一部分，拒绝猜测性迁移："
            f"{sorted(present)}"
        )
    if not present:
        _create_tables()
    else:
        _validate_existing_tables(sa.inspect(connection))
    _backfill_checkpoints(connection)


def downgrade() -> None:
    op.drop_index(
        "ix_sentinelops_audit_events_incident_id",
        table_name="sentinelops_audit_events",
    )
    op.drop_table("sentinelops_audit_events")
    op.drop_table("sentinelops_audit_heads")
