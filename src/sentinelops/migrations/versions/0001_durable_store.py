"""Create the durable incident and approval schema.

Revision ID: 0001_durable_store
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_durable_store"
down_revision = None
branch_labels = None
depends_on = None

EXPECTED_SCHEMA = {
    "sentinelops_incidents": {
        "columns": {
            "id": (sa.String, 64, False),
            "version": (sa.BigInteger, None, False),
            "status": (sa.String, 32, False),
            "execution_profile_id": (sa.String, 160, False),
            "record": (sa.JSON, None, False),
            "graph_state": (sa.JSON, None, True),
            "created_at": (sa.String, 40, False),
            "updated_at": (sa.String, 40, False),
        },
        "primary_key": ("id",),
        "unique": set(),
        "indexes": {("status",)},
    },
    "sentinelops_incident_events": {
        "columns": {
            "id": (sa.Integer, None, False),
            "incident_id": (sa.String, 64, False),
            "sequence": (sa.Integer, None, False),
            "event_type": (sa.String, 100, False),
            "message": (sa.Text, None, False),
            "data": (sa.JSON, None, False),
            "created_at": (sa.String, 40, False),
        },
        "primary_key": ("id",),
        "unique": {("incident_id", "sequence")},
        "indexes": {("incident_id",)},
    },
    "sentinelops_approvals": {
        "columns": {
            "approval_id": (sa.String, 64, False),
            "incident_id": (sa.String, 64, False),
            "version": (sa.Integer, None, False),
            "status": (sa.String, 24, False),
            "payload": (sa.JSON, None, False),
            "expires_at": (sa.String, 40, False),
            "decided_at": (sa.String, 40, True),
            "decision_note": (sa.Text, None, False),
        },
        "primary_key": ("approval_id",),
        "unique": {("incident_id", "version")},
        "indexes": {("incident_id",)},
    },
}


def _type_matches(actual_type: sa.types.TypeEngine, expected_type: type) -> bool:
    if expected_type is sa.BigInteger:
        return isinstance(actual_type, sa.BigInteger)
    if expected_type is sa.Integer:
        return isinstance(actual_type, sa.Integer) and not isinstance(
            actual_type,
            sa.BigInteger,
        )
    if expected_type is sa.Text:
        return isinstance(actual_type, sa.Text)
    if expected_type is sa.String:
        return isinstance(actual_type, sa.String) and not isinstance(
            actual_type,
            sa.Text,
        )
    return isinstance(actual_type, expected_type)


def _validate_existing_schema(inspector: sa.Inspector) -> None:
    problems: list[str] = []
    existing_tables = set(inspector.get_table_names())
    missing_tables = set(EXPECTED_SCHEMA) - existing_tables
    if missing_tables:
        problems.append(f"缺少表={sorted(missing_tables)}")

    for table, contract in EXPECTED_SCHEMA.items():
        if table not in existing_tables:
            continue
        expected_columns = contract["columns"]
        actual_columns = {
            column["name"]: column for column in inspector.get_columns(table)
        }
        if set(actual_columns) != set(expected_columns):
            problems.append(
                f"{table} 字段应为={sorted(expected_columns)}，"
                f"实际={sorted(actual_columns)}"
            )
            continue
        for name, (type_class, length, nullable) in expected_columns.items():
            column = actual_columns[name]
            actual_type = column["type"]
            if not _type_matches(actual_type, type_class):
                problems.append(
                    f"{table}.{name} 类型应为={type_class.__name__}，"
                    f"实际={type(actual_type).__name__}"
                )
            if length is not None and getattr(actual_type, "length", None) != length:
                problems.append(
                    f"{table}.{name} 长度应为={length}，"
                    f"实际={getattr(actual_type, 'length', None)}"
                )
            if bool(column["nullable"]) is not nullable:
                problems.append(
                    f"{table}.{name} nullable 应为={nullable}，"
                    f"实际={column['nullable']}"
                )

        primary_key = tuple(
            inspector.get_pk_constraint(table).get("constrained_columns") or ()
        )
        if primary_key != contract["primary_key"]:
            problems.append(
                f"{table} 主键应为={contract['primary_key']}，实际={primary_key}"
            )
        unique_constraints = {
            tuple(item.get("column_names") or ())
            for item in inspector.get_unique_constraints(table)
        }
        if unique_constraints != contract["unique"]:
            problems.append(
                f"{table} 唯一约束应为={sorted(contract['unique'])}，"
                f"实际={sorted(unique_constraints)}"
            )
        indexes = {
            tuple(item.get("column_names") or ())
            for item in inspector.get_indexes(table)
            if not item.get("unique")
        }
        if not contract["indexes"].issubset(indexes):
            problems.append(
                f"{table} 缺少索引={sorted(contract['indexes'] - indexes)}"
            )

    if problems:
        raise RuntimeError(
            "检测到未版本化且结构不匹配的 SentinelOps 数据库："
            + "；".join(problems)
            + "。为避免破坏现有事故记录，迁移已停止。"
        )


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())
    existing_sentinel_tables = {
        table for table in existing_tables if table.startswith("sentinelops_")
    }
    if existing_sentinel_tables:
        _validate_existing_schema(inspector)
        # metadata.create_all from the pre-migration release already produced
        # the exact baseline. Returning lets Alembic stamp it without rebuilding.
        return

    op.create_table(
        "sentinelops_incidents",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("execution_profile_id", sa.String(length=160), nullable=False),
        sa.Column("record", sa.JSON(), nullable=False),
        sa.Column("graph_state", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_sentinelops_incidents_status",
        "sentinelops_incidents",
        ["status"],
    )
    op.create_table(
        "sentinelops_incident_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "incident_id",
            "sequence",
            name="uq_incident_event_sequence",
        ),
    )
    op.create_index(
        "ix_sentinelops_incident_events_incident_id",
        "sentinelops_incident_events",
        ["incident_id"],
    )
    op.create_table(
        "sentinelops_approvals",
        sa.Column("approval_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.String(length=40), nullable=False),
        sa.Column("decided_at", sa.String(length=40), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("approval_id"),
        sa.UniqueConstraint(
            "incident_id",
            "version",
            name="uq_incident_approval_version",
        ),
    )
    op.create_index(
        "ix_sentinelops_approvals_incident_id",
        "sentinelops_approvals",
        ["incident_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_sentinelops_approvals_incident_id",
        table_name="sentinelops_approvals",
    )
    op.drop_table("sentinelops_approvals")
    op.drop_index(
        "ix_sentinelops_incident_events_incident_id",
        table_name="sentinelops_incident_events",
    )
    op.drop_table("sentinelops_incident_events")
    op.drop_index(
        "ix_sentinelops_incidents_status",
        table_name="sentinelops_incidents",
    )
    op.drop_table("sentinelops_incidents")
