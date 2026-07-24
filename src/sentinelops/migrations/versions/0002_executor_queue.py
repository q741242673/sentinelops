"""Add Worker Lease and independent Executor queue.

Revision ID: 0002_executor_queue
Revises: 0001_durable_store
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_executor_queue"
down_revision = "0001_durable_store"
branch_labels = None
depends_on = None

EXPECTED_SCHEMA = {
    "sentinelops_worker_leases": {
        "columns": {
            "incident_id": (sa.String, 64, False),
            "owner_id": (sa.String, 200, False),
            "generation": (sa.BigInteger, None, False),
            "expires_at": (sa.String, 40, False),
            "updated_at": (sa.String, 40, False),
        },
        "primary_key": ("incident_id",),
        "unique": set(),
        "indexes": set(),
    },
    "sentinelops_action_intents": {
        "columns": {
            "idempotency_key": (sa.String, 64, False),
            "incident_id": (sa.String, 64, False),
            "lease_generation": (sa.BigInteger, None, False),
            "approval_id": (sa.String, 64, True),
            "approval_version": (sa.Integer, None, True),
            "action": (sa.JSON, None, False),
            "precondition": (sa.JSON, None, False),
            "status": (sa.String, 24, False),
            "executor_id": (sa.String, 200, True),
            "executor_generation": (sa.BigInteger, None, False),
            "executor_lease_until": (sa.String, 40, True),
            "attempt_id": (sa.String, 64, True),
            "result": (sa.JSON, None, True),
            "error": (sa.Text, None, True),
            "created_at": (sa.String, 40, False),
            "updated_at": (sa.String, 40, False),
            "queued_at": (sa.String, 40, True),
            "claimed_at": (sa.String, 40, True),
            "dispatched_at": (sa.String, 40, True),
            "finished_at": (sa.String, 40, True),
        },
        "primary_key": ("idempotency_key",),
        "unique": {("attempt_id",)},
        "indexes": {("incident_id",), ("status",)},
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
            "检测到未版本化且结构不匹配的 Executor 数据库："
            + "；".join(problems)
            + "。为避免错误重放集群操作，迁移已停止。"
        )


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())
    existing_executor_tables = existing_tables.intersection(EXPECTED_SCHEMA)
    if existing_executor_tables:
        _validate_existing_schema(inspector)
        return

    op.create_table(
        "sentinelops_worker_leases",
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("owner_id", sa.String(length=200), nullable=False),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("incident_id"),
    )
    op.create_table(
        "sentinelops_action_intents",
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("lease_generation", sa.BigInteger(), nullable=False),
        sa.Column("approval_id", sa.String(length=64), nullable=True),
        sa.Column("approval_version", sa.Integer(), nullable=True),
        sa.Column("action", sa.JSON(), nullable=False),
        sa.Column("precondition", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("executor_id", sa.String(length=200), nullable=True),
        sa.Column("executor_generation", sa.BigInteger(), nullable=False),
        sa.Column("executor_lease_until", sa.String(length=40), nullable=True),
        sa.Column("attempt_id", sa.String(length=64), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.Column("queued_at", sa.String(length=40), nullable=True),
        sa.Column("claimed_at", sa.String(length=40), nullable=True),
        sa.Column("dispatched_at", sa.String(length=40), nullable=True),
        sa.Column("finished_at", sa.String(length=40), nullable=True),
        sa.PrimaryKeyConstraint("idempotency_key"),
        sa.UniqueConstraint("attempt_id", name="uq_action_intent_attempt_id"),
    )
    op.create_index(
        "ix_sentinelops_action_intents_incident_id",
        "sentinelops_action_intents",
        ["incident_id"],
    )
    op.create_index(
        "ix_sentinelops_action_intents_status",
        "sentinelops_action_intents",
        ["status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_sentinelops_action_intents_status",
        table_name="sentinelops_action_intents",
    )
    op.drop_index(
        "ix_sentinelops_action_intents_incident_id",
        table_name="sentinelops_action_intents",
    )
    op.drop_table("sentinelops_action_intents")
    op.drop_table("sentinelops_worker_leases")
