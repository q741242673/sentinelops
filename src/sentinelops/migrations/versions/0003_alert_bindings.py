"""Add database-arbitrated Alertmanager fingerprint bindings.

Revision ID: 0003_alert_bindings
Revises: 0002_executor_queue
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_alert_bindings"
down_revision = "0002_executor_queue"
branch_labels = None
depends_on = None

EXPECTED_COLUMNS = {
    "source_id": (sa.String, 128, False),
    "fingerprint": (sa.String, 128, False),
    "incident_id": (sa.String, 64, True),
    "status": (sa.String, 16, False),
    "generation": (sa.BigInteger, None, False),
    "version": (sa.BigInteger, None, False),
    "starts_at": (sa.String, 40, True),
    "resolved_at": (sa.String, 40, True),
    "created_at": (sa.String, 40, False),
    "updated_at": (sa.String, 40, False),
}


def _type_matches(actual_type: sa.types.TypeEngine, expected_type: type) -> bool:
    if expected_type is sa.BigInteger:
        return isinstance(actual_type, sa.BigInteger)
    if expected_type is sa.String:
        return isinstance(actual_type, sa.String) and not isinstance(
            actual_type,
            sa.Text,
        )
    return isinstance(actual_type, expected_type)


def _validate_existing_schema(inspector: sa.Inspector) -> None:
    table = "sentinelops_alert_bindings"
    actual_columns = {
        column["name"]: column for column in inspector.get_columns(table)
    }
    problems: list[str] = []
    if set(actual_columns) != set(EXPECTED_COLUMNS):
        problems.append(
            f"字段应为={sorted(EXPECTED_COLUMNS)}，实际={sorted(actual_columns)}"
        )
    else:
        for name, (type_class, length, nullable) in EXPECTED_COLUMNS.items():
            column = actual_columns[name]
            actual_type = column["type"]
            if not _type_matches(actual_type, type_class):
                problems.append(
                    f"{name} 类型应为={type_class.__name__}，"
                    f"实际={type(actual_type).__name__}"
                )
            if length is not None and getattr(actual_type, "length", None) != length:
                problems.append(
                    f"{name} 长度应为={length}，"
                    f"实际={getattr(actual_type, 'length', None)}"
                )
            if bool(column["nullable"]) is not nullable:
                problems.append(
                    f"{name} nullable 应为={nullable}，实际={column['nullable']}"
                )

    primary_key = tuple(
        inspector.get_pk_constraint(table).get("constrained_columns") or ()
    )
    if primary_key != ("source_id", "fingerprint"):
        problems.append(
            "主键应为=('source_id', 'fingerprint')，"
            f"实际={primary_key}"
        )
    unique_constraints = {
        tuple(item.get("column_names") or ())
        for item in inspector.get_unique_constraints(table)
    }
    if unique_constraints != {("incident_id",)}:
        problems.append(
            "唯一约束应为=[('incident_id',)]，"
            f"实际={sorted(unique_constraints)}"
        )
    indexes = {
        tuple(item.get("column_names") or ())
        for item in inspector.get_indexes(table)
        if not item.get("unique")
    }
    if ("status",) not in indexes:
        problems.append("缺少 status 索引")
    if problems:
        raise RuntimeError(
            "检测到未版本化且结构不匹配的 Alertmanager 去重表："
            + "；".join(problems)
            + "。为避免重复创建事故，迁移已停止。"
        )


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "sentinelops_alert_bindings" in inspector.get_table_names():
        _validate_existing_schema(inspector)
        return

    op.create_table(
        "sentinelops_alert_bindings",
        sa.Column("source_id", sa.String(length=128), nullable=False),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("starts_at", sa.String(length=40), nullable=True),
        sa.Column("resolved_at", sa.String(length=40), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("source_id", "fingerprint"),
        sa.UniqueConstraint("incident_id", name="uq_alert_binding_incident_id"),
    )
    op.create_index(
        "ix_sentinelops_alert_bindings_status",
        "sentinelops_alert_bindings",
        ["status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_sentinelops_alert_bindings_status",
        table_name="sentinelops_alert_bindings",
    )
    op.drop_table("sentinelops_alert_bindings")
