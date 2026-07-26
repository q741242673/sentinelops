"""Add the fenced Controller outcome reconciliation outbox.

Revision ID: 0010_action_reconcile_outbox
Revises: 0009_gitops_proposal_outbox
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_action_reconcile_outbox"
down_revision = "0009_gitops_proposal_outbox"
branch_labels = None
depends_on = None

TABLE = "sentinelops_action_reconciliation_outbox"
ACTION_TABLE = "sentinelops_action_intents"
EXPECTED_COLUMNS = {
    "action_id": (sa.String, 64, False),
    "status": (sa.String, 24, False),
    "attempt_count": (sa.Integer, None, False),
    "next_attempt_at": (sa.String, 40, False),
    "claimed_by": (sa.String, 200, True),
    "claim_generation": (sa.BigInteger, None, False),
    "attempt_id": (sa.String, 64, True),
    "claim_until": (sa.String, 40, True),
    "last_error_sha256": (sa.String, 64, True),
    "created_at": (sa.String, 40, False),
    "updated_at": (sa.String, 40, False),
}


def _type_matches(actual: sa.types.TypeEngine, expected: type) -> bool:
    if expected is sa.BigInteger:
        return isinstance(actual, sa.BigInteger)
    if expected is sa.Integer:
        return isinstance(actual, sa.Integer) and not isinstance(
            actual,
            sa.BigInteger,
        )
    return isinstance(actual, expected)


def _validate_existing_schema(inspector: sa.Inspector) -> None:
    problems: list[str] = []
    actual_columns = {
        column["name"]: column
        for column in inspector.get_columns(TABLE)
    }
    if set(actual_columns) != set(EXPECTED_COLUMNS):
        problems.append(
            f"字段应为={sorted(EXPECTED_COLUMNS)}，"
            f"实际={sorted(actual_columns)}"
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
            if (
                length is not None
                and getattr(actual_type, "length", None) != length
            ):
                problems.append(
                    f"{name} 长度应为={length}，"
                    f"实际={getattr(actual_type, 'length', None)}"
                )
            if bool(column["nullable"]) is not nullable:
                problems.append(
                    f"{name} nullable 应为={nullable}，"
                    f"实际={column['nullable']}"
                )
    primary_key = tuple(
        inspector.get_pk_constraint(TABLE).get("constrained_columns") or ()
    )
    if primary_key != ("action_id",):
        problems.append(f"主键应为=('action_id',)，实际={primary_key}")
    unique_constraints = {
        tuple(item.get("column_names") or ())
        for item in inspector.get_unique_constraints(TABLE)
    }
    if ("attempt_id",) not in unique_constraints:
        problems.append("缺少 attempt_id 唯一约束")
    indexes = {
        tuple(item.get("column_names") or ())
        for item in inspector.get_indexes(TABLE)
        if not item.get("unique")
    }
    required_indexes = {("status",), ("status", "next_attempt_at")}
    if not required_indexes.issubset(indexes):
        problems.append(
            f"缺少索引={sorted(required_indexes - indexes)}"
        )
    if problems:
        raise RuntimeError(
            "检测到结构不匹配的 Controller 对账表："
            + "；".join(problems)
            + "。为避免错误收口未知集群写入，迁移已停止。"
        )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                f"LOCK TABLE {ACTION_TABLE} IN SHARE ROW EXCLUSIVE MODE"
            )
        )
    inspector = sa.inspect(bind)
    if TABLE not in set(inspector.get_table_names()):
        op.create_table(
            TABLE,
            sa.Column("action_id", sa.String(length=64), nullable=False),
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
            sa.PrimaryKeyConstraint("action_id"),
            sa.UniqueConstraint(
                "attempt_id",
                name="uq_sentinelops_action_reconciliation_attempt",
            ),
        )
        op.create_index(
            "ix_sentinelops_action_reconciliation_outbox_status",
            TABLE,
            ["status"],
            unique=False,
        )
        op.create_index(
            "ix_sentinelops_action_reconciliation_status_next_attempt",
            TABLE,
            ["status", "next_attempt_at"],
            unique=False,
        )
    else:
        _validate_existing_schema(inspector)
    op.execute(
        sa.text(
            f"""
            INSERT INTO {TABLE} (
                action_id,
                status,
                attempt_count,
                next_attempt_at,
                claimed_by,
                claim_generation,
                attempt_id,
                claim_until,
                last_error_sha256,
                created_at,
                updated_at
            )
            SELECT
                idempotency_key,
                'pending',
                0,
                COALESCE(executor_lease_until, updated_at),
                NULL,
                0,
                NULL,
                NULL,
                NULL,
                created_at,
                updated_at
            FROM {ACTION_TABLE}
            WHERE status IN ('dispatched', 'unknown')
              AND NOT EXISTS (
                  SELECT 1
                  FROM {TABLE} existing
                  WHERE existing.action_id = {ACTION_TABLE}.idempotency_key
              )
            """
        )
    )
    orphaned = bind.execute(
        sa.text(
            f"""
            SELECT COUNT(*)
            FROM {ACTION_TABLE} action
            LEFT JOIN {TABLE} outbox
              ON outbox.action_id = action.idempotency_key
            WHERE action.status IN ('dispatched', 'unknown')
              AND outbox.action_id IS NULL
            """
        )
    ).scalar_one()
    if int(orphaned) != 0:
        raise RuntimeError(
            "迁移后仍有 dispatched/unknown Action Intent 缺少对账任务，"
            "为避免遗漏未知写入，迁移已停止"
        )


def downgrade() -> None:
    op.drop_index(
        "ix_sentinelops_action_reconciliation_status_next_attempt",
        table_name=TABLE,
    )
    op.drop_index(
        "ix_sentinelops_action_reconciliation_outbox_status",
        table_name=TABLE,
    )
    op.drop_table(TABLE)
