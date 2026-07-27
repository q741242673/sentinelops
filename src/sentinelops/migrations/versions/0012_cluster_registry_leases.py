"""Add durable cluster registrations and fenced agent leases.

Revision ID: 0012_cluster_registry_leases
Revises: 0011_cluster_routing_fence
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012_cluster_registry_leases"
down_revision = "0011_cluster_routing_fence"
branch_labels = None
depends_on = None

REGISTRATIONS = "sentinelops_cluster_registrations"
AGENT_LEASES = "sentinelops_cluster_agent_leases"
INCIDENTS = "sentinelops_incidents"
ACTIONS = "sentinelops_action_intents"
MIGRATION_REASON = (
    "cluster agent lease migration invalidated an action without a registered execution session"
)
EXPECTED_REGISTRATION_COLUMNS = {
    "cluster_id": (sa.String, 63, False),
    "display_name": (sa.String, 128, False),
    "default_namespace": (sa.String, 253, False),
    "routing_generation": (sa.BigInteger, None, False),
    "lifecycle": (sa.String, 24, False),
    "metadata_state": (sa.String, 16, False),
    "created_at": (sa.String, 40, False),
    "updated_at": (sa.String, 40, False),
}
EXPECTED_AGENT_COLUMNS = {
    "cluster_id": (sa.String, 63, False),
    "instance_id": (sa.String, 200, False),
    "session_id": (sa.String, 64, False),
    "generation": (sa.BigInteger, None, False),
    "routing_generation": (sa.BigInteger, None, False),
    "capabilities": (sa.JSON, None, False),
    "version": (sa.String, 128, False),
    "registered_at": (sa.String, 40, False),
    "last_seen_at": (sa.String, 40, False),
    "lease_until": (sa.String, 40, False),
    "status": (sa.String, 16, False),
    "updated_at": (sa.String, 40, False),
}
EXPECTED_ACTION_COLUMNS = {
    "cluster_generation": (sa.BigInteger, None, False),
    "executor_session_id": (sa.String, 64, True),
    "executor_session_generation": (sa.BigInteger, None, True),
}


def _type_matches(actual: sa.types.TypeEngine, expected: type) -> bool:
    if expected is sa.BigInteger:
        return isinstance(actual, sa.BigInteger)
    return isinstance(actual, expected)


def _validate_columns(
    inspector: sa.Inspector,
    table: str,
    expected: dict[str, tuple[type, int | None, bool]],
    *,
    exact: bool,
) -> list[str]:
    actual = {column["name"]: column for column in inspector.get_columns(table)}
    problems: list[str] = []
    if (exact and set(actual) != set(expected)) or not set(expected).issubset(actual):
        problems.append(f"{table} 字段应为={sorted(expected)}，实际={sorted(actual)}")
        return problems
    for name, (type_class, length, nullable) in expected.items():
        column = actual[name]
        actual_type = column["type"]
        if (
            not _type_matches(actual_type, type_class)
            or (length is not None and getattr(actual_type, "length", None) != length)
            or bool(column["nullable"]) is not nullable
        ):
            problems.append(f"{table}.{name} 结构不匹配")
    return problems


def _adopt_current_schema_if_complete(
    inspector: sa.Inspector,
) -> bool:
    tables = set(inspector.get_table_names())
    action_columns = {column["name"] for column in inspector.get_columns(ACTIONS)}
    forward_action_columns = set(EXPECTED_ACTION_COLUMNS)
    has_forward_state = bool(
        {REGISTRATIONS, AGENT_LEASES}.intersection(tables)
        or forward_action_columns.intersection(action_columns)
    )
    if not has_forward_state:
        return False
    problems: list[str] = []
    if not {REGISTRATIONS, AGENT_LEASES}.issubset(tables):
        problems.append("缺少完整的集群注册表或 Agent 租约表")
    else:
        problems.extend(
            _validate_columns(
                inspector,
                REGISTRATIONS,
                EXPECTED_REGISTRATION_COLUMNS,
                exact=True,
            )
        )
        problems.extend(
            _validate_columns(
                inspector,
                AGENT_LEASES,
                EXPECTED_AGENT_COLUMNS,
                exact=True,
            )
        )
        if tuple(inspector.get_pk_constraint(REGISTRATIONS).get("constrained_columns") or ()) != (
            "cluster_id",
        ):
            problems.append("集群注册表主键不匹配")
        if tuple(inspector.get_pk_constraint(AGENT_LEASES).get("constrained_columns") or ()) != (
            "cluster_id",
            "instance_id",
        ):
            problems.append("Agent 租约表主键不匹配")
        unique = {
            tuple(item.get("column_names") or ())
            for item in inspector.get_unique_constraints(AGENT_LEASES)
        }
        if ("session_id",) not in unique:
            problems.append("Agent 租约表缺少 session_id 唯一约束")
        foreign_keys = inspector.get_foreign_keys(AGENT_LEASES)
        if not any(
            tuple(item.get("constrained_columns") or ()) == ("cluster_id",)
            and item.get("referred_table") == REGISTRATIONS
            and tuple(item.get("referred_columns") or ()) == ("cluster_id",)
            for item in foreign_keys
        ):
            problems.append("Agent 租约表缺少集群注册外键")
        registration_indexes = {
            tuple(item.get("column_names") or ())
            for item in inspector.get_indexes(REGISTRATIONS)
            if not item.get("unique")
        }
        agent_indexes = {
            tuple(item.get("column_names") or ())
            for item in inspector.get_indexes(AGENT_LEASES)
            if not item.get("unique")
        }
        if ("lifecycle",) not in registration_indexes:
            problems.append("集群注册表缺少 lifecycle 索引")
        required_agent_indexes = {
            ("status",),
            ("cluster_id", "status", "lease_until"),
            ("status", "lease_until"),
        }
        if not required_agent_indexes.issubset(agent_indexes):
            problems.append("Agent 租约表缺少必要索引")
    problems.extend(
        _validate_columns(
            inspector,
            ACTIONS,
            EXPECTED_ACTION_COLUMNS,
            exact=False,
        )
    )
    if problems:
        raise RuntimeError(
            "检测到结构不匹配的集群注册数据库："
            + "；".join(problems)
            + "。为避免旧 Session 越过执行围栏，迁移已停止。"
        )
    return True


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _adopt_current_schema_if_complete(inspector):
        return
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text(f"LOCK TABLE {INCIDENTS}, {ACTIONS} IN SHARE ROW EXCLUSIVE MODE"))

    op.create_table(
        REGISTRATIONS,
        sa.Column("cluster_id", sa.String(length=63), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column(
            "default_namespace",
            sa.String(length=253),
            nullable=False,
        ),
        sa.Column("routing_generation", sa.BigInteger(), nullable=False),
        sa.Column("lifecycle", sa.String(length=24), nullable=False),
        sa.Column("metadata_state", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("cluster_id"),
    )
    op.create_index(
        "ix_sentinelops_cluster_registrations_lifecycle",
        REGISTRATIONS,
        ["lifecycle"],
        unique=False,
    )
    op.create_table(
        AGENT_LEASES,
        sa.Column("cluster_id", sa.String(length=63), nullable=False),
        sa.Column("instance_id", sa.String(length=200), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("routing_generation", sa.BigInteger(), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("registered_at", sa.String(length=40), nullable=False),
        sa.Column("last_seen_at", sa.String(length=40), nullable=False),
        sa.Column("lease_until", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("cluster_id", "instance_id"),
        sa.UniqueConstraint(
            "session_id",
            name="uq_sentinelops_cluster_agent_session",
        ),
        sa.ForeignKeyConstraint(
            ["cluster_id"],
            [f"{REGISTRATIONS}.cluster_id"],
            name="fk_sentinelops_cluster_agent_registration",
        ),
    )
    op.create_index(
        "ix_sentinelops_cluster_agent_leases_status",
        AGENT_LEASES,
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_sentinelops_cluster_agent_cluster_status_lease",
        AGENT_LEASES,
        ["cluster_id", "status", "lease_until"],
        unique=False,
    )
    op.create_index(
        "ix_sentinelops_cluster_agent_status_lease",
        AGENT_LEASES,
        ["status", "lease_until"],
        unique=False,
    )

    with op.batch_alter_table(ACTIONS) as batch:
        batch.add_column(
            sa.Column(
                "cluster_generation",
                sa.BigInteger(),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "executor_session_id",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "executor_session_generation",
                sa.BigInteger(),
                nullable=True,
            )
        )

    now = bind.execute(sa.select(sa.func.current_timestamp())).scalar_one()
    now_text = now.isoformat() if hasattr(now, "isoformat") else str(now)
    cluster_ids = list(
        bind.execute(
            sa.text(
                f"""
                SELECT DISTINCT cluster_id
                FROM (
                    SELECT cluster_id FROM {INCIDENTS}
                    UNION
                    SELECT cluster_id FROM {ACTIONS}
                ) durable_clusters
                ORDER BY cluster_id
                """
            )
        ).scalars()
    )
    for cluster_id in cluster_ids:
        bind.execute(
            sa.text(
                f"""
                INSERT INTO {REGISTRATIONS} (
                    cluster_id,
                    display_name,
                    default_namespace,
                    routing_generation,
                    lifecycle,
                    metadata_state,
                    created_at,
                    updated_at
                ) VALUES (
                    :cluster_id,
                    :display_name,
                    :default_namespace,
                    1,
                    'active',
                    'inferred',
                    :created_at,
                    :updated_at
                )
                """
            ),
            {
                "cluster_id": cluster_id,
                "display_name": cluster_id,
                "default_namespace": "default",
                "created_at": now_text,
                "updated_at": now_text,
            },
        )

    action_table = sa.table(
        ACTIONS,
        sa.column("cluster_generation", sa.BigInteger()),
        sa.column("status", sa.String(length=24)),
        sa.column("error", sa.Text()),
        sa.column("executor_id", sa.String(length=200)),
        sa.column("executor_lease_until", sa.String(length=40)),
        sa.column("attempt_id", sa.String(length=64)),
        sa.column("executor_session_id", sa.String(length=64)),
        sa.column("executor_session_generation", sa.BigInteger()),
        sa.column("finished_at", sa.String(length=40)),
        sa.column("updated_at", sa.String(length=40)),
    )
    bind.execute(sa.update(action_table).values(cluster_generation=1))
    bind.execute(
        sa.update(action_table)
        .where(action_table.c.status.in_(["prepared", "queued", "claimed"]))
        .values(
            status="cancelled",
            error=MIGRATION_REASON,
            executor_id=None,
            executor_lease_until=None,
            attempt_id=None,
            executor_session_id=None,
            executor_session_generation=None,
            finished_at=sa.func.coalesce(
                action_table.c.finished_at,
                action_table.c.updated_at,
            ),
        )
    )
    bind.execute(
        sa.update(action_table)
        .where(action_table.c.status == "dispatched")
        .values(
            status="unknown",
            error=MIGRATION_REASON,
            executor_session_id=None,
            executor_session_generation=None,
            finished_at=sa.func.coalesce(
                action_table.c.finished_at,
                action_table.c.updated_at,
            ),
        )
    )
    missing_generation = bind.execute(
        sa.text(f"SELECT COUNT(*) FROM {ACTIONS} WHERE cluster_generation IS NULL")
    ).scalar_one()
    if int(missing_generation) != 0:
        raise RuntimeError("cluster_generation 回填不完整，迁移已停止")
    with op.batch_alter_table(ACTIONS) as batch:
        batch.alter_column(
            "cluster_generation",
            existing_type=sa.BigInteger(),
            nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table(ACTIONS) as batch:
        batch.drop_column("executor_session_generation")
        batch.drop_column("executor_session_id")
        batch.drop_column("cluster_generation")
    op.drop_index(
        "ix_sentinelops_cluster_agent_status_lease",
        table_name=AGENT_LEASES,
    )
    op.drop_index(
        "ix_sentinelops_cluster_agent_cluster_status_lease",
        table_name=AGENT_LEASES,
    )
    op.drop_index(
        "ix_sentinelops_cluster_agent_leases_status",
        table_name=AGENT_LEASES,
    )
    op.drop_table(AGENT_LEASES)
    op.drop_index(
        "ix_sentinelops_cluster_registrations_lifecycle",
        table_name=REGISTRATIONS,
    )
    op.drop_table(REGISTRATIONS)
