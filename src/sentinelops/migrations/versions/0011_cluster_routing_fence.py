"""Bind durable incidents and action intents to one immutable cluster.

Revision ID: 0011_cluster_routing_fence
Revises: 0010_action_reconcile_outbox
"""

from __future__ import annotations

import re
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0011_cluster_routing_fence"
down_revision = "0010_action_reconcile_outbox"
branch_labels = None
depends_on = None

INCIDENTS = "sentinelops_incidents"
ACTIONS = "sentinelops_action_intents"
LEGACY_CLUSTER_ID = "legacy-unassigned"
MIGRATION_REASON = (
    "cluster routing fence migration invalidated an action that was not terminal"
)
CLUSTER_ID = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$"
)


def _incident_table() -> sa.Table:
    return sa.table(
        INCIDENTS,
        sa.column("id", sa.String(length=64)),
        sa.column("cluster_id", sa.String(length=128)),
        sa.column("record", sa.JSON()),
    )


def _action_table() -> sa.Table:
    return sa.table(
        ACTIONS,
        sa.column("idempotency_key", sa.String(length=64)),
        sa.column("incident_id", sa.String(length=64)),
        sa.column("cluster_id", sa.String(length=128)),
        sa.column("precondition", sa.JSON()),
        sa.column("status", sa.String(length=24)),
        sa.column("error", sa.Text()),
        sa.column("finished_at", sa.String(length=40)),
        sa.column("updated_at", sa.String(length=40)),
    )


def _record_cluster_id(record: dict[str, Any]) -> str:
    alert = record.get("alert")
    if not isinstance(alert, dict):
        raise RuntimeError("历史事故快照缺少 alert，无法建立集群路由围栏")
    value = alert.get("cluster_id")
    if not isinstance(value, str) or not value.strip():
        return LEGACY_CLUSTER_ID
    if CLUSTER_ID.fullmatch(value) is None:
        raise RuntimeError("历史事故 cluster_id 不符合稳定路由标识格式")
    return value


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                f"LOCK TABLE {INCIDENTS}, {ACTIONS} "
                "IN SHARE ROW EXCLUSIVE MODE"
            )
        )

    inspector = sa.inspect(bind)
    incident_columns = {
        column["name"] for column in inspector.get_columns(INCIDENTS)
    }
    action_columns = {
        column["name"] for column in inspector.get_columns(ACTIONS)
    }
    if "cluster_id" not in incident_columns:
        with op.batch_alter_table(INCIDENTS) as batch:
            batch.add_column(
                sa.Column(
                    "cluster_id",
                    sa.String(length=128),
                    nullable=True,
                )
            )
    if "cluster_id" not in action_columns:
        with op.batch_alter_table(ACTIONS) as batch:
            batch.add_column(
                sa.Column(
                    "cluster_id",
                    sa.String(length=128),
                    nullable=True,
                )
            )

    incident_table = _incident_table()
    rows = list(
        bind.execute(
            sa.select(incident_table.c.id, incident_table.c.record)
        ).mappings()
    )
    for row in rows:
        record = dict(row["record"])
        alert = dict(record["alert"])
        cluster_id = _record_cluster_id(record)
        alert["cluster_id"] = cluster_id
        record["alert"] = alert
        bind.execute(
            sa.update(incident_table)
            .where(incident_table.c.id == row["id"])
            .values(cluster_id=cluster_id, record=record)
        )

    orphaned = bind.execute(
        sa.text(
            f"""
            SELECT COUNT(*)
            FROM {ACTIONS} action
            LEFT JOIN {INCIDENTS} incident
              ON incident.id = action.incident_id
            WHERE incident.id IS NULL
            """
        )
    ).scalar_one()
    if int(orphaned) != 0:
        raise RuntimeError(
            "存在无法关联事故的历史 Action Intent，迁移已停止"
        )

    bind.execute(
        sa.text(
            f"""
            UPDATE {ACTIONS}
            SET cluster_id = (
                SELECT incident.cluster_id
                FROM {INCIDENTS} incident
                WHERE incident.id = {ACTIONS}.incident_id
            )
            """
        )
    )
    action_table = _action_table()
    action_rows = list(
        bind.execute(
            sa.select(
                action_table.c.idempotency_key,
                action_table.c.cluster_id,
                action_table.c.precondition,
            )
        ).mappings()
    )
    for row in action_rows:
        if not isinstance(row["precondition"], dict):
            raise RuntimeError("历史 Action Intent precondition 不是对象")
        precondition = dict(row["precondition"])
        existing_cluster_id = precondition.get("cluster_id")
        if (
            existing_cluster_id is not None
            and existing_cluster_id != row["cluster_id"]
        ):
            raise RuntimeError(
                "历史 Action Intent precondition.cluster_id 与事故不一致"
            )
        precondition["cluster_id"] = row["cluster_id"]
        bind.execute(
            sa.update(action_table)
            .where(
                action_table.c.idempotency_key == row["idempotency_key"]
            )
            .values(precondition=precondition)
        )
    bind.execute(
        sa.update(action_table)
        .where(action_table.c.status.in_(["prepared", "queued", "claimed"]))
        .values(
            status="cancelled",
            error=MIGRATION_REASON,
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
            finished_at=sa.func.coalesce(
                action_table.c.finished_at,
                action_table.c.updated_at,
            ),
        )
    )

    missing = bind.execute(
        sa.text(
            f"""
            SELECT
              (SELECT COUNT(*) FROM {INCIDENTS}
               WHERE cluster_id IS NULL OR TRIM(cluster_id) = '')
              +
              (SELECT COUNT(*) FROM {ACTIONS}
               WHERE cluster_id IS NULL OR TRIM(cluster_id) = '')
            """
        )
    ).scalar_one()
    if int(missing) != 0:
        raise RuntimeError("cluster_id 回填不完整，迁移已停止")

    inspector = sa.inspect(bind)
    incident_indexes = {
        index["name"] for index in inspector.get_indexes(INCIDENTS)
    }
    action_indexes = {
        index["name"] for index in inspector.get_indexes(ACTIONS)
    }
    with op.batch_alter_table(INCIDENTS) as batch:
        batch.alter_column(
            "cluster_id",
            existing_type=sa.String(length=128),
            nullable=False,
        )
        if "ix_sentinelops_incidents_cluster_id" not in incident_indexes:
            batch.create_index(
                "ix_sentinelops_incidents_cluster_id",
                ["cluster_id"],
                unique=False,
            )
    with op.batch_alter_table(ACTIONS) as batch:
        batch.alter_column(
            "cluster_id",
            existing_type=sa.String(length=128),
            nullable=False,
        )
        if "ix_sentinelops_action_intents_cluster_id" not in action_indexes:
            batch.create_index(
                "ix_sentinelops_action_intents_cluster_id",
                ["cluster_id"],
                unique=False,
            )


def downgrade() -> None:
    with op.batch_alter_table(ACTIONS) as batch:
        batch.drop_index("ix_sentinelops_action_intents_cluster_id")
        batch.drop_column("cluster_id")
    with op.batch_alter_table(INCIDENTS) as batch:
        batch.drop_index("ix_sentinelops_incidents_cluster_id")
        batch.drop_column("cluster_id")
