from __future__ import annotations

import asyncio
import os

import pytest
from alembic import command
from sqlalchemy import insert

from sentinelops.domain import Alert, IncidentRecord, IncidentStatus
from sentinelops.migration import (
    HEAD_REVISIONS,
    alembic_config,
    upgrade_database,
)
from sentinelops.storage import SqlIncidentStore
from sentinelops.storage.sqlalchemy import incidents

DATABASE_URL = os.getenv("SENTINELOPS_MIGRATION_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason=(
        "SENTINELOPS_MIGRATION_DATABASE_URL is only configured "
        "in the PostgreSQL migration contract job"
    ),
)


@pytest.mark.asyncio
async def test_postgres_previous_revision_upgrades_with_data_and_is_idempotent() -> None:
    assert DATABASE_URL is not None
    config = alembic_config(DATABASE_URL)
    await asyncio.to_thread(command.downgrade, config, "base")
    await asyncio.to_thread(upgrade_database, DATABASE_URL, "0002_executor_queue")

    legacy_store = SqlIncidentStore(DATABASE_URL)
    record = IncidentRecord(
        alert=Alert(
            name="PostgresMigrationContract",
            namespace="sentinelops-migrations",
            service="order-service",
            severity="warning",
            summary="preserve data while adding the Executor queue",
        ),
        status=IncidentStatus.INVESTIGATING,
    )
    async with legacy_store.engine.begin() as connection:
        await connection.execute(
            insert(incidents).values(
                id=record.id,
                version=1,
                status=record.status.value,
                execution_profile_id=record.execution_profile_id,
                record=record.model_dump(mode="json"),
                graph_state={"revision": "0002_executor_queue"},
                created_at=record.created_at.isoformat(),
                updated_at=record.updated_at.isoformat(),
            )
        )
    assert await legacy_store.schema_revisions() == ("0002_executor_queue",)
    await legacy_store.close()

    await asyncio.to_thread(upgrade_database, DATABASE_URL)
    await asyncio.to_thread(upgrade_database, DATABASE_URL)
    current_store = SqlIncidentStore(DATABASE_URL)
    loaded = await current_store.get(record.id)

    assert await current_store.schema_revisions() == HEAD_REVISIONS
    assert loaded is not None
    assert loaded.graph_state == {"revision": "0002_executor_queue"}
    await current_store.close()
