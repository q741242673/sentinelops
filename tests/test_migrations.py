from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import sys

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import insert, inspect
from sqlalchemy.ext.asyncio import create_async_engine

import sentinelops.api as api_module
from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentRecord, IncidentStatus
from sentinelops.migration import (
    HEAD_REVISIONS,
    SchemaRevisionError,
    alembic_config,
    upgrade_database,
)
from sentinelops.storage import SqlIncidentStore
from sentinelops.storage.sqlalchemy import incidents


def _database_url(tmp_path, name: str = "sentinelops.db") -> str:
    return f"sqlite+aiosqlite:///{tmp_path / name}"


def _record(name: str) -> IncidentRecord:
    return IncidentRecord(
        alert=Alert(
            name="MigrationContract",
            namespace="sentinelops-demo",
            service=name,
            severity="warning",
            summary="database migration contract",
        ),
        status=IncidentStatus.INVESTIGATING,
    )


async def _upgrade(database_url: str, revision: str = "head") -> None:
    await asyncio.to_thread(upgrade_database, database_url, revision)


async def _table_names(database_url: str) -> set[str]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            return await connection.run_sync(
                lambda sync_connection: set(inspect(sync_connection).get_table_names())
            )
    finally:
        await engine.dispose()


async def _indexes(
    database_url: str,
    table_name: str,
) -> dict[str, tuple[str, ...]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            return await connection.run_sync(
                lambda sync_connection: {
                    item["name"]: tuple(item.get("column_names") or ())
                    for item in inspect(sync_connection).get_indexes(
                        table_name
                    )
                }
            )
    finally:
        await engine.dispose()


async def _legacy_save(
    store: SqlIncidentStore,
    record: IncidentRecord,
    *,
    graph_state: dict[str, object] | None,
) -> None:
    payload = record.model_dump(mode="json")
    async with store.engine.begin() as connection:
        await connection.execute(
            insert(incidents).values(
                id=record.id,
                version=1,
                status=record.status.value,
                execution_profile_id=record.execution_profile_id,
                record=payload,
                graph_state=graph_state,
                created_at=record.created_at.isoformat(),
                updated_at=record.updated_at.isoformat(),
            )
        )


@pytest.mark.asyncio
async def test_empty_database_upgrades_to_single_head_and_is_idempotent(tmp_path) -> None:
    database_url = _database_url(tmp_path)

    await _upgrade(database_url)
    store = SqlIncidentStore(database_url)
    created = await store.save(
        _record("empty-upgrade"),
        expected_version=None,
        graph_state={"checkpoint": "preserve-me"},
    )
    await store.close()

    await _upgrade(database_url)
    reopened = SqlIncidentStore(database_url)
    loaded = await reopened.get(created.record.id)

    assert await reopened.schema_revisions() == HEAD_REVISIONS
    assert loaded is not None
    assert loaded.graph_state == {"checkpoint": "preserve-me"}
    assert (
        await _indexes(
            database_url,
            "sentinelops_audit_anchor_outbox",
        )
    )["ix_sentinelops_audit_anchor_outbox_status_created_at"] == (
        "status",
        "created_at",
    )
    assert await _table_names(database_url) == {
        "alembic_version",
        "sentinelops_action_intents",
        "sentinelops_alert_bindings",
        "sentinelops_approvals",
        "sentinelops_audit_events",
        "sentinelops_audit_anchor_outbox",
        "sentinelops_audit_anchor_security_state",
        "sentinelops_audit_anchor_inventory_epoch",
        "sentinelops_audit_anchor_unlock_decisions",
        "sentinelops_audit_anchor_unlock_requests",
        "sentinelops_audit_heads",
        "sentinelops_incident_events",
        "sentinelops_incidents",
        "sentinelops_worker_leases",
    }
    await reopened.close()


@pytest.mark.asyncio
async def test_versioned_durable_store_upgrades_to_executor_queue_without_data_loss(
    tmp_path,
) -> None:
    database_url = _database_url(tmp_path)
    await _upgrade(database_url, "0001_durable_store")
    old_store = SqlIncidentStore(database_url)
    created = _record("versioned-legacy")
    await _legacy_save(
        old_store,
        created,
        graph_state={"revision": "0001"},
    )
    assert await old_store.schema_revisions() == ("0001_durable_store",)
    await old_store.close()

    await _upgrade(database_url)
    current_store = SqlIncidentStore(database_url)
    loaded = await current_store.get(created.id)

    assert await current_store.schema_revisions() == HEAD_REVISIONS
    assert loaded is not None
    assert loaded.graph_state == {"revision": "0001"}
    assert "sentinelops_action_intents" in await _table_names(database_url)
    audit_events = await current_store.list_audit_events(created.id)
    assert [event.event_type for event in audit_events] == [
        "legacy.migration_checkpoint"
    ]
    assert audit_events[0].payload["historical_transitions_verified"] is False
    assert (await current_store.verify_audit_chain(created.id)).valid is True
    await current_store.close()


@pytest.mark.asyncio
async def test_audit_anchor_migration_backfills_only_current_head(tmp_path) -> None:
    database_url = _database_url(tmp_path)
    await _upgrade(database_url, "0001_durable_store")
    legacy_store = SqlIncidentStore(database_url)
    created = _record("anchor-migration")
    await _legacy_save(legacy_store, created, graph_state=None)
    await legacy_store.close()
    await _upgrade(database_url, "0004_audit_chain")

    await _upgrade(database_url)
    migrated = SqlIncidentStore(database_url)
    claim = await migrated.claim_audit_anchor(
        owner_id="migration-test",
        ttl_seconds=60,
    )

    assert claim is not None
    assert claim.anchor.incident_id == created.id
    assert claim.anchor.sequence == 1
    assert claim.anchor.previous_anchor_id is None
    assert (
        await migrated.claim_audit_anchor(
            owner_id="migration-test-2",
            ttl_seconds=60,
        )
        is None
    )
    await migrated.close()


@pytest.mark.asyncio
async def test_exact_unversioned_legacy_store_is_adopted_and_upgraded(tmp_path) -> None:
    database_url = _database_url(tmp_path)
    database_path = tmp_path / "sentinelops.db"
    await _upgrade(database_url, "0001_durable_store")
    legacy_store = SqlIncidentStore(database_url)
    created = _record("unversioned-legacy")
    await _legacy_save(
        legacy_store,
        created,
        graph_state=None,
    )
    await legacy_store.close()
    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TABLE alembic_version")

    await _upgrade(database_url)
    current_store = SqlIncidentStore(database_url)

    assert await current_store.schema_revisions() == HEAD_REVISIONS
    assert await current_store.get(created.id) is not None
    await current_store.close()


@pytest.mark.asyncio
async def test_exact_unversioned_current_store_is_stamped_without_data_loss(
    tmp_path,
) -> None:
    database_url = _database_url(tmp_path)
    current_store = SqlIncidentStore(database_url)
    await current_store.setup()
    created = await current_store.save(
        _record("unversioned-current"),
        expected_version=None,
        graph_state={"created_by": "metadata.create_all"},
    )
    assert await current_store.schema_revisions() == ()
    await current_store.close()

    await _upgrade(database_url)
    migrated = SqlIncidentStore(database_url)
    loaded = await migrated.get(created.record.id)

    assert await migrated.schema_revisions() == HEAD_REVISIONS
    assert loaded is not None
    assert loaded.graph_state == {"created_by": "metadata.create_all"}
    await migrated.close()


@pytest.mark.asyncio
async def test_unversioned_schema_with_wrong_contract_is_rejected(tmp_path) -> None:
    database_url = _database_url(tmp_path)
    with sqlite3.connect(tmp_path / "sentinelops.db") as connection:
        connection.execute(
            "CREATE TABLE sentinelops_incidents "
            "(id INTEGER PRIMARY KEY, unexpected TEXT)"
        )

    with pytest.raises(RuntimeError, match="结构不匹配"):
        await _upgrade(database_url)

    store = SqlIncidentStore(database_url)
    assert await store.schema_revisions() == ()
    await store.close()


@pytest.mark.asyncio
async def test_unversioned_schema_missing_required_index_is_rejected(tmp_path) -> None:
    database_url = _database_url(tmp_path)
    store = SqlIncidentStore(database_url)
    await store.setup()
    await store.close()
    with sqlite3.connect(tmp_path / "sentinelops.db") as connection:
        connection.execute("DROP INDEX ix_sentinelops_incidents_status")

    with pytest.raises(RuntimeError, match="缺少索引"):
        await _upgrade(database_url)

    check_store = SqlIncidentStore(database_url)
    assert await check_store.schema_revisions() == ()
    await check_store.close()


@pytest.mark.asyncio
async def test_production_startup_rejects_old_revision_without_modifying_it(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = _database_url(tmp_path)
    await _upgrade(database_url, "0001_durable_store")
    settings = Settings(
        environment="production",
        database_url=database_url,
        database_auto_create=False,
        executor_mode="external",
        alertmanager_source_id="migration-production-test",
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token=(
            "migration-production-test-token-0001"
        ),
        audit_hmac_key="migration-audit-test-key-00000001",
        audit_key_id="migration-test-v1",
        operator_auth_mode="oidc",
        oidc_issuer="https://identity.example.test",
        oidc_audience="sentinelops-api",
        oidc_jwks_url="https://identity.example.test/jwks",
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: settings)

    with pytest.raises(SchemaRevisionError, match="数据库版本不匹配"):
        await api_module.initialize_persistence(
            SqlIncidentStore(
                database_url,
                audit_hmac_key="migration-audit-test-key-00000001",
                audit_key_id="migration-test-v1",
            ),
            create_schema=False,
        )

    check_store = SqlIncidentStore(database_url)
    assert api_module.incident_store is None
    assert await check_store.schema_revisions() == ("0001_durable_store",)
    await check_store.close()


def test_declared_head_matches_alembic_script_directory(tmp_path) -> None:
    script = ScriptDirectory.from_config(alembic_config(_database_url(tmp_path)))

    assert tuple(script.get_heads()) == HEAD_REVISIONS


def test_cli_migrations_work_outside_repository_and_are_idempotent(tmp_path) -> None:
    database_url = _database_url(tmp_path)
    workdir = tmp_path / "elsewhere"
    workdir.mkdir()
    environment = {
        **os.environ,
        "SENTINELOPS_DATABASE_URL": database_url,
    }

    for command in ("db-init", "db-init", "db-check"):
        completed = subprocess.run(
            [sys.executable, "-m", "sentinelops.cli", command],
            cwd=workdir,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr
