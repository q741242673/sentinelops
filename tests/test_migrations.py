from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import insert, inspect, text
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
from sentinelops.storage import (
    ClusterRegistrationConflictError,
    SqlIncidentStore,
)
from sentinelops.storage.sqlalchemy import action_intents, incidents


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
                    for item in inspect(sync_connection).get_indexes(table_name)
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
    assert (
        await _indexes(
            database_url,
            "sentinelops_action_reconciliation_outbox",
        )
    )["ix_sentinelops_action_reconciliation_status_next_attempt"] == (
        "status",
        "next_attempt_at",
    )
    assert await _table_names(database_url) == {
        "alembic_version",
        "sentinelops_action_intents",
        "sentinelops_action_reconciliation_outbox",
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
        "sentinelops_change_proposals",
        "sentinelops_cluster_agent_leases",
        "sentinelops_cluster_registrations",
        "sentinelops_gitops_proposal_outbox",
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
    assert [event.event_type for event in audit_events] == ["legacy.migration_checkpoint"]
    assert audit_events[0].payload["historical_transitions_verified"] is False
    assert (await current_store.verify_audit_chain(created.id)).valid is True
    await current_store.close()


@pytest.mark.asyncio
async def test_action_reconciliation_migration_backfills_unknown_intents(
    tmp_path,
) -> None:
    database_url = _database_url(tmp_path)
    await _upgrade(database_url, "0009_gitops_proposal_outbox")
    engine = create_async_engine(database_url)
    timestamp = "2026-07-26T08:00:00+00:00"
    record = _record("migration-reconciliation").model_copy(
        update={"id": "migration-reconciliation"}
    )
    legacy_payload = record.model_dump(mode="json")
    legacy_payload["alert"].pop("cluster_id")
    async with engine.begin() as connection:
        await connection.execute(
            insert(incidents).values(
                id=record.id,
                version=1,
                status=record.status.value,
                execution_profile_id=record.execution_profile_id,
                record=legacy_payload,
                graph_state=None,
                created_at=timestamp,
                updated_at=timestamp,
            )
        )
        await connection.execute(
            insert(action_intents).values(
                idempotency_key="a" * 64,
                incident_id="migration-reconciliation",
                lease_generation=1,
                approval_id=None,
                approval_version=None,
                action={
                    "tool_name": "restart_deployment",
                    "arguments": {"name": "order-service"},
                    "rationale": "migration fixture",
                    "expected_outcome": "healthy",
                    "risk": "medium",
                },
                precondition={"resource_version": "17"},
                status="unknown",
                executor_id="executor-before-upgrade",
                executor_generation=1,
                executor_lease_until=timestamp,
                attempt_id="migration-attempt",
                result=None,
                error="result lost before upgrade",
                created_at=timestamp,
                updated_at=timestamp,
                queued_at=timestamp,
                claimed_at=timestamp,
                dispatched_at=timestamp,
                finished_at=timestamp,
            )
        )
    await engine.dispose()

    await _upgrade(database_url)

    migrated = create_async_engine(database_url)
    try:
        async with migrated.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text(
                            """
                        SELECT action_id, status, next_attempt_at
                        FROM sentinelops_action_reconciliation_outbox
                        """
                        )
                    )
                )
                .mappings()
                .one()
            )
        assert row["action_id"] == "a" * 64
        assert row["status"] == "pending"
        assert row["next_attempt_at"] == timestamp
    finally:
        await migrated.dispose()


@pytest.mark.asyncio
async def test_cluster_routing_migration_fences_nonterminal_actions(
    tmp_path,
) -> None:
    database_url = _database_url(tmp_path)
    await _upgrade(database_url, "0009_gitops_proposal_outbox")
    engine = create_async_engine(database_url)
    timestamp = "2026-07-27T08:00:00+00:00"
    record = _record("legacy-cluster-routing").model_copy(update={"id": "legacy-cluster-routing"})
    legacy_payload = record.model_dump(mode="json")
    legacy_payload["alert"].pop("cluster_id")
    async with engine.begin() as connection:
        await connection.execute(
            insert(incidents).values(
                id=record.id,
                version=1,
                status=record.status.value,
                execution_profile_id=record.execution_profile_id,
                record=legacy_payload,
                graph_state=None,
                created_at=timestamp,
                updated_at=timestamp,
            )
        )
        for index, status in enumerate(
            ["prepared", "queued", "claimed", "dispatched", "succeeded"],
            start=1,
        ):
            await connection.execute(
                insert(action_intents).values(
                    idempotency_key=str(index) * 64,
                    incident_id=record.id,
                    lease_generation=1,
                    approval_id=None,
                    approval_version=None,
                    action={
                        "tool_name": "restart_deployment",
                        "arguments": {"name": "order-service"},
                        "rationale": "migration fixture",
                        "expected_outcome": "healthy",
                        "risk": "medium",
                    },
                    precondition={"resource_version": str(index)},
                    status=status,
                    executor_id=(
                        "legacy-executor"
                        if status in {"claimed", "dispatched", "succeeded"}
                        else None
                    ),
                    executor_generation=(
                        1 if status in {"claimed", "dispatched", "succeeded"} else 0
                    ),
                    executor_lease_until=(
                        timestamp if status in {"claimed", "dispatched", "succeeded"} else None
                    ),
                    attempt_id=(
                        f"legacy-attempt-{index}"
                        if status in {"claimed", "dispatched", "succeeded"}
                        else None
                    ),
                    result=None,
                    error=None,
                    created_at=timestamp,
                    updated_at=timestamp,
                    queued_at=timestamp if status != "prepared" else None,
                    claimed_at=(
                        timestamp if status in {"claimed", "dispatched", "succeeded"} else None
                    ),
                    dispatched_at=(timestamp if status in {"dispatched", "succeeded"} else None),
                    finished_at=timestamp if status == "succeeded" else None,
                )
            )
    await engine.dispose()

    await _upgrade(database_url)

    migrated = create_async_engine(database_url)
    try:
        async with migrated.connect() as connection:
            action_rows = (
                (
                    await connection.execute(
                        text(
                            """
                        SELECT
                          idempotency_key,
                          cluster_id,
                          cluster_generation,
                          executor_session_id,
                          executor_session_generation,
                          status,
                          error
                        FROM sentinelops_action_intents
                        ORDER BY idempotency_key
                        """
                        )
                    )
                )
                .mappings()
                .all()
            )
            incident_row = (
                (
                    await connection.execute(
                        text(
                            """
                        SELECT cluster_id, record
                        FROM sentinelops_incidents
                        WHERE id = 'legacy-cluster-routing'
                        """
                        )
                    )
                )
                .mappings()
                .one()
            )
        assert [row["status"] for row in action_rows] == [
            "cancelled",
            "cancelled",
            "cancelled",
            "unknown",
            "succeeded",
        ]
        assert {row["cluster_id"] for row in action_rows} == {"legacy-unassigned"}
        assert {row["cluster_generation"] for row in action_rows} == {1}
        assert {row["executor_session_id"] for row in action_rows} == {None}
        assert {row["executor_session_generation"] for row in action_rows} == {None}
        assert action_rows[4]["error"] is None
        assert incident_row["cluster_id"] == "legacy-unassigned"
        incident_payload = incident_row["record"]
        if isinstance(incident_payload, str):
            incident_payload = json.loads(incident_payload)
        assert incident_payload["alert"]["cluster_id"] == "legacy-unassigned"
    finally:
        await migrated.dispose()


@pytest.mark.asyncio
async def test_cluster_registry_migration_placeholder_is_claimed_once(
    tmp_path,
) -> None:
    database_url = _database_url(tmp_path)
    await _upgrade(database_url, "0011_cluster_routing_fence")
    legacy = SqlIncidentStore(database_url)
    record = _record("configured-after-upgrade")
    record.alert = record.alert.model_copy(
        update={
            "cluster_id": "production-east",
            "namespace": "payments-production",
        }
    )
    await legacy.save(record, expected_version=None, graph_state=None)
    await legacy.close()

    await _upgrade(database_url)
    store = SqlIncidentStore(database_url)
    before = await store.get_cluster_connection("production-east")
    assert before is not None
    assert before.registration.routing_generation == 1
    assert before.registration.metadata_state == "inferred"
    assert before.status == "offline"

    configured = await store.ensure_cluster_registration(
        cluster_id="production-east",
        display_name="华东生产集群",
        default_namespace="payments-production",
    )
    assert configured.metadata_state == "configured"
    assert configured.display_name == "华东生产集群"
    assert configured.default_namespace == "payments-production"

    with pytest.raises(
        ClusterRegistrationConflictError,
        match="权威集群元数据",
    ):
        await store.ensure_cluster_registration(
            cluster_id="production-east",
            display_name="错误集群",
            default_namespace="other-namespace",
        )
    await store.close()


@pytest.mark.asyncio
async def test_action_reconciliation_migration_rejects_drifted_existing_table(
    tmp_path,
) -> None:
    database_url = _database_url(tmp_path)
    database_path = tmp_path / "sentinelops.db"
    await _upgrade(database_url, "0009_gitops_proposal_outbox")
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE sentinelops_action_reconciliation_outbox (
                action_id VARCHAR(64) PRIMARY KEY,
                status VARCHAR(24) NOT NULL
            )
            """
        )

    with pytest.raises(RuntimeError, match="Controller 对账表"):
        await _upgrade(database_url)

    store = SqlIncidentStore(database_url)
    assert await store.schema_revisions() == ("0009_gitops_proposal_outbox",)
    await store.close()


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
            "CREATE TABLE sentinelops_incidents (id INTEGER PRIMARY KEY, unexpected TEXT)"
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
        cluster_id="migration-production-cluster",
        database_url=database_url,
        database_auto_create=False,
        executor_mode="external",
        executor_backend="controller",
        alertmanager_source_id="migration-production-test",
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token=("migration-production-test-token-0001"),
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
