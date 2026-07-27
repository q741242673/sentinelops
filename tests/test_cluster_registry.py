from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

from sentinelops.domain import (
    Alert,
    IncidentRecord,
    IncidentStatus,
    RemediationAction,
)
from sentinelops.storage import (
    ClusterAgentLeaseConflictError,
    SqlIncidentStore,
)
from sentinelops.storage.sqlalchemy import (
    action_intents,
    cluster_agent_leases,
)


def _database_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'cluster-registry.db'}"


async def _registration(store: SqlIncidentStore, cluster_id: str = "cluster-a"):
    return await store.ensure_cluster_registration(
        cluster_id=cluster_id,
        display_name=f"{cluster_id} display",
        default_namespace="payments",
    )


async def _agent(
    store: SqlIncidentStore,
    *,
    cluster_id: str = "cluster-a",
    instance_id: str = "executor-0",
    session_id: str = "session-a",
    capabilities: tuple[str, ...] = (
        "action.execute",
        "action.reconcile",
    ),
):
    return await store.register_cluster_agent(
        cluster_id=cluster_id,
        instance_id=instance_id,
        session_id=session_id,
        capabilities=capabilities,
        version="0.2.0",
        ttl_seconds=60,
    )


async def _queued_action(
    store: SqlIncidentStore,
    *,
    cluster_id: str,
    key: str,
):
    record = IncidentRecord(
        id=f"incident-{key}",
        alert=Alert(
            name="ClusterLeaseContract",
            cluster_id=cluster_id,
            namespace="payments",
            service="payments-api",
            severity="critical",
            summary="cluster lease test",
        ),
        status=IncidentStatus.INVESTIGATING,
    )
    await store.save(record, expected_version=None, graph_state=None)
    worker = await store.acquire_lease(
        record.id,
        owner_id=f"worker-{key}",
        ttl_seconds=60,
    )
    intent = await store.prepare_action(
        worker,
        idempotency_key=key * 64,
        action=RemediationAction(
            tool_name="restart_deployment",
            arguments={"name": "payments-api"},
            rationale="cluster lease contract",
            expected_outcome="healthy",
            risk="medium",
        ),
        precondition={
            "cluster_id": cluster_id,
            "resource_version": "17",
        },
    )
    await store.enqueue_action(
        worker,
        idempotency_key=intent.idempotency_key,
    )
    return intent


@pytest.mark.asyncio
async def test_registration_is_idempotent_and_connection_is_derived(
    tmp_path,
) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    registration = await _registration(store)
    first = await _agent(store)
    retried = await _agent(store)

    assert registration.routing_generation == 1
    assert registration.metadata_state == "configured"
    assert retried.session_id == first.session_id
    assert retried.generation == first.generation == 1
    assert retried.lease_until >= first.lease_until
    connection = await store.get_cluster_connection("cluster-a")
    assert connection is not None
    assert connection.status == "online"
    assert len(connection.agents) == 1
    assert connection.agents[0].connection_status == "online"
    assert [item.registration.cluster_id for item in await store.list_cluster_connections()] == [
        "cluster-a"
    ]
    await store.close()


@pytest.mark.asyncio
async def test_session_generation_fences_aba_and_allows_multiple_instances(
    tmp_path,
) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    await _registration(store)
    first = await _agent(store)
    second_instance = await _agent(
        store,
        instance_id="executor-1",
        session_id="session-b",
    )
    assert second_instance.generation == 1

    with pytest.raises(
        ClusterAgentLeaseConflictError,
        match="已有活动 Session",
    ):
        await _agent(store, session_id="replacement-too-early")

    await store.close_cluster_agent(first)
    replacement = await _agent(
        store,
        session_id="replacement-after-close",
    )
    assert replacement.generation == first.generation + 1
    with pytest.raises(ClusterAgentLeaseConflictError):
        await store.heartbeat_cluster_agent(first, ttl_seconds=60)
    await store.close()


@pytest.mark.asyncio
async def test_claim_and_dispatch_require_live_bound_agent_capability(
    tmp_path,
) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    await _registration(store)
    execute_only = await _agent(
        store,
        capabilities=("action.execute",),
    )
    intent = await _queued_action(
        store,
        cluster_id="cluster-a",
        key="a",
    )
    claim = await store.claim_action_execution(
        agent_lease=execute_only,
        owner_id="executor-a",
        attempt_id="attempt-a",
        ttl_seconds=60,
    )
    assert claim is not None
    assert claim.idempotency_key == intent.idempotency_key
    assert claim.cluster_generation == 1
    assert claim.session_id == execute_only.session_id

    await store.close_cluster_agent(execute_only)
    with pytest.raises(ClusterAgentLeaseConflictError):
        await store.mark_action_dispatched(
            claim,
            agent_lease=execute_only,
        )
    await store.close()


@pytest.mark.asyncio
async def test_global_reaper_handles_offline_clusters_without_an_executor(
    tmp_path,
) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    await _registration(store, "cluster-a")
    await _registration(store, "cluster-b")
    agent_a = await _agent(store, cluster_id="cluster-a")
    agent_b = await _agent(
        store,
        cluster_id="cluster-b",
        instance_id="executor-b",
        session_id="session-b",
    )
    intent_a = await _queued_action(
        store,
        cluster_id="cluster-a",
        key="a",
    )
    intent_b = await _queued_action(
        store,
        cluster_id="cluster-b",
        key="b",
    )
    claim_a = await store.claim_action_execution(
        agent_lease=agent_a,
        owner_id="executor-a",
        attempt_id="attempt-a",
        ttl_seconds=60,
    )
    claim_b = await store.claim_action_execution(
        agent_lease=agent_b,
        owner_id="executor-b",
        attempt_id="attempt-b",
        ttl_seconds=60,
    )
    assert claim_a is not None and claim_b is not None
    await store.mark_action_dispatched(claim_b, agent_lease=agent_b)

    expired = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    async with store.engine.begin() as connection:
        await connection.execute(
            update(action_intents)
            .where(
                action_intents.c.idempotency_key.in_(
                    [intent_a.idempotency_key, intent_b.idempotency_key]
                )
            )
            .values(executor_lease_until=expired)
        )
        await connection.execute(
            update(cluster_agent_leases).values(
                lease_until=expired,
                updated_at=expired,
            )
        )

    assert await store.reap_expired_action_claims() == 2
    requeued = await store.latest_action_intent("incident-a")
    unknown = await store.latest_action_intent("incident-b")
    assert requeued is not None
    assert requeued.status == "queued"
    assert requeued.executor_session_id is None
    assert unknown is not None
    assert unknown.status == "unknown"
    assert unknown.executor_session_id == agent_b.session_id
    assert await store.reap_expired_action_claims() == 0
    await store.close()
