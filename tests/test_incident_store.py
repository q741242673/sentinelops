from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

import sentinelops.api as api_module
from sentinelops.api import app
from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentStatus, TimelineEvent, ToolResult
from sentinelops.runtime import build_agent
from sentinelops.storage import (
    ActionIntentConflictError,
    ApprovalConflictError,
    DurableActionJournal,
    LeaseConflictError,
    SqlIncidentStore,
    StoreConflictError,
)


def _database_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'sentinelops.db'}"


async def _paused_incident():
    agent = build_agent(
        Settings(tool_backend="simulator", model_provider="rule_based")
    )
    record = await agent.start(
        Alert(
            name="HighOrderServiceErrorRate",
            namespace="sentinelops-demo",
            service="order-service",
            severity="critical",
            summary="Order service error rate exceeded its SLO",
        )
    )
    assert record.status == IncidentStatus.AWAITING_APPROVAL
    return agent, record


async def _enqueue_claim_dispatch(
    store: SqlIncidentStore,
    lease,
    idempotency_key: str,
    *,
    owner_id: str = "executor-a",
    ttl_seconds: float = 60,
):
    await store.enqueue_action(lease, idempotency_key=idempotency_key)
    claim = await store.claim_action_execution(
        owner_id=owner_id,
        attempt_id=f"attempt-{idempotency_key[:16]}",
        ttl_seconds=ttl_seconds,
    )
    assert claim is not None
    assert claim.idempotency_key == idempotency_key
    await store.mark_action_dispatched(claim)
    return claim


@pytest.mark.asyncio
async def test_store_survives_reopen_and_preserves_nested_incident(tmp_path) -> None:
    agent, record = await _paused_incident()
    graph_state = await agent.export_state(record.id)
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()

    created = await store.save(
        record,
        expected_version=None,
        graph_state=graph_state,
    )
    await store.close()

    reopened = SqlIncidentStore(_database_url(tmp_path))
    await reopened.setup()
    loaded = await reopened.get(record.id)

    assert loaded is not None
    assert loaded.version == created.version == 1
    assert loaded.record == created.record
    assert loaded.record.approval is not None
    assert loaded.record.approval.expires_at.tzinfo is not None
    assert loaded.graph_state == graph_state
    await reopened.close()


@pytest.mark.asyncio
async def test_store_rejects_stale_snapshot_overwrite(tmp_path) -> None:
    _, record = await _paused_incident()
    url = _database_url(tmp_path)
    first = SqlIncidentStore(url)
    second = SqlIncidentStore(url)
    await first.setup()
    await second.setup()
    created = await first.save(record, expected_version=None, graph_state=None)
    stale = await second.get(record.id)
    assert stale is not None

    current_record = created.record.model_copy(deep=True)
    current_record.timeline.append(
        TimelineEvent(type="worker.current", message="newer worker won")
    )
    current = await first.save(
        current_record,
        expected_version=created.version,
        graph_state=None,
    )

    stale_record = stale.record.model_copy(deep=True)
    stale_record.status = IncidentStatus.FAILED
    with pytest.raises(StoreConflictError):
        await second.save(
            stale_record,
            expected_version=stale.version,
            graph_state=None,
        )

    final = await first.get(record.id)
    assert final is not None
    assert final.version == current.version == 2
    assert final.record.status == IncidentStatus.AWAITING_APPROVAL
    assert final.record.timeline[-1].type == "worker.current"
    await first.close()
    await second.close()


@pytest.mark.asyncio
async def test_paused_approval_resumes_after_process_restart_once(tmp_path) -> None:
    first_agent, record = await _paused_incident()
    assert record.approval is not None
    approval_id = record.approval.approval_id
    approval_version = record.approval.version
    url = _database_url(tmp_path)
    first_store = SqlIncidentStore(url)
    await first_store.setup()
    created = await first_store.save(
        record,
        expected_version=None,
        graph_state=await first_agent.export_state(record.id),
    )
    await first_store.close()
    del first_agent

    second_store = SqlIncidentStore(url)
    await second_store.setup()
    loaded = await second_store.get(record.id)
    assert loaded is not None and loaded.graph_state is not None
    restored_agent = build_agent(
        Settings(tool_backend="simulator", model_provider="rule_based")
    )
    await restored_agent.restore(loaded.record, loaded.graph_state)

    await second_store.claim_approval(
        record.id,
        approval_id=approval_id,
        approval_version=approval_version,
        approved=True,
        note="approved after restart",
    )
    resumed = await restored_agent.resume(
        record.id,
        approval_id=approval_id,
        approval_version=approval_version,
        approved=True,
        note="approved after restart",
    )
    assert resumed.status == IncidentStatus.RESOLVED
    assert len(resumed.execution_results) == 1
    assert resumed.timeline[-1].created_at <= datetime.now(UTC)
    saved = await second_store.save(
        resumed,
        expected_version=created.version,
        graph_state=None,
    )
    assert saved.version == 2

    with pytest.raises(ApprovalConflictError):
        await second_store.claim_approval(
            record.id,
            approval_id=approval_id,
            approval_version=approval_version,
            approved=True,
            note="duplicate",
        )
    await second_store.close()


@pytest.mark.asyncio
async def test_two_replicas_cannot_consume_the_same_approval(tmp_path) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    url = _database_url(tmp_path)
    first = SqlIncidentStore(url)
    second = SqlIncidentStore(url)
    await first.setup()
    await second.setup()
    await first.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )

    async def claim(store: SqlIncidentStore, approved: bool):
        try:
            await store.claim_approval(
                record.id,
                approval_id=record.approval.approval_id,
                approval_version=record.approval.version,
                approved=approved,
                note="concurrent decision",
            )
        except ApprovalConflictError:
            return "conflict"
        return "claimed"

    outcomes = await asyncio.gather(claim(first, True), claim(second, False))

    assert sorted(outcomes) == ["claimed", "conflict"]
    assert await first.approval_status(record.approval.approval_id) in {
        "approved",
        "rejected",
    }
    await first.close()
    await second.close()


@pytest.mark.asyncio
async def test_expired_approval_is_closed_without_user_interaction(tmp_path) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    record.approval.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    url = _database_url(tmp_path)
    store = SqlIncidentStore(url)
    await store.setup()
    await store.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await store.close()

    await api_module.initialize_persistence(SqlIncidentStore(url))
    try:
        recovered = api_module.incident_records[record.id]
        assert recovered.status == IncidentStatus.ESCALATED
        assert recovered.approval is None
        assert record.id not in api_module.incident_agents
        assert any(item.type == "approval.expired" for item in recovered.timeline)
        assert recovered.timeline[-1].type == "recovery.failed_closed"
        assert recovered.timeline[-1].data["execution_outcome"] == "not_dispatched"
        assert api_module.incident_store is not None
        assert (
            await api_module.incident_store.approval_status(
                record.approval.approval_id
            )
            == "expired"
        )
    finally:
        await api_module.shutdown_persistence()
        api_module.incident_records.clear()
        api_module.incident_agents.clear()
        api_module.incident_versions.clear()
        api_module.incident_recovery_errors.clear()


@pytest.mark.asyncio
async def test_api_restores_persisted_approval_after_fresh_startup(tmp_path) -> None:
    url = _database_url(tmp_path)
    await api_module.initialize_persistence(SqlIncidentStore(url))
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            created = await client.post(
                "/api/v1/incidents",
                json={
                    "name": "HighOrderServiceErrorRate",
                    "namespace": "sentinelops-demo",
                    "service": "order-service",
                    "severity": "critical",
                    "summary": "Persistent API recovery",
                },
            )
        assert created.status_code == 201
        paused = created.json()
        assert paused["status"] == "awaiting_approval"
    finally:
        await api_module.shutdown_persistence()

    # A new store and newly constructed Agent simulate a fresh API process.
    await api_module.initialize_persistence(SqlIncidentStore(url))
    try:
        assert paused["id"] in api_module.incident_agents
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            restored = await client.get(f"/api/v1/incidents/{paused['id']}")
            decided = await client.post(
                f"/api/v1/incidents/{paused['id']}/approval",
                json={
                    "approval_id": paused["approval"]["approval_id"],
                    "approval_version": paused["approval"]["version"],
                    "approved": True,
                    "note": "approved after API restart",
                },
            )
            duplicate = await client.post(
                f"/api/v1/incidents/{paused['id']}/approval",
                json={
                    "approval_id": paused["approval"]["approval_id"],
                    "approval_version": paused["approval"]["version"],
                    "approved": True,
                },
            )

        assert restored.status_code == 200
        assert restored.json()["status"] == "awaiting_approval"
        assert decided.status_code == 200
        assert decided.json()["status"] == "resolved"
        assert len(decided.json()["execution_results"]) == 1
        assert api_module.incident_store is not None
        intent = await api_module.incident_store.latest_action_intent(paused["id"])
        assert intent is not None
        assert intent.status == "succeeded"
        assert intent.result is not None and intent.result.success is True
        assert duplicate.status_code == 409
    finally:
        await api_module.shutdown_persistence()
        api_module.incident_records.clear()
        api_module.incident_agents.clear()
        api_module.incident_versions.clear()


@pytest.mark.asyncio
async def test_startup_never_replays_an_approval_consumed_before_crash(tmp_path) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    url = _database_url(tmp_path)
    before_crash = SqlIncidentStore(url)
    await before_crash.setup()
    await before_crash.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await before_crash.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="process dies immediately after this commit",
    )
    await before_crash.close()

    await api_module.initialize_persistence(SqlIncidentStore(url))
    try:
        recovered = api_module.incident_records[record.id]
        assert recovered.status == IncidentStatus.ESCALATED
        assert recovered.approval is None
        assert recovered.execution_results == []
        assert recovered.timeline[-1].type == "recovery.failed_closed"
        assert recovered.timeline[-1].data["execution_outcome"] == "not_dispatched"
        assert record.id not in api_module.incident_agents
    finally:
        await api_module.shutdown_persistence()
        api_module.incident_records.clear()
        api_module.incident_agents.clear()
        api_module.incident_versions.clear()


@pytest.mark.asyncio
async def test_worker_lease_uses_fencing_generation_and_cannot_be_stolen(tmp_path) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    first = await store.acquire_lease(
        "lease-contract",
        owner_id="worker-a",
        ttl_seconds=60,
    )
    assert first.generation == 1

    with pytest.raises(LeaseConflictError):
        await store.acquire_lease(
            "lease-contract",
            owner_id="worker-b",
            ttl_seconds=60,
        )

    heartbeat = await store.heartbeat_lease(first, ttl_seconds=60)
    assert heartbeat.generation == first.generation
    assert heartbeat.expires_at >= first.expires_at
    await store.release_lease(first)
    second = await store.acquire_lease(
        "lease-contract",
        owner_id="worker-b",
        ttl_seconds=60,
    )
    assert second.generation == 2

    with pytest.raises(LeaseConflictError):
        await store.heartbeat_lease(first, ttl_seconds=60)
    await store.close()


@pytest.mark.asyncio
async def test_expired_lease_can_be_taken_over_without_sleep(tmp_path) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    expired = await store.acquire_lease(
        "expired-lease",
        owner_id="worker-a",
        ttl_seconds=-1,
    )
    replacement = await store.acquire_lease(
        "expired-lease",
        owner_id="worker-b",
        ttl_seconds=60,
    )

    assert replacement.generation == expired.generation + 1
    with pytest.raises(LeaseConflictError):
        await store.heartbeat_lease(expired, ttl_seconds=60)
    await store.close()


@pytest.mark.asyncio
async def test_action_intent_records_dispatch_and_result_before_incident_terminal(
    tmp_path,
) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    await store.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await store.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="intent contract",
    )
    lease = await store.acquire_lease(
        record.id,
        owner_id="worker-a",
        ttl_seconds=60,
    )
    precondition = {"resource_version": "17", "generation": 4}
    prepared = await store.prepare_action(
        lease,
        idempotency_key="a" * 64,
        action=record.approval.action,
        precondition=precondition,
    )
    assert prepared.status == "prepared"

    await store.enqueue_action(lease, idempotency_key=prepared.idempotency_key)
    claim = await store.claim_action_execution(
        owner_id="executor-a",
        attempt_id="attempt-a",
        ttl_seconds=60,
    )
    assert claim is not None
    dispatched = await store.mark_action_dispatched(claim)
    assert dispatched.status == "dispatched"
    result = ToolResult(
        tool_name=record.approval.action.tool_name,
        success=True,
        content={"deployment": "order-service"},
    )
    completed = await store.complete_action(
        claim=claim,
        result=result,
    )

    assert completed.status == "succeeded"
    assert completed.result == result
    with pytest.raises(ActionIntentConflictError):
        await store.mark_action_dispatched(claim)
    await store.close()


@pytest.mark.asyncio
async def test_prepared_intent_can_be_fenced_and_reassigned_before_dispatch(
    tmp_path,
) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    await store.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await store.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="lease takeover",
    )
    first = await store.acquire_lease(
        record.id,
        owner_id="worker-a",
        ttl_seconds=60,
    )
    prepared = await store.prepare_action(
        first,
        idempotency_key="b" * 64,
        action=record.approval.action,
        precondition={"resource_version": "17"},
    )
    await store.release_lease(first)
    second = await store.acquire_lease(
        record.id,
        owner_id="worker-b",
        ttl_seconds=60,
    )
    reassigned = await store.prepare_action(
        second,
        idempotency_key=prepared.idempotency_key,
        action=record.approval.action,
        precondition=prepared.precondition,
    )

    assert reassigned.lease_generation == second.generation
    with pytest.raises(LeaseConflictError):
        await store.enqueue_action(first, idempotency_key=prepared.idempotency_key)
    claim = await _enqueue_claim_dispatch(
        store,
        second,
        prepared.idempotency_key,
    )
    dispatched = await store.latest_action_intent(record.id)
    assert claim.idempotency_key == prepared.idempotency_key
    assert dispatched is not None
    assert dispatched.status == "dispatched"
    await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("complete_before_crash", "expected_outcome", "expected_intent_status"),
    [
        (False, "unknown", "unknown"),
        (True, "known_succeeded", "succeeded"),
    ],
)
async def test_startup_recovers_durable_action_boundary_without_replaying_write(
    tmp_path,
    complete_before_crash: bool,
    expected_outcome: str,
    expected_intent_status: str,
) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    url = _database_url(tmp_path)
    before_crash = SqlIncidentStore(url)
    await before_crash.setup()
    await before_crash.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await before_crash.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="crash boundary",
    )
    lease = await before_crash.acquire_lease(
        record.id,
        owner_id="crashed-worker",
        ttl_seconds=60,
    )
    intent = await before_crash.prepare_action(
        lease,
        idempotency_key=("d" if complete_before_crash else "c") * 64,
        action=record.approval.action,
        precondition={"resource_version": "17"},
    )
    claim = await _enqueue_claim_dispatch(
        before_crash,
        lease,
        intent.idempotency_key,
        owner_id="crashed-executor",
        ttl_seconds=2 if not complete_before_crash else 60,
    )
    if complete_before_crash:
        await before_crash.complete_action(
            claim=claim,
            result=ToolResult(
                tool_name=record.approval.action.tool_name,
                success=True,
                content={"durable_result": True},
            ),
        )
    else:
        await asyncio.sleep(2.1)
    await before_crash.release_lease(lease)
    await before_crash.close()

    await api_module.initialize_persistence(SqlIncidentStore(url))
    try:
        recovered = api_module.incident_records[record.id]
        assert recovered.status == IncidentStatus.ESCALATED
        assert recovered.timeline[-1].data["execution_outcome"] == expected_outcome
        assert (
            recovered.timeline[-1].data["action_intent_status"]
            == expected_intent_status
        )
        assert len(recovered.execution_results) == (
            1 if complete_before_crash else 0
        )
        assert record.id not in api_module.incident_agents
    finally:
        await api_module.shutdown_persistence()
        api_module.incident_records.clear()
        api_module.incident_agents.clear()
        api_module.incident_versions.clear()


@pytest.mark.asyncio
async def test_durable_resolved_state_blocks_dispatch_across_replicas(tmp_path) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    url = _database_url(tmp_path)
    worker = SqlIncidentStore(url)
    webhook = SqlIncidentStore(url)
    await worker.setup()
    created = await worker.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await worker.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="approved before resolved race",
    )
    lease = await worker.acquire_lease(
        record.id,
        owner_id="worker-a",
        ttl_seconds=60,
    )
    intent = await worker.prepare_action(
        lease,
        idempotency_key="e" * 64,
        action=record.approval.action,
        precondition={"resource_version": "17"},
    )
    await worker.enqueue_action(lease, idempotency_key=intent.idempotency_key)

    resolved = created.record.model_copy(deep=True)
    resolved.status = IncidentStatus.RESOLVED
    resolved.approval = None
    resolved.timeline.append(
        TimelineEvent(type="alertmanager.resolved", message="resolved on replica b")
    )
    await webhook.save(
        resolved,
        expected_version=created.version,
        graph_state=None,
    )

    claim = await worker.claim_action_execution(
        owner_id="executor-a",
        attempt_id="resolved-before-dispatch",
        ttl_seconds=60,
    )
    assert claim is not None
    with pytest.raises(ActionIntentConflictError):
        await worker.mark_action_dispatched(claim)
    current_intent = await worker.latest_action_intent(record.id)
    assert current_intent is not None
    assert current_intent.status == "claimed"
    await worker.close()
    await webhook.close()


@pytest.mark.asyncio
async def test_fenced_agent_cannot_reach_cluster_write_tool(tmp_path) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    await store.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await store.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="fencing test",
    )
    stale = await store.acquire_lease(
        record.id,
        owner_id="worker-a",
        ttl_seconds=60,
    )
    await store.release_lease(stale)
    current = await store.acquire_lease(
        record.id,
        owner_id="worker-b",
        ttl_seconds=60,
    )
    assert current.generation > stale.generation
    agent.set_action_journal(DurableActionJournal(store, stale))

    blocked = await agent.resume(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="stale worker tries to continue",
    )

    assert blocked.status == IncidentStatus.ESCALATED
    assert blocked.execution_results == []
    assert await store.latest_action_intent(record.id) is None
    assert any(
        "无法持久化受限操作意图" in event.data.get("reason", "")
        for event in blocked.timeline
        if event.type == "approval.invalidated"
    )
    await store.close()


@pytest.mark.asyncio
async def test_startup_does_not_take_over_incident_with_live_worker_lease(
    tmp_path,
) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    url = _database_url(tmp_path)
    active_worker = SqlIncidentStore(url)
    await active_worker.setup()
    await active_worker.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await active_worker.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="live worker is still processing",
    )
    live_lease = await active_worker.acquire_lease(
        record.id,
        owner_id="still-running-worker",
        ttl_seconds=60,
    )
    await active_worker.close()

    await api_module.initialize_persistence(SqlIncidentStore(url))
    try:
        recovered = api_module.incident_records[record.id]
        assert recovered.status == IncidentStatus.AWAITING_APPROVAL
        assert record.id not in api_module.incident_agents
        assert "still-running-worker" in api_module.incident_recovery_errors[record.id]
        assert api_module.incident_store is not None
        await api_module.incident_store.release_lease(live_lease)
    finally:
        await api_module.shutdown_persistence()
        api_module.incident_records.clear()
        api_module.incident_agents.clear()
        api_module.incident_versions.clear()
        api_module.incident_recovery_errors.clear()


@pytest.mark.asyncio
async def test_crashed_live_lease_is_reconciled_after_ttl_without_restart(
    tmp_path,
) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    url = _database_url(tmp_path)
    crashed_worker = SqlIncidentStore(url)
    await crashed_worker.setup()
    await crashed_worker.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await crashed_worker.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="worker will be killed",
    )
    lease = await crashed_worker.acquire_lease(
        record.id,
        owner_id="killed-worker",
        ttl_seconds=2,
    )
    intent = await crashed_worker.prepare_action(
        lease,
        idempotency_key="f" * 64,
        action=record.approval.action,
        precondition={"resource_version": "17"},
    )
    await _enqueue_claim_dispatch(
        crashed_worker,
        lease,
        intent.idempotency_key,
        owner_id="killed-executor",
        ttl_seconds=2,
    )
    # Simulate SIGKILL: close the DB pool without release_lease().
    await crashed_worker.close()

    await api_module.initialize_persistence(SqlIncidentStore(url))
    try:
        assert api_module.incident_records[record.id].status == (
            IncidentStatus.AWAITING_APPROVAL
        )
        assert "killed-worker" in api_module.incident_recovery_errors[record.id]

        await asyncio.sleep(2.1)
        await api_module._reconcile_persistence_once()

        recovered = api_module.incident_records[record.id]
        assert recovered.status == IncidentStatus.ESCALATED
        assert recovered.timeline[-1].data["execution_outcome"] == "unknown"
        assert record.id not in api_module.incident_recovery_errors
    finally:
        await api_module.shutdown_persistence()
        api_module.incident_records.clear()
        api_module.incident_agents.clear()
        api_module.incident_versions.clear()
        api_module.incident_recovery_errors.clear()


@pytest.mark.asyncio
async def test_resolved_after_dispatch_preserves_late_durable_result(tmp_path) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    url = _database_url(tmp_path)
    store = SqlIncidentStore(url)
    await store.setup()
    created = await store.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await store.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="resolved race",
    )
    lease = await store.acquire_lease(
        record.id,
        owner_id="worker-a",
        ttl_seconds=60,
    )
    intent = await store.prepare_action(
        lease,
        idempotency_key="1" * 64,
        action=record.approval.action,
        precondition={"resource_version": "17"},
    )
    claim = await _enqueue_claim_dispatch(
        store,
        lease,
        intent.idempotency_key,
    )

    resolution = await store.record_alert_resolved(
        record.id,
        fingerprint="resolved-during-write",
    )
    assert resolution is not None
    assert resolution.version == created.version + 1
    assert resolution.record.status == IncidentStatus.ESCALATED
    assert resolution.record.execution_results == []
    assert resolution.record.timeline[-1].data["execution_outcome"] == "unknown"

    result = ToolResult(
        tool_name=record.approval.action.tool_name,
        success=True,
        content={"late_result": "known"},
    )
    await store.complete_action(
        claim=claim,
        result=result,
    )
    await store.release_lease(lease)
    await store.close()

    await api_module.initialize_persistence(SqlIncidentStore(url))
    try:
        recovered = api_module.incident_records[record.id]
        assert recovered.status == IncidentStatus.ESCALATED
        assert recovered.execution_results == [result]
        assert recovered.timeline[-1].data["execution_outcome"] == "known_succeeded"
        assert recovered.timeline[-1].data["action_intent_status"] == "succeeded"
    finally:
        await api_module.shutdown_persistence()
        api_module.incident_records.clear()
        api_module.incident_agents.clear()
        api_module.incident_versions.clear()


@pytest.mark.asyncio
async def test_recoverable_query_is_not_limited_to_latest_two_hundred(tmp_path) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    oldest_id = ""
    for index in range(205):
        record = api_module.IncidentRecord(
            alert=api_module.Alert(
                name="BacklogRecovery",
                service=f"service-{index}",
                summary="recoverable backlog",
            ),
            status=IncidentStatus.INVESTIGATING,
        )
        if index == 0:
            oldest_id = record.id
        await store.save(record, expected_version=None, graph_state=None)

    visible_history = await store.list()
    recoverable = await store.list_recoverable()

    assert len(visible_history) == 200
    assert len(recoverable) == 205
    assert oldest_id in {item.record.id for item in recoverable}
    await store.close()
