from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update

from sentinelops.config import Settings
from sentinelops.domain import Alert, ToolResult
from sentinelops.executor import ExecutorWorker
from sentinelops.executor_control import ExecutorControlUnavailableError
from sentinelops.remediation_controller import RemediationObservation
from sentinelops.runtime import build_agent
from sentinelops.storage import (
    ActionIntentConflictError,
    ClusterAgentLeaseConflictError,
    SqlIncidentStore,
)
from sentinelops.storage.base import ClusterAgentLeaseToken
from sentinelops.storage.sqlalchemy import (
    action_intents,
    action_reconciliation_outbox,
)
from sentinelops.tools import ToolRegistry


class RecordingWriteBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def call(self, name: str, arguments: dict[str, object]) -> ToolResult:
        self.calls.append((name, arguments))
        return ToolResult(
            tool_name=name,
            success=True,
            content={"executor_write": True},
        )


class RecordingRemediationGateway:
    def __init__(self) -> None:
        self.namespace = "sentinelops-demo"
        self.intents = []
        self.observed_intents = []
        self.observation = RemediationObservation(
            state="not_found",
            reason="no recovery contract",
        )

    async def execute(self, intent) -> ToolResult:
        self.intents.append(intent)
        return ToolResult(
            tool_name=intent.action.tool_name,
            success=True,
            content={
                "sentinel_remediation": intent.idempotency_key,
                "controller_phase": "Succeeded",
            },
        )

    async def observe(self, intent) -> RemediationObservation:
        self.observed_intents.append(intent)
        if isinstance(self.observation, Exception):
            raise self.observation
        return self.observation


class BlockingExecutorStore:
    def __init__(self) -> None:
        self.heartbeat_entered = asyncio.Event()
        now = datetime.now(UTC)
        self.token = ClusterAgentLeaseToken(
            cluster_id="local",
            instance_id="executor-health-test",
            session_id="health-session",
            generation=1,
            routing_generation=1,
            capabilities=("action.execute", "backend.direct"),
            version="test",
            registered_at=now,
            last_seen_at=now,
            lease_until=now + timedelta(seconds=60),
        )

    async def ensure_cluster_registration(self, **_kwargs):
        return None

    async def register_cluster_agent(self, **_kwargs):
        return self.token

    async def heartbeat_cluster_agent(self, *_args, **_kwargs):
        self.heartbeat_entered.set()
        await asyncio.Event().wait()

    async def close_cluster_agent(self, _token):
        return None

    async def claim_action_execution(self, **_kwargs):
        return None


class ResponseLossStore:
    def __init__(self, delegate: SqlIncidentStore) -> None:
        self.delegate = delegate
        self.lost = {"claim": False, "dispatch": False, "complete": False}

    def __getattr__(self, name: str):
        return getattr(self.delegate, name)

    async def claim_action_execution(self, **kwargs):
        result = await self.delegate.claim_action_execution(**kwargs)
        if not self.lost["claim"]:
            self.lost["claim"] = True
            raise ExecutorControlUnavailableError("claim response lost")
        return result

    async def mark_action_dispatched(self, claim, *, agent_lease):
        result = await self.delegate.mark_action_dispatched(
            claim,
            agent_lease=agent_lease,
        )
        if not self.lost["dispatch"]:
            self.lost["dispatch"] = True
            raise ExecutorControlUnavailableError("dispatch response lost")
        return result

    async def complete_action(self, *, claim, agent_lease, result):
        stored = await self.delegate.complete_action(
            claim=claim,
            agent_lease=agent_lease,
            result=result,
        )
        if not self.lost["complete"]:
            self.lost["complete"] = True
            raise ExecutorControlUnavailableError("complete response lost")
        return stored


class CloseAgentAfterClaimStore:
    def __init__(self, store: SqlIncidentStore) -> None:
        self.store = store

    def __getattr__(self, name):
        return getattr(self.store, name)

    async def claim_action_execution(self, **kwargs):
        claim = await self.store.claim_action_execution(**kwargs)
        if claim is not None:
            await self.store.close_cluster_agent(kwargs["agent_lease"])
        return claim


def _execution_precondition(
    action,
) -> dict[str, object]:
    precondition: dict[str, object] = {
        "cluster_id": "local",
        "action_fingerprint": "approved-action",
        "tool_name": action.tool_name,
        "target": action.arguments["name"],
        "namespace": "sentinelops-demo",
        "deployment_uid": "deployment-uid",
        "generation": 2,
        "resource_version": "17",
        "desired_replicas": 1,
        "paused": False,
        "current_revision": 2,
        "current_replica_set_uid": "replica-set-uid",
        "current_template_hash": "template-hash",
        "current_replicas": 1,
        "current_ready_replicas": 0,
        "captured_at": "2099-07-26T00:00:00+00:00",
        "expires_at": "2099-07-26T00:15:00+00:00",
    }
    if action.tool_name == "rollback_deployment":
        precondition["rollback_target"] = {
            "revision": action.arguments["revision"],
            "replica_set_uid": "healthy-replica-set",
            "health_proof": {"subject": "healthy-revision"},
        }
    return precondition


async def _queued_intent(tmp_path, *, suffix: str = "a"):
    agent = build_agent(
        Settings(tool_backend="simulator", model_provider="rule_based")
    )
    record = await agent.start(
        Alert(
            name="ExecutorContract",
            namespace="sentinelops-demo",
            service="order-service",
            severity="critical",
            summary="Executor contract test",
        )
    )
    assert record.approval is not None
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / f'executor-{suffix}.db'}"
    )
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
        note="executor test",
    )
    lease = await store.acquire_lease(
        record.id,
        owner_id="agent-worker",
        ttl_seconds=60,
    )
    intent = await store.prepare_action(
        lease,
        idempotency_key=suffix * 64,
        action=record.approval.action,
        precondition=_execution_precondition(record.approval.action),
    )
    await store.enqueue_action(lease, idempotency_key=intent.idempotency_key)
    return store, record, lease, intent


async def _cluster_agent(
    store: SqlIncidentStore,
    *,
    instance_id: str,
    cluster_id: str = "local",
    session_id: str | None = None,
):
    await store.ensure_cluster_registration(
        cluster_id=cluster_id,
        display_name=cluster_id,
        default_namespace="sentinelops-demo",
    )
    return await store.register_cluster_agent(
        cluster_id=cluster_id,
        instance_id=instance_id,
        session_id=session_id or f"session-{instance_id}",
        capabilities=(
            "action.execute",
            "action.reconcile",
            "backend.controller",
        ),
        version="test",
        ttl_seconds=60,
    )


async def _expire_action_for_reconciliation(
    store: SqlIncidentStore,
    action_id: str,
) -> None:
    expired = "2000-01-01T00:00:00+00:00"
    async with store.engine.begin() as connection:
        await connection.execute(
            update(action_intents)
            .where(action_intents.c.idempotency_key == action_id)
            .values(executor_lease_until=expired)
        )
        await connection.execute(
            update(action_reconciliation_outbox)
            .where(action_reconciliation_outbox.c.action_id == action_id)
            .values(next_attempt_at=expired)
        )


async def _set_action_fence_expiry(
    store: SqlIncidentStore,
    action_id: str,
    expires_at: str,
) -> None:
    async with store.engine.begin() as connection:
        row = (
            await connection.execute(
                select(action_intents.c.precondition).where(
                    action_intents.c.idempotency_key == action_id
                )
            )
        ).one()
        precondition = dict(row.precondition)
        precondition["expires_at"] = expires_at
        await connection.execute(
            update(action_intents)
            .where(action_intents.c.idempotency_key == action_id)
            .values(precondition=precondition)
        )


async def _reconciliation_outbox_status(
    store: SqlIncidentStore,
    action_id: str,
) -> str:
    async with store.engine.connect() as connection:
        return (
            await connection.execute(
                select(action_reconciliation_outbox.c.status).where(
                    action_reconciliation_outbox.c.action_id == action_id
                )
            )
        ).scalar_one()


@pytest.mark.asyncio
async def test_executor_is_the_only_component_that_calls_write_backend(tmp_path) -> None:
    store, record, _, intent = await _queued_intent(tmp_path)
    backend = RecordingWriteBackend()
    worker = ExecutorWorker(
        store,
        ToolRegistry(backend),
        owner_id="executor-a",
        cluster_id="local",
    )

    assert await worker.run_once() is True

    completed = await store.latest_action_intent(record.id)
    assert completed is not None
    assert completed.idempotency_key == intent.idempotency_key
    assert completed.status == "succeeded"
    assert len(backend.calls) == 1
    assert backend.calls[0][0] == record.approval.action.tool_name
    connection = await store.get_cluster_connection("local")
    assert connection is not None
    assert connection.status == "online"
    assert len(connection.agents) == 1
    assert connection.agents[0].instance_id == "executor-a"
    assert connection.agents[0].capabilities == (
        "action.execute",
        "backend.direct",
    )
    assert completed.executor_session_id == connection.agents[0].session_id
    await store.close()


@pytest.mark.asyncio
async def test_executor_submits_immutable_contract_without_direct_write_access(
    tmp_path,
) -> None:
    store, record, _, intent = await _queued_intent(tmp_path)
    gateway = RecordingRemediationGateway()
    worker = ExecutorWorker(
        store,
        None,
        owner_id="executor-controller",
        cluster_id="local",
        remediation_gateway=gateway,
    )

    assert await worker.run_once() is True

    completed = await store.latest_action_intent(record.id)
    assert completed is not None
    assert completed.status == "succeeded"
    assert completed.result is not None
    assert completed.result.content["sentinel_remediation"] == intent.idempotency_key
    assert [item.idempotency_key for item in gateway.intents] == [
        intent.idempotency_key
    ]
    await store.close()


@pytest.mark.asyncio
async def test_executor_readiness_is_not_refreshed_while_registry_is_blocked() -> None:
    store = BlockingExecutorStore()
    pulses = 0

    def health() -> None:
        nonlocal pulses
        pulses += 1

    worker = ExecutorWorker(
        store,  # type: ignore[arg-type]
        ToolRegistry(RecordingWriteBackend()),
        owner_id="executor-health-test",
        cluster_id="local",
        instance_id="executor-health-test",
        session_id="health-session",
        registry_ttl_seconds=0.03,
        registry_heartbeat_seconds=0.01,
        health_callback=health,
    )
    task = asyncio.create_task(worker.run_forever())
    await asyncio.wait_for(store.heartbeat_entered.wait(), timeout=1)
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert pulses == 1


@pytest.mark.asyncio
async def test_executor_closes_registered_session_on_normal_shutdown(
    tmp_path,
) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'executor-close.db'}"
    )
    await store.setup()
    worker = ExecutorWorker(
        store,
        ToolRegistry(RecordingWriteBackend()),
        owner_id="executor-close",
        cluster_id="local",
        instance_id="executor-close",
        session_id="executor-close-session",
        poll_interval_seconds=0.01,
    )
    task = asyncio.create_task(worker.run_forever())
    for _ in range(100):
        connection = await store.get_cluster_connection("local")
        if connection is not None and connection.status == "online":
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("Executor did not register")

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    connection = await store.get_cluster_connection("local")
    assert connection is not None
    assert connection.status == "offline"
    assert connection.agents[0].status == "closed"
    await store.close()


@pytest.mark.asyncio
async def test_closed_agent_between_claim_and_dispatch_causes_zero_gateway_calls(
    tmp_path,
) -> None:
    store, record, _, _ = await _queued_intent(tmp_path)
    gateway = RecordingRemediationGateway()
    worker = ExecutorWorker(
        CloseAgentAfterClaimStore(store),  # type: ignore[arg-type]
        None,
        owner_id="executor-closed-before-dispatch",
        cluster_id="local",
        instance_id="executor-closed-before-dispatch",
        session_id="closed-before-dispatch-session",
        remediation_gateway=gateway,
    )

    with pytest.raises(Exception, match="Session|fencing|关闭"):
        await worker.run_once()

    assert gateway.intents == []
    intent = await store.latest_action_intent(record.id)
    assert intent is not None
    assert intent.status == "claimed"
    await store.close()


@pytest.mark.asyncio
async def test_run_once_replaces_a_closed_registry_session(
    tmp_path,
) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'executor-reregister.db'}"
    )
    await store.setup()
    worker = ExecutorWorker(
        store,
        ToolRegistry(RecordingWriteBackend()),
        owner_id="executor-reregister",
        cluster_id="local",
        instance_id="executor-reregister",
        session_id="first-session",
    )

    assert await worker.run_once() is False
    first = worker._agent_lease
    assert first is not None
    await store.close_cluster_agent(first)

    assert await worker.run_once() is False
    second = worker._agent_lease
    assert second is not None
    assert second.generation == first.generation + 1
    assert second.session_id != first.session_id
    await store.close()


@pytest.mark.asyncio
async def test_resolved_after_claim_before_dispatch_causes_zero_writes(tmp_path) -> None:
    store, record, _, intent = await _queued_intent(tmp_path)
    agent = await _cluster_agent(store, instance_id="executor-a")
    claim = await store.claim_action_execution(
        agent_lease=agent,
        owner_id="executor-a",
        attempt_id="claim-before-resolved",
        ttl_seconds=60,
    )
    assert claim is not None

    resolved = await store.record_alert_resolved(
        record.id,
        fingerprint="resolved-before-write",
    )
    assert resolved is not None
    assert resolved.record.timeline[-1].data["execution_outcome"] == "not_dispatched"
    with pytest.raises(ActionIntentConflictError):
        await store.mark_action_dispatched(claim, agent_lease=agent)

    cancelled = await store.latest_action_intent(record.id)
    assert cancelled is not None
    assert cancelled.idempotency_key == intent.idempotency_key
    assert cancelled.status == "cancelled"
    await store.close()


@pytest.mark.asyncio
async def test_executor_rejects_intent_that_does_not_match_approved_action(
    tmp_path,
) -> None:
    store, record, lease, original = await _queued_intent(tmp_path)
    assert record.approval is not None
    # Replace the queued valid intent with a second incident-local intent whose
    # immutable action does not match the exact approved payload.
    await store.cancel_action(
        lease,
        idempotency_key=original.idempotency_key,
        reason="prepare tamper contract",
    )
    tampered_action = record.approval.action.model_copy(
        update={"arguments": {"name": "unrelated-service", "revision": 1}}
    )
    tampered = await store.prepare_action(
        lease,
        idempotency_key="t" * 64,
        action=tampered_action,
        precondition={"cluster_id": "local", "resource_version": "17"},
    )
    await store.enqueue_action(lease, idempotency_key=tampered.idempotency_key)
    agent = await _cluster_agent(store, instance_id="executor-a")
    claim = await store.claim_action_execution(
        agent_lease=agent,
        owner_id="executor-a",
        attempt_id="tampered-attempt",
        ttl_seconds=60,
    )
    assert claim is not None

    with pytest.raises(
        ActionIntentConflictError,
        match="已批准的动作或审批版本不一致",
    ):
        await store.mark_action_dispatched(claim, agent_lease=agent)
    await store.close()


@pytest.mark.asyncio
async def test_expired_claim_is_requeued_and_stale_attempt_is_fenced(tmp_path) -> None:
    store, record, _, _ = await _queued_intent(tmp_path)
    stale_agent = await _cluster_agent(store, instance_id="executor-a")
    stale = await store.claim_action_execution(
        agent_lease=stale_agent,
        owner_id="executor-a",
        attempt_id="stale-attempt",
        ttl_seconds=60,
    )
    assert stale is not None
    async with store.engine.begin() as connection:
        await connection.execute(
            update(action_intents)
            .where(
                action_intents.c.idempotency_key
                == stale.idempotency_key
            )
            .values(
                executor_lease_until="2000-01-01T00:00:00+00:00"
            )
        )
    current_agent = await _cluster_agent(store, instance_id="executor-b")
    current = await store.claim_action_execution(
        agent_lease=current_agent,
        owner_id="executor-b",
        attempt_id="current-attempt",
        ttl_seconds=60,
    )
    assert current is not None
    assert current.generation == stale.generation + 1

    with pytest.raises(ActionIntentConflictError):
        await store.mark_action_dispatched(
            stale,
            agent_lease=stale_agent,
        )
    dispatched = await store.mark_action_dispatched(
        current,
        agent_lease=current_agent,
    )
    assert dispatched.status == "dispatched"
    assert dispatched.attempt_id == "current-attempt"
    assert dispatched.incident_id == record.id
    await store.close()


@pytest.mark.asyncio
async def test_action_claim_and_dispatch_exact_replay_are_idempotent(tmp_path) -> None:
    store, record, _, intent = await _queued_intent(tmp_path)
    agent = await _cluster_agent(store, instance_id="executor-replay")
    claim = await store.claim_action_execution(
        agent_lease=agent,
        owner_id="executor-replay",
        attempt_id="stable-request-attempt",
        ttl_seconds=60,
    )
    assert claim is not None

    replayed_claim = await store.claim_action_execution(
        agent_lease=agent,
        owner_id="executor-replay",
        attempt_id="stable-request-attempt",
        ttl_seconds=60,
    )
    assert replayed_claim == claim

    dispatched = await store.mark_action_dispatched(
        claim,
        agent_lease=agent,
    )
    replayed_dispatch = await store.mark_action_dispatched(
        claim,
        agent_lease=agent,
    )
    assert replayed_dispatch == dispatched
    assert replayed_dispatch.idempotency_key == intent.idempotency_key

    audit = await store.list_audit_events(record.id)
    assert sum(event.event_type == "action.claimed" for event in audit) == 1
    assert sum(event.event_type == "action.dispatched" for event in audit) == 1
    async with store.engine.connect() as connection:
        outbox_count = (
            await connection.execute(
                select(func.count())
                .select_from(action_reconciliation_outbox)
                .where(
                    action_reconciliation_outbox.c.action_id
                    == intent.idempotency_key
                )
            )
        ).scalar_one()
    assert outbox_count == 1
    await store.close()


@pytest.mark.asyncio
async def test_executor_recovers_lost_gateway_responses_without_duplicate_write(
    tmp_path,
) -> None:
    store, record, _, _ = await _queued_intent(tmp_path)
    backend = RecordingWriteBackend()
    wrapped = ResponseLossStore(store)
    worker = ExecutorWorker(
        wrapped,
        ToolRegistry(backend),
        owner_id="executor-response-loss",
        cluster_id="local",
        instance_id="executor-response-loss",
        session_id="response-loss-session",
    )

    assert await worker.run_once() is True

    completed = await store.latest_action_intent(record.id)
    assert completed is not None
    assert completed.status == "succeeded"
    assert len(backend.calls) == 1
    assert all(wrapped.lost.values())
    audit = await store.list_audit_events(record.id)
    assert sum(event.event_type == "action.claimed" for event in audit) == 1
    assert sum(event.event_type == "action.dispatched" for event in audit) == 1
    assert sum(event.event_type == "action.succeeded" for event in audit) == 1
    await store.close()


@pytest.mark.asyncio
async def test_dispatched_crash_becomes_unknown_and_late_result_is_bound_to_attempt(
    tmp_path,
) -> None:
    store, record, _, _ = await _queued_intent(tmp_path)
    agent = await _cluster_agent(store, instance_id="executor-a")
    claim = await store.claim_action_execution(
        agent_lease=agent,
        owner_id="executor-a",
        attempt_id="immutable-attempt",
        ttl_seconds=1,
    )
    assert claim is not None
    await store.mark_action_dispatched(claim, agent_lease=agent)
    await asyncio.sleep(1.2)

    assert (
        await store.claim_action_execution(
            agent_lease=await _cluster_agent(
                store,
                instance_id="executor-b",
            ),
            owner_id="executor-b",
            attempt_id="must-not-replay",
            ttl_seconds=60,
        )
        is None
    )
    unknown = await store.latest_action_intent(record.id)
    assert unknown is not None
    assert unknown.status == "unknown"

    late_result = ToolResult(
        tool_name=unknown.action.tool_name,
        success=True,
        content={"late": "trusted"},
    )
    completed = await store.complete_action(
        claim=claim,
        agent_lease=agent,
        result=late_result,
    )
    assert completed.status == "succeeded"
    assert completed.result == late_result
    assert (
        await store.complete_action(
            claim=claim,
            agent_lease=agent,
            result=late_result,
        )
        == completed
    )

    conflicting = ToolResult(
        tool_name=unknown.action.tool_name,
        success=False,
        error="conflicting late result",
    )
    with pytest.raises(ActionIntentConflictError):
        await store.complete_action(
            claim=claim,
            agent_lease=agent,
            result=conflicting,
        )
    await store.close()


@pytest.mark.asyncio
async def test_replacement_executor_recovers_controller_result_without_replay(
    tmp_path,
) -> None:
    store, record, _, intent = await _queued_intent(tmp_path, suffix="e")
    original_agent = await _cluster_agent(
        store,
        instance_id="executor-before-crash",
    )
    original = await store.claim_action_execution(
        agent_lease=original_agent,
        owner_id="executor-before-crash",
        attempt_id="crashed-after-controller-submit",
        ttl_seconds=60,
    )
    assert original is not None
    await store.mark_action_dispatched(
        original,
        agent_lease=original_agent,
    )
    await store.mark_action_unknown(
        claim=original,
        agent_lease=original_agent,
        reason="Executor disappeared after submitting the CR",
    )
    await _expire_action_for_reconciliation(store, intent.idempotency_key)

    controller_result = ToolResult(
        tool_name=intent.action.tool_name,
        success=True,
        content={
            "sentinel_remediation": intent.idempotency_key,
            "remediation_uid": "controller-resource-uid",
            "controller_phase": "Succeeded",
            "outcome_digest": "trusted-controller-outcome",
        },
        duration_ms=0,
    )
    gateway = RecordingRemediationGateway()
    gateway.observation = RemediationObservation(
        state="terminal",
        phase="Succeeded",
        result=controller_result,
        reason="ActionApplied",
    )
    replacement = ExecutorWorker(
        store,
        None,
        owner_id="executor-replacement",
        cluster_id="local",
        remediation_gateway=gateway,
        claim_ttl_seconds=60,
    )

    assert await replacement.run_once() is True

    recovered = await store.latest_action_intent(record.id)
    assert recovered is not None
    assert recovered.status == "succeeded"
    assert recovered.result == controller_result
    assert [item.idempotency_key for item in gateway.observed_intents] == [
        intent.idempotency_key
    ]
    assert gateway.intents == []
    audit = await store.list_audit_events(record.id)
    reconciled = [
        event
        for event in audit
        if event.source_component == "executor-reconciler"
    ]
    assert len(reconciled) == 1
    assert reconciled[0].event_type == "action.succeeded"
    await store.close()


@pytest.mark.asyncio
async def test_action_reconciliation_claim_is_fenced_between_executors(
    tmp_path,
) -> None:
    store, _, _, intent = await _queued_intent(tmp_path, suffix="f")
    original_agent = await _cluster_agent(
        store,
        instance_id="executor-before-crash",
    )
    original = await store.claim_action_execution(
        agent_lease=original_agent,
        owner_id="executor-before-crash",
        attempt_id="expired-controller-attempt",
        ttl_seconds=60,
    )
    assert original is not None
    await store.mark_action_dispatched(
        original,
        agent_lease=original_agent,
    )
    await store.mark_action_unknown(
        claim=original,
        agent_lease=original_agent,
        reason="controller response was lost",
    )
    await _expire_action_for_reconciliation(store, intent.idempotency_key)

    first_agent = await _cluster_agent(store, instance_id="reconciler-a")
    first = await store.claim_action_reconciliation(
        agent_lease=first_agent,
        owner_id="reconciler-a",
        ttl_seconds=1,
    )
    assert first is not None
    second_agent = await _cluster_agent(store, instance_id="reconciler-b")
    assert (
        await store.claim_action_reconciliation(
            agent_lease=second_agent,
            owner_id="reconciler-b",
            ttl_seconds=1,
        )
        is None
    )
    await store.retry_action_reconciliation(
        first,
        agent_lease=first_agent,
        error="Controller is still executing",
        retry_after_seconds=0.1,
    )
    async with store.engine.begin() as connection:
        await connection.execute(
            update(action_reconciliation_outbox)
            .where(
                action_reconciliation_outbox.c.action_id
                == intent.idempotency_key
            )
            .values(next_attempt_at="2000-01-01T00:00:00+00:00")
        )
    second = await store.claim_action_reconciliation(
        agent_lease=second_agent,
        owner_id="reconciler-b",
        ttl_seconds=1,
    )
    assert second is not None
    assert second.generation == first.generation + 1

    with pytest.raises(ActionIntentConflictError):
        await store.complete_action_reconciliation(
            first,
            agent_lease=first_agent,
            result=ToolResult(
                tool_name=first.intent.action.tool_name,
                success=True,
                content={"stale_reconciler": True},
            ),
        )
    await store.retry_action_reconciliation(
        second,
        agent_lease=second_agent,
        error="leave the unknown result for manual review",
        retry_after_seconds=60,
    )
    await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("transition", "suffix"),
    [("complete", "x"), ("retry", "y"), ("dead_letter", "z")],
)
async def test_reconciliation_terminal_transition_rejects_replaced_agent_session(
    tmp_path,
    transition: str,
    suffix: str,
) -> None:
    store, record, _, intent = await _queued_intent(
        tmp_path,
        suffix=suffix,
    )
    execution_agent = await _cluster_agent(
        store,
        instance_id=f"executor-before-{transition}",
    )
    execution = await store.claim_action_execution(
        agent_lease=execution_agent,
        owner_id=f"executor-before-{transition}",
        attempt_id=f"execution-{transition}",
        ttl_seconds=60,
    )
    assert execution is not None
    await store.mark_action_dispatched(
        execution,
        agent_lease=execution_agent,
    )
    await store.mark_action_unknown(
        claim=execution,
        agent_lease=execution_agent,
        reason="Controller result requires read-only reconciliation",
    )
    await _expire_action_for_reconciliation(store, intent.idempotency_key)

    stale_agent = await _cluster_agent(
        store,
        instance_id="reconciler-aba",
        session_id=f"session-stale-{transition}",
    )
    reconciliation = await store.claim_action_reconciliation(
        agent_lease=stale_agent,
        owner_id="reconciler-aba",
        ttl_seconds=60,
    )
    assert reconciliation is not None
    await store.close_cluster_agent(stale_agent)
    current_agent = await _cluster_agent(
        store,
        instance_id="reconciler-aba",
        session_id=f"session-current-{transition}",
    )
    assert current_agent.generation == stale_agent.generation + 1

    async def transition_with(agent_lease: ClusterAgentLeaseToken) -> None:
        if transition == "complete":
            await store.complete_action_reconciliation(
                reconciliation,
                agent_lease=agent_lease,
                result=ToolResult(
                    tool_name=intent.action.tool_name,
                    success=True,
                    content={"stale_session": True},
                ),
            )
        elif transition == "retry":
            await store.retry_action_reconciliation(
                reconciliation,
                agent_lease=agent_lease,
                error="stale session must not retry",
                retry_after_seconds=1,
            )
        else:
            await store.dead_letter_action_reconciliation(
                reconciliation,
                agent_lease=agent_lease,
                error="stale session must not dead-letter",
            )

    with pytest.raises(ClusterAgentLeaseConflictError):
        await transition_with(stale_agent)
    with pytest.raises(ClusterAgentLeaseConflictError):
        await transition_with(current_agent)

    preserved = await store.latest_action_intent(record.id)
    assert preserved is not None
    assert preserved.status == "unknown"
    await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("transition", "suffix"),
    [("complete", "u"), ("unknown", "v")],
)
async def test_execution_terminal_transition_rejects_replaced_agent_session(
    tmp_path,
    transition: str,
    suffix: str,
) -> None:
    store, record, _, intent = await _queued_intent(
        tmp_path,
        suffix=suffix,
    )
    stale_agent = await _cluster_agent(
        store,
        instance_id="executor-aba",
        session_id=f"execution-stale-{transition}",
    )
    claim = await store.claim_action_execution(
        agent_lease=stale_agent,
        owner_id="executor-aba",
        attempt_id=f"attempt-{transition}",
        ttl_seconds=60,
    )
    assert claim is not None
    await store.mark_action_dispatched(claim, agent_lease=stale_agent)
    await store.close_cluster_agent(stale_agent)
    current_agent = await _cluster_agent(
        store,
        instance_id="executor-aba",
        session_id=f"execution-current-{transition}",
    )
    assert current_agent.generation == stale_agent.generation + 1

    async def transition_with(agent_lease: ClusterAgentLeaseToken) -> None:
        if transition == "complete":
            await store.complete_action(
                claim=claim,
                agent_lease=agent_lease,
                result=ToolResult(
                    tool_name=intent.action.tool_name,
                    success=True,
                    content={"stale_session": True},
                ),
            )
        else:
            await store.mark_action_unknown(
                claim=claim,
                agent_lease=agent_lease,
                reason="stale session must not update the action",
            )

    with pytest.raises(ClusterAgentLeaseConflictError):
        await transition_with(stale_agent)
    with pytest.raises(ClusterAgentLeaseConflictError):
        await transition_with(current_agent)

    preserved = await store.latest_action_intent(record.id)
    assert preserved is not None
    assert preserved.status == "dispatched"
    await store.close()


@pytest.mark.asyncio
async def test_missing_controller_contract_dead_letters_only_after_fence_grace(
    tmp_path,
) -> None:
    store, record, _, intent = await _queued_intent(tmp_path, suffix="m")
    original_agent = await _cluster_agent(
        store,
        instance_id="executor-before-missing-contract",
    )
    original = await store.claim_action_execution(
        agent_lease=original_agent,
        owner_id="executor-before-missing-contract",
        attempt_id="missing-contract-attempt",
        ttl_seconds=60,
    )
    assert original is not None
    await store.mark_action_dispatched(
        original,
        agent_lease=original_agent,
    )
    await store.mark_action_unknown(
        claim=original,
        agent_lease=original_agent,
        reason="Executor disappeared before the Controller result was stored",
    )
    await _expire_action_for_reconciliation(store, intent.idempotency_key)

    gateway = RecordingRemediationGateway()
    replacement = ExecutorWorker(
        store,
        None,
        owner_id="executor-missing-contract-reconciler",
        cluster_id="local",
        remediation_gateway=gateway,
        claim_ttl_seconds=60,
        missing_contract_grace_seconds=0,
    )

    assert await replacement.run_once() is True
    assert (
        await _reconciliation_outbox_status(store, intent.idempotency_key)
        == "pending"
    )
    before_deadline = await store.latest_action_intent(record.id)
    assert before_deadline is not None
    assert before_deadline.status == "unknown"

    await _set_action_fence_expiry(
        store,
        intent.idempotency_key,
        "2000-01-01T00:00:00+00:00",
    )
    await _expire_action_for_reconciliation(store, intent.idempotency_key)
    assert await replacement.run_once() is True
    assert (
        await _reconciliation_outbox_status(store, intent.idempotency_key)
        == "dead_letter"
    )
    await store.close()


@pytest.mark.asyncio
async def test_in_progress_controller_contract_retries_after_fence_expiry(
    tmp_path,
) -> None:
    store, record, _, intent = await _queued_intent(tmp_path, suffix="p")
    original_agent = await _cluster_agent(
        store,
        instance_id="executor-before-in-progress-contract",
    )
    original = await store.claim_action_execution(
        agent_lease=original_agent,
        owner_id="executor-before-in-progress-contract",
        attempt_id="in-progress-contract-attempt",
        ttl_seconds=60,
    )
    assert original is not None
    await store.mark_action_dispatched(
        original,
        agent_lease=original_agent,
    )
    await store.mark_action_unknown(
        claim=original,
        agent_lease=original_agent,
        reason="Controller is still applying the action",
    )
    await _set_action_fence_expiry(
        store,
        intent.idempotency_key,
        "2000-01-01T00:00:00+00:00",
    )
    await _expire_action_for_reconciliation(store, intent.idempotency_key)

    gateway = RecordingRemediationGateway()
    gateway.observation = RemediationObservation(
        state="in_progress",
        phase="Executing",
        reason="Controller is still executing",
    )
    replacement = ExecutorWorker(
        store,
        None,
        owner_id="executor-in-progress-reconciler",
        cluster_id="local",
        remediation_gateway=gateway,
        claim_ttl_seconds=60,
        missing_contract_grace_seconds=0,
    )

    assert await replacement.run_once() is True
    assert (
        await _reconciliation_outbox_status(store, intent.idempotency_key)
        == "pending"
    )
    preserved = await store.latest_action_intent(record.id)
    assert preserved is not None
    assert preserved.status == "unknown"
    await store.close()


@pytest.mark.asyncio
async def test_temporary_controller_error_retries_after_fence_expiry(
    tmp_path,
) -> None:
    store, record, _, intent = await _queued_intent(tmp_path, suffix="t")
    original_agent = await _cluster_agent(
        store,
        instance_id="executor-before-temporary-error",
    )
    original = await store.claim_action_execution(
        agent_lease=original_agent,
        owner_id="executor-before-temporary-error",
        attempt_id="temporary-error-attempt",
        ttl_seconds=60,
    )
    assert original is not None
    await store.mark_action_dispatched(
        original,
        agent_lease=original_agent,
    )
    await store.mark_action_unknown(
        claim=original,
        agent_lease=original_agent,
        reason="Kubernetes API response was lost",
    )
    await _set_action_fence_expiry(
        store,
        intent.idempotency_key,
        "2000-01-01T00:00:00+00:00",
    )
    await _expire_action_for_reconciliation(store, intent.idempotency_key)

    gateway = RecordingRemediationGateway()
    gateway.observation = RuntimeError("temporary Kubernetes 503")
    replacement = ExecutorWorker(
        store,
        None,
        owner_id="executor-temporary-error-reconciler",
        cluster_id="local",
        remediation_gateway=gateway,
        claim_ttl_seconds=60,
        missing_contract_grace_seconds=0,
    )

    assert await replacement.run_once() is True
    assert (
        await _reconciliation_outbox_status(store, intent.idempotency_key)
        == "pending"
    )
    preserved = await store.latest_action_intent(record.id)
    assert preserved is not None
    assert preserved.status == "unknown"
    await store.close()


@pytest.mark.asyncio
async def test_immutable_invalid_controller_result_is_dead_lettered(
    tmp_path,
) -> None:
    store, record, _, intent = await _queued_intent(tmp_path, suffix="d")
    original_agent = await _cluster_agent(
        store,
        instance_id="executor-before-invalid-result",
    )
    original = await store.claim_action_execution(
        agent_lease=original_agent,
        owner_id="executor-before-invalid-result",
        attempt_id="invalid-controller-result-attempt",
        ttl_seconds=60,
    )
    assert original is not None
    await store.mark_action_dispatched(
        original,
        agent_lease=original_agent,
    )
    await _expire_action_for_reconciliation(store, intent.idempotency_key)

    gateway = RecordingRemediationGateway()
    gateway.observation = RemediationObservation(
        state="unknown",
        phase="Succeeded",
        reason="Controller outcome digest is invalid",
        retryable=False,
    )
    replacement = ExecutorWorker(
        store,
        None,
        owner_id="executor-dead-letter",
        cluster_id="local",
        remediation_gateway=gateway,
        claim_ttl_seconds=60,
    )

    assert await replacement.run_once() is True
    preserved = await store.latest_action_intent(record.id)
    assert preserved is not None
    assert preserved.status == "unknown"
    assert preserved.error == "Controller outcome digest is invalid"
    dead_letter_agent = await _cluster_agent(
        store,
        instance_id="must-not-retry-dead-letter",
    )
    assert (
        await store.claim_action_reconciliation(
            agent_lease=dead_letter_agent,
            owner_id="must-not-retry-dead-letter",
            ttl_seconds=60,
        )
        is None
    )
    audit = await store.list_audit_events(record.id)
    dead_letters = [
        event
        for event in audit
        if event.event_type == "action.reconciliation_dead_lettered"
    ]
    assert len(dead_letters) == 1

    late_result = ToolResult(
        tool_name=intent.action.tool_name,
        success=True,
        content={"trusted_late_controller_result": True},
        duration_ms=0,
    )
    completed = await store.complete_action(
        claim=original,
        agent_lease=original_agent,
        result=late_result,
    )
    assert completed.status == "succeeded"
    async with store.engine.connect() as connection:
        outbox_status = (
            await connection.execute(
                select(action_reconciliation_outbox.c.status).where(
                    action_reconciliation_outbox.c.action_id
                    == intent.idempotency_key
                )
            )
        ).scalar_one()
    assert outbox_status == "completed"
    await store.close()


@pytest.mark.asyncio
async def test_late_executor_and_reconciler_cannot_commit_conflicting_duplicates(
    tmp_path,
) -> None:
    store, record, _, intent = await _queued_intent(tmp_path, suffix="c")
    original_agent = await _cluster_agent(
        store,
        instance_id="executor-original",
    )
    original = await store.claim_action_execution(
        agent_lease=original_agent,
        owner_id="executor-original",
        attempt_id="original-late-result",
        ttl_seconds=60,
    )
    assert original is not None
    await store.mark_action_dispatched(
        original,
        agent_lease=original_agent,
    )
    await store.mark_action_unknown(
        claim=original,
        agent_lease=original_agent,
        reason="original Executor response was delayed",
    )
    await _expire_action_for_reconciliation(store, intent.idempotency_key)
    reconciliation_agent = await _cluster_agent(
        store,
        instance_id="executor-reconciler",
    )
    reconciliation = await store.claim_action_reconciliation(
        agent_lease=reconciliation_agent,
        owner_id="executor-reconciler",
        ttl_seconds=60,
    )
    assert reconciliation is not None
    result = ToolResult(
        tool_name=intent.action.tool_name,
        success=True,
        content={
            "sentinel_remediation": intent.idempotency_key,
            "controller_phase": "Succeeded",
            "deterministic": True,
        },
        duration_ms=0,
    )

    outcomes = await asyncio.gather(
        store.complete_action(
            claim=original,
            agent_lease=original_agent,
            result=result,
        ),
        store.complete_action_reconciliation(
            reconciliation,
            agent_lease=reconciliation_agent,
            result=result,
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(item, Exception) for item in outcomes) >= 1
    final = await store.latest_action_intent(record.id)
    assert final is not None
    assert final.status == "succeeded"
    assert final.result == result
    succeeded_events = [
        event
        for event in await store.list_audit_events(record.id)
        if event.event_type == "action.succeeded"
    ]
    assert len(succeeded_events) == 1
    await store.close()
