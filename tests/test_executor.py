from __future__ import annotations

import asyncio

import pytest

from sentinelops.config import Settings
from sentinelops.domain import Alert, ToolResult
from sentinelops.executor import ExecutorWorker
from sentinelops.runtime import build_agent
from sentinelops.storage import ActionIntentConflictError, SqlIncidentStore
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
        precondition={"resource_version": "17"},
    )
    await store.enqueue_action(lease, idempotency_key=intent.idempotency_key)
    return store, record, lease, intent


@pytest.mark.asyncio
async def test_executor_is_the_only_component_that_calls_write_backend(tmp_path) -> None:
    store, record, _, intent = await _queued_intent(tmp_path)
    backend = RecordingWriteBackend()
    worker = ExecutorWorker(
        store,
        ToolRegistry(backend),
        owner_id="executor-a",
    )

    assert await worker.run_once() is True

    completed = await store.latest_action_intent(record.id)
    assert completed is not None
    assert completed.idempotency_key == intent.idempotency_key
    assert completed.status == "succeeded"
    assert len(backend.calls) == 1
    assert backend.calls[0][0] == record.approval.action.tool_name
    await store.close()


@pytest.mark.asyncio
async def test_resolved_after_claim_before_dispatch_causes_zero_writes(tmp_path) -> None:
    store, record, _, intent = await _queued_intent(tmp_path)
    claim = await store.claim_action_execution(
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
        await store.mark_action_dispatched(claim)

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
        precondition={"resource_version": "17"},
    )
    await store.enqueue_action(lease, idempotency_key=tampered.idempotency_key)
    claim = await store.claim_action_execution(
        owner_id="executor-a",
        attempt_id="tampered-attempt",
        ttl_seconds=60,
    )
    assert claim is not None

    with pytest.raises(
        ActionIntentConflictError,
        match="已批准的动作或审批版本不一致",
    ):
        await store.mark_action_dispatched(claim)
    await store.close()


@pytest.mark.asyncio
async def test_expired_claim_is_requeued_and_stale_attempt_is_fenced(tmp_path) -> None:
    store, record, _, _ = await _queued_intent(tmp_path)
    stale = await store.claim_action_execution(
        owner_id="executor-a",
        attempt_id="stale-attempt",
        ttl_seconds=-1,
    )
    assert stale is not None
    current = await store.claim_action_execution(
        owner_id="executor-b",
        attempt_id="current-attempt",
        ttl_seconds=60,
    )
    assert current is not None
    assert current.generation == stale.generation + 1

    with pytest.raises(ActionIntentConflictError):
        await store.mark_action_dispatched(stale)
    dispatched = await store.mark_action_dispatched(current)
    assert dispatched.status == "dispatched"
    assert dispatched.attempt_id == "current-attempt"
    assert dispatched.incident_id == record.id
    await store.close()


@pytest.mark.asyncio
async def test_dispatched_crash_becomes_unknown_and_late_result_is_bound_to_attempt(
    tmp_path,
) -> None:
    store, record, _, _ = await _queued_intent(tmp_path)
    claim = await store.claim_action_execution(
        owner_id="executor-a",
        attempt_id="immutable-attempt",
        ttl_seconds=0.1,
    )
    assert claim is not None
    await store.mark_action_dispatched(claim)
    await asyncio.sleep(1.1)

    assert (
        await store.claim_action_execution(
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
    completed = await store.complete_action(claim=claim, result=late_result)
    assert completed.status == "succeeded"
    assert completed.result == late_result
    assert await store.complete_action(claim=claim, result=late_result) == completed

    conflicting = ToolResult(
        tool_name=unknown.action.tool_name,
        success=False,
        error="conflicting late result",
    )
    with pytest.raises(ActionIntentConflictError):
        await store.complete_action(claim=claim, result=conflicting)
    await store.close()
