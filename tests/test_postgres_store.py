from __future__ import annotations

import asyncio
import os

import pytest

from sentinelops.config import Settings
from sentinelops.domain import Alert, TimelineEvent, ToolResult
from sentinelops.runtime import build_agent
from sentinelops.storage import LeaseConflictError, SqlIncidentStore, StoreConflictError

DATABASE_URL = os.getenv("SENTINELOPS_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="SENTINELOPS_TEST_DATABASE_URL is only configured in the PostgreSQL contract job",
)


@pytest.mark.asyncio
async def test_postgres_roundtrip_and_compare_and_swap() -> None:
    assert DATABASE_URL is not None
    agent = build_agent(
        Settings(tool_backend="simulator", model_provider="rule_based")
    )
    record = await agent.start(
        Alert(
            name="PostgresContractErrorRate",
            namespace="sentinelops-demo",
            service="order-service",
            severity="critical",
            summary="PostgreSQL durable store contract",
        )
    )
    first = SqlIncidentStore(DATABASE_URL)
    second = SqlIncidentStore(DATABASE_URL)
    await first.setup()
    try:
        created = await first.save(
            record,
            expected_version=None,
            graph_state=await agent.export_state(record.id),
        )
        stale = await second.get(record.id)
        assert stale is not None
        assert stale.record.approval == record.approval

        current_record = created.record.model_copy(deep=True)
        current_record.timeline.append(
            TimelineEvent(type="postgres.contract", message="CAS winner")
        )
        updated = await first.save(
            current_record,
            expected_version=created.version,
            graph_state=created.graph_state,
        )
        assert updated.version == 2

        with pytest.raises(StoreConflictError):
            await second.save(
                stale.record,
                expected_version=stale.version,
                graph_state=stale.graph_state,
            )

        assert record.approval is not None
        await first.claim_approval(
            record.id,
            approval_id=record.approval.approval_id,
            approval_version=record.approval.version,
            approved=True,
            note="PostgreSQL action contract",
        )
        lease = await first.acquire_lease(
            record.id,
            owner_id="postgres-worker-a",
            ttl_seconds=60,
        )
        with pytest.raises(LeaseConflictError):
            await second.acquire_lease(
                record.id,
                owner_id="postgres-worker-b",
                ttl_seconds=60,
            )
        intent = await first.prepare_action(
            lease,
            idempotency_key=record.id.replace("-", "").ljust(64, "0")[:64],
            action=record.approval.action,
            precondition={"resource_version": "postgres-contract"},
        )
        await first.enqueue_action(lease, idempotency_key=intent.idempotency_key)
        claim = await first.claim_action_execution(
            owner_id="postgres-executor-a",
            attempt_id="postgres-contract-attempt",
            ttl_seconds=60,
        )
        assert claim is not None
        await first.mark_action_dispatched(claim)
        completed = await first.complete_action(
            claim=claim,
            result=ToolResult(
                tool_name=record.approval.action.tool_name,
                success=True,
                content={"postgres_contract": True},
            ),
        )
        assert completed.status == "succeeded"
    finally:
        await first.close()
        await second.close()


@pytest.mark.asyncio
async def test_postgres_serializes_resolved_against_action_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert DATABASE_URL is not None
    agent = build_agent(
        Settings(tool_backend="simulator", model_provider="rule_based")
    )
    record = await agent.start(
        Alert(
            name="PostgresResolvedDispatchRace",
            namespace="sentinelops-demo",
            service="order-service",
            severity="critical",
            summary="resolved and dispatch race",
        )
    )
    assert record.approval is not None
    worker = SqlIncidentStore(DATABASE_URL)
    webhook = SqlIncidentStore(DATABASE_URL)
    await worker.setup()
    await worker.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    await worker.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="concurrent race",
    )
    lease = await worker.acquire_lease(
        record.id,
        owner_id="postgres-race-worker",
        ttl_seconds=60,
    )
    intent = await worker.prepare_action(
        lease,
        idempotency_key=record.id.replace("-", "").ljust(64, "9")[:64],
        action=record.approval.action,
        precondition={"resource_version": "race"},
    )
    await worker.enqueue_action(lease, idempotency_key=intent.idempotency_key)
    claim = await worker.claim_action_execution(
        owner_id="postgres-race-executor",
        attempt_id="postgres-race-attempt",
        ttl_seconds=60,
    )
    assert claim is not None
    incident_locked = asyncio.Event()
    allow_dispatch_commit = asyncio.Event()
    original_guard = worker._assert_dispatch_allowed

    async def gated_guard(connection, incident_id, **kwargs):
        await original_guard(connection, incident_id, **kwargs)
        incident_locked.set()
        await allow_dispatch_commit.wait()

    monkeypatch.setattr(worker, "_assert_dispatch_allowed", gated_guard)
    dispatch_task = asyncio.create_task(
        worker.mark_action_dispatched(claim)
    )
    await asyncio.wait_for(incident_locked.wait(), timeout=5)
    resolved_task = asyncio.create_task(
        webhook.record_alert_resolved(
            record.id,
            fingerprint="postgres-race",
        )
    )
    await asyncio.sleep(0.05)
    assert not resolved_task.done()

    allow_dispatch_commit.set()
    dispatched = await dispatch_task
    resolution = await resolved_task

    assert dispatched.status == "dispatched"
    assert resolution is not None
    assert resolution.record.status.value == "escalated"
    assert resolution.record.timeline[-1].data["execution_outcome"] == "unknown"
    await worker.close()
    await webhook.close()


@pytest.mark.asyncio
async def test_postgres_two_executors_can_claim_intent_only_once() -> None:
    assert DATABASE_URL is not None
    agent = build_agent(
        Settings(tool_backend="simulator", model_provider="rule_based")
    )
    record = await agent.start(
        Alert(
            name="PostgresExecutorClaim",
            namespace="sentinelops-demo",
            service="order-service",
            severity="critical",
            summary="two executors race for one intent",
        )
    )
    assert record.approval is not None
    first = SqlIncidentStore(DATABASE_URL)
    second = SqlIncidentStore(DATABASE_URL)
    await first.setup()
    try:
        await first.save(
            record,
            expected_version=None,
            graph_state=await agent.export_state(record.id),
        )
        await first.claim_approval(
            record.id,
            approval_id=record.approval.approval_id,
            approval_version=record.approval.version,
            approved=True,
            note="executor claim race",
        )
        lease = await first.acquire_lease(
            record.id,
            owner_id="agent-worker",
            ttl_seconds=60,
        )
        intent = await first.prepare_action(
            lease,
            idempotency_key=record.id.replace("-", "").ljust(64, "7")[:64],
            action=record.approval.action,
            precondition={"resource_version": "executor-race"},
        )
        await first.enqueue_action(lease, idempotency_key=intent.idempotency_key)

        claims = await asyncio.gather(
            first.claim_action_execution(
                owner_id="executor-a",
                attempt_id=f"{record.id}-a",
                ttl_seconds=60,
            ),
            second.claim_action_execution(
                owner_id="executor-b",
                attempt_id=f"{record.id}-b",
                ttl_seconds=60,
            ),
        )

        winners = [claim for claim in claims if claim is not None]
        assert len(winners) == 1
        dispatched = await first.mark_action_dispatched(winners[0])
        assert dispatched.status == "dispatched"
    finally:
        await first.close()
        await second.close()


@pytest.mark.asyncio
async def test_postgres_resolved_before_executor_claim_cancels_without_dispatch() -> None:
    assert DATABASE_URL is not None
    agent = build_agent(
        Settings(tool_backend="simulator", model_provider="rule_based")
    )
    record = await agent.start(
        Alert(
            name="PostgresResolvedBeforeClaim",
            namespace="sentinelops-demo",
            service="order-service",
            severity="critical",
            summary="resolved wins before executor claim",
        )
    )
    assert record.approval is not None
    store = SqlIncidentStore(DATABASE_URL)
    await store.setup()
    try:
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
            note="resolved before claim",
        )
        lease = await store.acquire_lease(
            record.id,
            owner_id="agent-worker",
            ttl_seconds=60,
        )
        intent = await store.prepare_action(
            lease,
            idempotency_key=record.id.replace("-", "").ljust(64, "8")[:64],
            action=record.approval.action,
            precondition={"resource_version": "resolved-first"},
        )
        await store.enqueue_action(lease, idempotency_key=intent.idempotency_key)

        resolution = await store.record_alert_resolved(
            record.id,
            fingerprint=f"resolved-{record.id}",
        )
        assert resolution is not None
        assert resolution.record.timeline[-1].data["execution_outcome"] == (
            "not_dispatched"
        )
        assert (
            await store.claim_action_execution(
                owner_id="executor-a",
                attempt_id=f"{record.id}-must-not-claim",
                ttl_seconds=60,
            )
            is None
        )
        cancelled = await store.latest_action_intent(record.id)
        assert cancelled is not None
        assert cancelled.status == "cancelled"
    finally:
        await store.close()
