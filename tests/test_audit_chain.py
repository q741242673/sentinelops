from __future__ import annotations

import pytest
from sqlalchemy import delete, select, update

from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentStatus, ToolResult
from sentinelops.runtime import build_agent
from sentinelops.storage import SqlIncidentStore, StoreConflictError
from sentinelops.storage.audit import canonical_payload_hash
from sentinelops.storage.sqlalchemy import (
    approvals,
    audit_events,
    audit_heads,
)

AUDIT_KEY = "audit-chain-test-key-000000000001"
AUDIT_KEY_ID = "test-audit-v1"


def _database_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}"


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
    assert record.approval is not None
    return agent, record


async def _store(tmp_path) -> SqlIncidentStore:
    store = SqlIncidentStore(
        _database_url(tmp_path),
        audit_hmac_key=AUDIT_KEY,
        audit_key_id=AUDIT_KEY_ID,
    )
    await store.setup()
    return store


@pytest.mark.asyncio
async def test_hmac_audit_chain_covers_approval_and_action_boundary(tmp_path) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    store = await _store(tmp_path)
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
        note="operator approved",
    )
    lease = await store.acquire_lease(
        record.id,
        owner_id="api-worker-a",
        ttl_seconds=60,
    )
    intent = await store.prepare_action(
        lease,
        idempotency_key="a" * 64,
        action=record.approval.action,
        precondition={"resource_version": "17"},
    )
    await store.enqueue_action(lease, idempotency_key=intent.idempotency_key)
    claim = await store.claim_action_execution(
        owner_id="executor-a",
        attempt_id="attempt-a",
        ttl_seconds=60,
    )
    assert claim is not None
    await store.mark_action_dispatched(claim)
    await store.complete_action(
        claim=claim,
        result=ToolResult(
            tool_name=record.approval.action.tool_name,
            success=True,
            content={"revision": 1},
        ),
    )

    events = await store.list_audit_events(record.id)
    verification = await store.verify_audit_chain(record.id)
    event_types = [event.event_type for event in events]

    assert verification.valid is True
    assert verification.event_count == len(events)
    assert verification.head_sequence == len(events)
    assert all(event.auth_algorithm == "hmac-sha256" for event in events)
    assert all(event.auth_tag for event in events)
    assert AUDIT_KEY not in str(events)
    assert "approval.approved" in event_types
    assert event_types[-5:] == [
        "action.prepared",
        "action.queued",
        "action.claimed",
        "action.dispatched",
        "action.succeeded",
    ]
    await store.close()


@pytest.mark.asyncio
async def test_approval_audit_is_committed_before_agent_resume(tmp_path) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    store = await _store(tmp_path)
    await store.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )

    await store.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=False,
        note="stop before agent resume",
    )

    events = await store.list_audit_events(record.id)
    assert events[-1].event_type == "approval.rejected"
    assert events[-1].actor_assurance == "unverified"
    assert "stop before agent resume" not in str(events[-1].payload)
    assert (await store.verify_audit_chain(record.id)).valid is True
    await store.close()


@pytest.mark.asyncio
async def test_approval_audit_records_verified_oidc_principal_hash(
    tmp_path,
) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    store = await _store(tmp_path)
    await store.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    principal_hash = "f" * 64

    await store.claim_approval(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=False,
        note="verified operator rejected",
        actor_id=principal_hash,
        actor_assurance="oidc-human",
    )

    event = (await store.list_audit_events(record.id))[-1]
    assert event.actor_id == principal_hash
    assert event.actor_assurance == "oidc-human"
    assert "verified operator rejected" not in str(event.payload)
    await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    ["payload", "delete-middle", "delete-tail", "head"],
)
async def test_audit_verifier_detects_database_tampering(tmp_path, tamper: str) -> None:
    _, record = await _paused_incident()
    store = await _store(tmp_path)
    await store.save(record, expected_version=None, graph_state=None)
    original = await store.list_audit_events(record.id)
    assert len(original) >= 3

    async with store.engine.begin() as connection:
        if tamper == "payload":
            await connection.execute(
                update(audit_events)
                .where(
                    audit_events.c.incident_id == record.id,
                    audit_events.c.sequence == 1,
                )
                .values(payload={"forged": True})
            )
        elif tamper == "delete-middle":
            await connection.execute(
                delete(audit_events).where(
                    audit_events.c.incident_id == record.id,
                    audit_events.c.sequence == 2,
                )
            )
        elif tamper == "delete-tail":
            await connection.execute(
                delete(audit_events).where(
                    audit_events.c.incident_id == record.id,
                    audit_events.c.sequence == len(original),
                )
            )
        else:
            await connection.execute(
                update(audit_heads)
                .where(audit_heads.c.incident_id == record.id)
                .values(last_hash="f" * 64)
            )

    verification = await store.verify_audit_chain(record.id)
    assert verification.valid is False
    assert verification.errors
    await store.close()


@pytest.mark.asyncio
async def test_wrong_audit_key_cannot_verify_hmac_events(tmp_path) -> None:
    _, record = await _paused_incident()
    store = await _store(tmp_path)
    await store.save(record, expected_version=None, graph_state=None)
    await store.close()

    wrong_key_store = SqlIncidentStore(
        _database_url(tmp_path),
        audit_hmac_key="wrong-audit-key-0000000000000001",
        audit_key_id=AUDIT_KEY_ID,
    )
    verification = await wrong_key_store.verify_audit_chain(record.id)

    assert verification.valid is False
    assert any("HMAC" in error for error in verification.errors)
    await wrong_key_store.close()


@pytest.mark.asyncio
async def test_audit_failure_rolls_back_approval_decision(tmp_path) -> None:
    agent, record = await _paused_incident()
    assert record.approval is not None
    store = await _store(tmp_path)
    await store.save(
        record,
        expected_version=None,
        graph_state=await agent.export_state(record.id),
    )
    async with store.engine.begin() as connection:
        await connection.execute(
            delete(audit_heads).where(audit_heads.c.incident_id == record.id)
        )

    with pytest.raises(StoreConflictError, match="缺少审计 head"):
        await store.claim_approval(
            record.id,
            approval_id=record.approval.approval_id,
            approval_version=record.approval.version,
            approved=True,
            note="must roll back",
        )

    async with store.engine.connect() as connection:
        status = (
            await connection.execute(
                select(approvals.c.status).where(
                    approvals.c.approval_id == record.approval.approval_id
                )
            )
        ).scalar_one()
    assert status == "pending"
    await store.close()


def test_canonical_payload_hash_ignores_mapping_insertion_order() -> None:
    first = {"service": "orders", "details": {"revision": 3, "ready": True}}
    second = {"details": {"ready": True, "revision": 3}, "service": "orders"}

    assert canonical_payload_hash(first) == canonical_payload_hash(second)
