from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import delete

from sentinelops.domain import Alert, IncidentRecord
from sentinelops.storage import SqlIncidentStore
from sentinelops.storage.sqlalchemy import audit_anchor_outbox

DATABASE_URL = os.getenv("SENTINELOPS_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="SENTINELOPS_TEST_DATABASE_URL is only configured in PostgreSQL CI",
)


@pytest.mark.asyncio
async def test_postgres_serializes_concurrent_audit_appends_per_incident() -> None:
    assert DATABASE_URL is not None
    audit_key = "postgres-audit-contract-key-000001"
    first = SqlIncidentStore(
        DATABASE_URL,
        audit_hmac_key=audit_key,
        audit_key_id="postgres-contract-v1",
    )
    second = SqlIncidentStore(
        DATABASE_URL,
        audit_hmac_key=audit_key,
        audit_key_id="postgres-contract-v1",
    )
    record = IncidentRecord(
        alert=Alert(
            name="ConcurrentAuditContract",
            namespace="sentinelops-tests",
            service="order-service",
            severity="warning",
            summary="serialize per-incident audit writers",
        )
    )
    await first.save(record, expected_version=None, graph_state=None)

    async def append(store: SqlIncidentStore, index: int) -> None:
        async with store.engine.begin() as connection:
            await store._append_audit_event(
                connection,
                incident_id=record.id,
                operation_id=f"postgres-contract:{index}",
                event_type="contract.concurrent_append",
                source_component="test",
                actor_type="system",
                actor_id=f"writer-{index % 2}",
                actor_assurance="internal",
                subject_type="incident",
                subject_id=record.id,
                payload={"index": index},
            )

    await asyncio.gather(
        *[
            append(first if index % 2 == 0 else second, index)
            for index in range(20)
        ]
    )

    events = await first.list_audit_events(record.id)
    verification = await first.verify_audit_chain(record.id)
    assert verification.valid is True
    assert [event.sequence for event in events] == list(
        range(1, len(events) + 1)
    )
    assert len(events) == 21
    await first.close()
    await second.close()


@pytest.mark.asyncio
async def test_postgres_anchor_claim_uses_skip_locked_and_cas() -> None:
    assert DATABASE_URL is not None
    audit_key = "postgres-anchor-contract-key-00001"
    first = SqlIncidentStore(
        DATABASE_URL,
        audit_hmac_key=audit_key,
        audit_key_id="postgres-anchor-v1",
    )
    second = SqlIncidentStore(
        DATABASE_URL,
        audit_hmac_key=audit_key,
        audit_key_id="postgres-anchor-v1",
    )
    async with first.engine.begin() as connection:
        await connection.execute(delete(audit_anchor_outbox))
    record = IncidentRecord(
        alert=Alert(
            name="ConcurrentAnchorClaim",
            namespace="sentinelops-tests",
            service="payments",
            severity="warning",
            summary="only one publisher may own an anchor attempt",
        )
    )
    await first.save(record, expected_version=None, graph_state=None)

    claims = await asyncio.gather(
        first.claim_audit_anchor(owner_id="publisher-a", ttl_seconds=60),
        second.claim_audit_anchor(owner_id="publisher-b", ttl_seconds=60),
    )
    owned = [claim for claim in claims if claim is not None]

    assert len(owned) == 1
    assert owned[0].anchor.incident_id == record.id
    await first.complete_audit_anchor(
        owned[0],
        receipt={"receipt_id": "postgres-contract"},
    )
    assert (
        await second.claim_audit_anchor(
            owner_id="publisher-b",
            ttl_seconds=60,
        )
        is None
    )
    await first.close()
    await second.close()
