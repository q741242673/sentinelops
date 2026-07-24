from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from sentinelops.audit_anchor import (
    RECEIPT_PROTOCOL,
    AuditAnchorDeliveryError,
    AuditAnchorPublisher,
    HttpAuditAnchorSink,
)
from sentinelops.domain import Alert, IncidentRecord
from sentinelops.storage import AuditAnchorConflictError, SqlIncidentStore
from sentinelops.storage.audit import canonical_payload_hash
from sentinelops.storage.sqlalchemy import audit_anchor_outbox, audit_events

AUDIT_KEY = "anchor-audit-key-000000000000000001"
AUDIT_KEY_ID = "anchor-test-v1"
SOURCE_ID = "test-cluster-a"
TOKEN = "anchor-delivery-token-000000000001"


def _database_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'anchor.db'}"


def _record() -> IncidentRecord:
    return IncidentRecord(
        alert=Alert(
            name="AnchorContract",
            namespace="sentinelops-tests",
            service="orders",
            severity="warning",
            summary="verify external audit anchoring",
        )
    )


async def _store(tmp_path) -> SqlIncidentStore:
    store = SqlIncidentStore(
        _database_url(tmp_path),
        audit_hmac_key=AUDIT_KEY,
        audit_key_id=AUDIT_KEY_ID,
    )
    await store.setup()
    return store


def _receipt(request: httpx.Request, *, status: str = "accepted") -> dict:
    payload = json.loads(request.content)
    return {
        "protocol_version": RECEIPT_PROTOCOL,
        "status": status,
        "anchor_id": payload["anchor_id"],
        "source_id": payload["source_id"],
        "incident_id": payload["incident_id"],
        "sequence": payload["sequence"],
        "head_hash": payload["head_hash"],
        "head_auth_tag": payload["head_auth_tag"],
        "head_committed_at": payload["head_committed_at"],
        "audit": payload["audit"],
        "previous_anchor_id": payload["previous_anchor_id"],
        "bootstrap_checkpoint": payload["bootstrap_checkpoint"],
        "receipt_id": f"receipt-{payload['anchor_id'][:16]}",
        "accepted_at": "2026-07-23T12:00:00Z",
    }


def _sink(
    handler,
) -> tuple[HttpAuditAnchorSink, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sink = HttpAuditAnchorSink(
        "https://audit.example.test/v1/anchors",
        bearer_token=TOKEN,
        source_id=SOURCE_ID,
        timeout_seconds=5,
        require_https=True,
        client=client,
    )
    return sink, client


@pytest.mark.asyncio
async def test_audit_append_enqueues_anchor_in_same_transaction(tmp_path) -> None:
    store = await _store(tmp_path)
    record = _record()
    await store.save(record, expected_version=None, graph_state=None)

    claim = await store.claim_audit_anchor(owner_id="publisher-a", ttl_seconds=60)

    assert claim is not None
    assert claim.anchor.incident_id == record.id
    assert claim.anchor.sequence == 1
    assert claim.anchor.audit_key_id == AUDIT_KEY_ID
    assert claim.anchor.audit_auth_algorithm == "hmac-sha256"
    assert claim.anchor.audit_auth_tag
    assert claim.anchor.previous_anchor_id is None
    await store.close()


@pytest.mark.asyncio
async def test_outbox_failure_rolls_back_incident_and_audit_event(tmp_path) -> None:
    store = await _store(tmp_path)
    record = _record()
    async with store.engine.begin() as connection:
        await connection.run_sync(
            lambda sync_connection: audit_anchor_outbox.drop(sync_connection)
        )

    with pytest.raises(SQLAlchemyError):
        await store.save(record, expected_version=None, graph_state=None)

    assert await store.get(record.id) is None
    assert await store.list_audit_events(record.id) == []
    await store.close()


@pytest.mark.asyncio
async def test_same_incident_anchors_are_claimed_in_sequence(tmp_path) -> None:
    store = await _store(tmp_path)
    record = _record()
    await store.save(record, expected_version=None, graph_state=None)
    async with store.engine.begin() as connection:
        await store._append_audit_event(
            connection,
            incident_id=record.id,
            operation_id="anchor-contract:second",
            event_type="contract.second",
            source_component="test",
            actor_type="system",
            actor_id="test",
            actor_assurance="internal",
            subject_type="incident",
            subject_id=record.id,
            payload={"second": True},
        )

    first = await store.claim_audit_anchor(
        owner_id="publisher-a",
        ttl_seconds=60,
    )
    assert first is not None
    assert first.anchor.sequence == 1
    assert (
        await store.claim_audit_anchor(
            owner_id="publisher-b",
            ttl_seconds=60,
        )
        is None
    )
    await store.complete_audit_anchor(
        first,
        receipt={"receipt_id": "first"},
    )
    second = await store.claim_audit_anchor(
        owner_id="publisher-b",
        ttl_seconds=60,
    )

    assert second is not None
    assert second.anchor.sequence == 2
    assert second.anchor.previous_anchor_id == first.anchor.anchor_id
    await store.close()


@pytest.mark.asyncio
async def test_expired_anchor_claim_cannot_confirm_delivery(tmp_path) -> None:
    store = await _store(tmp_path)
    await store.save(_record(), expected_version=None, graph_state=None)
    stale = await store.claim_audit_anchor(
        owner_id="publisher-a",
        ttl_seconds=60,
    )
    assert stale is not None
    async with store.engine.begin() as connection:
        await connection.execute(
            update(audit_anchor_outbox)
            .where(
                audit_anchor_outbox.c.anchor_id == stale.anchor.anchor_id
            )
            .values(claim_until="1970-01-01T00:00:00+00:00")
        )
    current = await store.claim_audit_anchor(
        owner_id="publisher-b",
        ttl_seconds=60,
    )

    assert current is not None
    assert current.generation == stale.generation + 1
    with pytest.raises(AuditAnchorConflictError, match="失效"):
        await store.complete_audit_anchor(
            stale,
            receipt={"receipt_id": "stale"},
        )
    await store.complete_audit_anchor(
        current,
        receipt={"receipt_id": "current"},
    )
    await store.close()


@pytest.mark.asyncio
async def test_http_sink_sends_deterministic_minimal_request_and_strict_receipt(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    await store.save(_record(), expected_version=None, graph_state=None)
    claim = await store.claim_audit_anchor(owner_id="publisher-a", ttl_seconds=60)
    assert claim is not None
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json=_receipt(request),
            headers={"Content-Type": "application/json"},
        )

    sink, client = _sink(handler)
    try:
        first = await sink.publish(claim.anchor)
        second = await sink.publish(claim.anchor)
    finally:
        await client.aclose()

    assert first == second
    assert len(requests) == 2
    assert requests[0].content == requests[1].content
    assert requests[0].headers["idempotency-key"] == claim.anchor.anchor_id
    assert requests[0].headers["authorization"] == f"Bearer {TOKEN}"
    payload = json.loads(requests[0].content)
    assert payload["incident_id"] == claim.anchor.incident_id
    assert payload["head_hash"] == claim.anchor.head_hash
    assert "payload" not in payload
    assert "logs" not in payload
    await store.close()


@pytest.mark.asyncio
async def test_publisher_dead_letters_local_tampering_without_http(tmp_path) -> None:
    store = await _store(tmp_path)
    record = _record()
    await store.save(record, expected_version=None, graph_state=None)
    async with store.engine.begin() as connection:
        await connection.execute(
            update(audit_events)
            .where(
                audit_events.c.incident_id == record.id,
                audit_events.c.sequence == 1,
            )
            .values(payload={"tampered": True})
        )
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("tampered local chain must not be published")

    sink, client = _sink(handler)
    publisher = AuditAnchorPublisher(
        store,
        sink,
        owner_id="publisher-a",
        claim_ttl_seconds=60,
        poll_interval_seconds=0.1,
        retry_base_seconds=1,
        retry_max_seconds=10,
    )
    try:
        assert await publisher.run_once() is True
    finally:
        await client.aclose()

    async with store.engine.connect() as connection:
        row = (
            await connection.execute(select(audit_anchor_outbox))
        ).mappings().one()
    assert calls == 0
    assert row["status"] == "dead_letter"
    assert row["last_error_sha256"] == canonical_payload_hash(
        "local_chain_invalid"
    )
    await store.close()


@pytest.mark.asyncio
async def test_retryable_delivery_failure_keeps_only_error_hash(tmp_path) -> None:
    store = await _store(tmp_path)
    await store.save(_record(), expected_version=None, graph_state=None)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            text=f"upstream leaked {TOKEN}",
        )

    sink, client = _sink(handler)
    publisher = AuditAnchorPublisher(
        store,
        sink,
        owner_id="publisher-a",
        claim_ttl_seconds=60,
        poll_interval_seconds=0.1,
        retry_base_seconds=1,
        retry_max_seconds=10,
    )
    try:
        assert await publisher.run_once() is True
    finally:
        await client.aclose()

    async with store.engine.connect() as connection:
        row = (
            await connection.execute(select(audit_anchor_outbox))
        ).mappings().one()
    assert row["status"] == "pending"
    assert row["last_error_sha256"] == canonical_payload_hash("http_500")
    assert TOKEN not in str(dict(row))
    await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "mutate", "category"),
    [
        (202, None, "http_202"),
        (200, "anchor_id", "receipt_echo_mismatch"),
        (200, "status", "receipt_not_accepted"),
    ],
)
async def test_sink_rejects_unconfirmed_receipts(
    tmp_path,
    status_code: int,
    mutate: str | None,
    category: str,
) -> None:
    store = await _store(tmp_path)
    await store.save(_record(), expected_version=None, graph_state=None)
    claim = await store.claim_audit_anchor(owner_id="publisher-a", ttl_seconds=60)
    assert claim is not None

    def handler(request: httpx.Request) -> httpx.Response:
        receipt = _receipt(request)
        if mutate == "anchor_id":
            receipt["anchor_id"] = "f" * 64
        elif mutate == "status":
            receipt["status"] = "queued"
        return httpx.Response(
            status_code,
            json=receipt,
            headers={"Content-Type": "application/json"},
        )

    sink, client = _sink(handler)
    try:
        with pytest.raises(AuditAnchorDeliveryError) as exc_info:
            await sink.publish(claim.anchor)
    finally:
        await client.aclose()

    assert exc_info.value.category == category
    assert exc_info.value.retryable is False
    assert TOKEN not in str(exc_info.value)
    await store.close()


def test_production_sink_rejects_unsafe_url() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        HttpAuditAnchorSink(
            "http://audit.example.test/v1/anchors",
            bearer_token=TOKEN,
            source_id=SOURCE_ID,
            timeout_seconds=5,
            require_https=True,
        )
    with pytest.raises(ValueError, match="query"):
        HttpAuditAnchorSink(
            "https://audit.example.test/v1/anchors?token=unsafe",
            bearer_token=TOKEN,
            source_id=SOURCE_ID,
            timeout_seconds=5,
            require_https=True,
        )
