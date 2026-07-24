from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import update

from sentinelops import api as api_module
from sentinelops.domain import Alert, IncidentRecord
from sentinelops.metrics import render_prometheus_metrics
from sentinelops.storage import SqlIncidentStore
from sentinelops.storage.sqlalchemy import audit_anchor_outbox


def _record() -> IncidentRecord:
    return IncidentRecord(
        alert=Alert(
            name="AuditAnchorMetrics",
            namespace="sentinelops-tests",
            service="checkout",
            severity="warning",
            summary="verify low-cardinality audit-anchor metrics",
        )
    )


@pytest.mark.asyncio
async def test_anchor_metrics_are_database_backed_and_low_cardinality(
    tmp_path,
) -> None:
    secret = "metrics-secret-that-must-never-be-exported"
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'metrics.db'}",
        audit_hmac_key=secret,
        audit_key_id="metrics-test-v1",
    )
    await store.setup()
    record = _record()
    await store.save(record, expected_version=None, graph_state=None)
    await store.set_audit_anchor_security_state(
        status="initializing",
        write_blocked=True,
        reason="sensitive internal reason",
        successful=False,
    )

    snapshot = await store.audit_anchor_metrics()
    rendered = render_prometheus_metrics(snapshot)

    assert snapshot.status_counts["pending"] == 1
    assert snapshot.oldest_undelivered_age_seconds >= 0
    assert (
        'sentinelops_audit_anchor_outbox_items{status="pending"} 1'
        in rendered
    )
    assert "sentinelops_audit_anchor_security_write_blocked 1" in rendered
    assert (
        'sentinelops_audit_anchor_security_state{status="initializing"} 1'
        in rendered
    )
    assert record.id not in rendered
    assert secret not in rendered
    assert "sensitive internal reason" not in rendered
    assert "reason_sha256" not in rendered
    await store.close()


@pytest.mark.asyncio
async def test_anchor_metrics_track_delivery_and_dead_letter_separately(
    tmp_path,
) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'metrics-status.db'}"
    )
    await store.setup()
    first = _record()
    second = _record()
    await store.save(first, expected_version=None, graph_state=None)
    await store.save(second, expected_version=None, graph_state=None)
    claim = await store.claim_audit_anchor(owner_id="metrics", ttl_seconds=60)
    assert claim is not None
    await store.complete_audit_anchor(claim, receipt={"receipt_id": "ok"})
    async with store.engine.begin() as connection:
        await connection.execute(
            update(audit_anchor_outbox)
            .where(audit_anchor_outbox.c.incident_id == second.id)
            .values(
                status="dead_letter",
                next_attempt_at=datetime.now(UTC).isoformat(),
            )
        )

    snapshot = await store.audit_anchor_metrics()
    rendered = render_prometheus_metrics(snapshot)

    assert snapshot.status_counts["delivered"] == 1
    assert snapshot.status_counts["dead_letter"] == 1
    assert snapshot.oldest_undelivered_age_seconds == 0
    assert snapshot.last_delivered_at is not None
    assert "sentinelops_audit_anchor_dead_letter_items 1" in rendered
    assert (
        "sentinelops_audit_anchor_oldest_delivery_age_seconds 0.000000"
        in rendered
    )
    await store.close()


def test_empty_metrics_snapshot_is_explicitly_safe() -> None:
    rendered = render_prometheus_metrics(None)

    for status in ("pending", "claimed", "delivered", "dead_letter"):
        assert (
            f'sentinelops_audit_anchor_outbox_items{{status="{status}"}} 0'
            in rendered
        )
    assert "sentinelops_audit_anchor_security_write_blocked 0" in rendered


@pytest.mark.asyncio
async def test_metrics_endpoint_exports_database_snapshot(
    tmp_path,
    monkeypatch,
) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'metrics-api.db'}"
    )
    await store.setup()
    await store.save(_record(), expected_version=None, graph_state=None)
    monkeypatch.setattr(api_module, "incident_store", store)

    response = await api_module.metrics()

    assert response.media_type == "text/plain; version=0.0.4"
    assert b"sentinelops_audit_anchor_outbox_items" in response.body
    await store.close()
