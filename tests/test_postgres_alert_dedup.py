from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from sentinelops.domain import Alert, IncidentRecord, IncidentStatus, TimelineEvent
from sentinelops.storage import SqlIncidentStore

DATABASE_URL = os.getenv("SENTINELOPS_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="SENTINELOPS_TEST_DATABASE_URL is only configured in PostgreSQL CI",
)


def _placeholder(
    fingerprint: str,
    starts_at: datetime,
    sequence: int,
) -> IncidentRecord:
    return IncidentRecord(
        alert=Alert(
            name="PostgresAlertDedup",
            namespace="sentinelops-postgres",
            service="order-service",
            severity="critical",
            summary=f"concurrent delivery {sequence}",
            starts_at=starts_at,
            labels={
                "source": "alertmanager",
                "alertmanager_source_id": "postgres-contract",
                "alertmanager_fingerprint": fingerprint,
            },
        ),
        status=IncidentStatus.INVESTIGATING,
        timeline=[
            TimelineEvent(
                type="alertmanager.received",
                message="PostgreSQL dedup contract",
                data={"fingerprint": fingerprint},
            )
        ],
    )


@pytest.mark.asyncio
async def test_postgres_many_concurrent_firings_create_one_incident() -> None:
    assert DATABASE_URL is not None
    first = SqlIncidentStore(DATABASE_URL)
    second = SqlIncidentStore(DATABASE_URL)
    fingerprint = f"postgres-concurrent-{uuid4()}"
    starts_at = datetime.now(UTC)

    claims = await asyncio.gather(
        *[
            (first if index % 2 == 0 else second).claim_alert_firing(
                _placeholder(fingerprint, starts_at, index),
                source_id="postgres-contract",
                fingerprint=fingerprint,
                starts_at=starts_at,
            )
            for index in range(20)
        ]
    )

    assert sum(claim.outcome == "accepted" for claim in claims) == 1
    assert sum(claim.outcome == "deduplicated" for claim in claims) == 19
    assert len({claim.incident_id for claim in claims}) == 1
    await first.close()
    await second.close()


@pytest.mark.asyncio
async def test_postgres_old_resolution_cannot_close_new_occurrence() -> None:
    assert DATABASE_URL is not None
    first = SqlIncidentStore(DATABASE_URL)
    second = SqlIncidentStore(DATABASE_URL)
    fingerprint = f"postgres-recurrence-{uuid4()}"
    first_start = datetime.now(UTC)
    second_start = first_start + timedelta(hours=1)

    first_claim = await first.claim_alert_firing(
        _placeholder(fingerprint, first_start, 1),
        source_id="postgres-contract",
        fingerprint=fingerprint,
        starts_at=first_start,
    )
    await second.resolve_alert(
        source_id="postgres-contract",
        fingerprint=fingerprint,
        starts_at=first_start,
        resolved_at=first_start + timedelta(minutes=5),
    )
    second_claim, old_resolution = await asyncio.gather(
        second.claim_alert_firing(
            _placeholder(fingerprint, second_start, 2),
            source_id="postgres-contract",
            fingerprint=fingerprint,
            starts_at=second_start,
        ),
        first.resolve_alert(
            source_id="postgres-contract",
            fingerprint=fingerprint,
            starts_at=first_start,
            resolved_at=first_start + timedelta(minutes=5),
        ),
    )

    assert first_claim.incident_id != second_claim.incident_id
    assert old_resolution.outcome in {"duplicate", "stale"}
    assert (
        await first.active_alert_incident(
            source_id="postgres-contract",
            fingerprint=fingerprint,
        )
        == second_claim.incident_id
    )
    latest = await first.get(second_claim.incident_id or "")
    assert latest is not None
    assert latest.record.status == IncidentStatus.INVESTIGATING
    await first.close()
    await second.close()
