from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from sentinelops.domain import (
    Alert,
    IncidentRecord,
    IncidentStatus,
    TimelineEvent,
)
from sentinelops.storage import SqlIncidentStore

SOURCE_ID = "cluster-a/alertmanager-main"
FINGERPRINT = "alert-fingerprint-001"
T1 = datetime(2026, 7, 23, 8, 0, tzinfo=UTC)
T2 = T1 + timedelta(hours=1)


def _database_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'alert-dedup.db'}"


def _placeholder(name: str, *, starts_at: datetime = T1) -> IncidentRecord:
    return IncidentRecord(
        alert=Alert(
            name="HighOrderServiceErrorRate",
            namespace="payments",
            service="order-service",
            severity="critical",
            summary=name,
            starts_at=starts_at,
            labels={
                "source": "alertmanager",
                "alertmanager_source_id": SOURCE_ID,
                "alertmanager_fingerprint": FINGERPRINT,
            },
        ),
        status=IncidentStatus.INVESTIGATING,
        timeline=[
            TimelineEvent(
                type="alertmanager.received",
                message="received",
                data={"fingerprint": FINGERPRINT},
            )
        ],
    )


async def _stores(tmp_path) -> tuple[SqlIncidentStore, SqlIncidentStore]:
    first = SqlIncidentStore(_database_url(tmp_path))
    second = SqlIncidentStore(_database_url(tmp_path))
    await first.setup()
    return first, second


async def test_two_stores_claim_same_firing_exactly_once(tmp_path) -> None:
    first, second = await _stores(tmp_path)
    first_record = _placeholder("replica-a")
    second_record = _placeholder("replica-b")

    claims = await asyncio.gather(
        first.claim_alert_firing(
            first_record,
            source_id=SOURCE_ID,
            fingerprint=FINGERPRINT,
            starts_at=T1,
        ),
        second.claim_alert_firing(
            second_record,
            source_id=SOURCE_ID,
            fingerprint=FINGERPRINT,
            starts_at=T1,
        ),
    )

    assert sorted(claim.outcome for claim in claims) == [
        "accepted",
        "deduplicated",
    ]
    assert len({claim.incident_id for claim in claims}) == 1
    incidents = await first.list()
    assert len(incidents) == 1
    assert len(incidents[0].record.timeline) == 1
    await first.close()
    await second.close()


async def test_resolved_on_other_store_is_durable_and_idempotent(tmp_path) -> None:
    first, second = await _stores(tmp_path)
    claim = await first.claim_alert_firing(
        _placeholder("cross-replica"),
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T1,
    )

    resolutions = await asyncio.gather(
        first.resolve_alert(
            source_id=SOURCE_ID,
            fingerprint=FINGERPRINT,
            starts_at=T1,
            resolved_at=T1 + timedelta(minutes=5),
        ),
        second.resolve_alert(
            source_id=SOURCE_ID,
            fingerprint=FINGERPRINT,
            starts_at=T1,
            resolved_at=T1 + timedelta(minutes=5),
        ),
    )

    assert claim.incident_id is not None
    assert {item.incident_id for item in resolutions} == {claim.incident_id}
    assert sorted(item.outcome for item in resolutions) == ["duplicate", "resolved"]
    stored = await second.get(claim.incident_id)
    assert stored is not None
    assert stored.record.status == IncidentStatus.RESOLVED
    assert sum(
        event.type == "alertmanager.resolved"
        for event in stored.record.timeline
    ) == 1
    await first.close()
    await second.close()


async def test_resolved_tombstone_blocks_delayed_firing_same_occurrence(
    tmp_path,
) -> None:
    first, second = await _stores(tmp_path)
    resolution = await first.resolve_alert(
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T1,
        resolved_at=T1 + timedelta(minutes=5),
    )

    delayed = await second.claim_alert_firing(
        _placeholder("delayed-old-firing"),
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T1,
    )

    assert resolution.outcome == "unknown"
    assert delayed.outcome == "stale"
    assert delayed.incident_id is None
    assert await first.list() == []
    await first.close()
    await second.close()


async def test_new_occurrence_gets_new_incident_and_old_resolved_cannot_close_it(
    tmp_path,
) -> None:
    first, second = await _stores(tmp_path)
    first_claim = await first.claim_alert_firing(
        _placeholder("first-occurrence"),
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T1,
    )
    await second.resolve_alert(
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T1,
        resolved_at=T1 + timedelta(minutes=5),
    )
    second_claim = await first.claim_alert_firing(
        _placeholder("second-occurrence", starts_at=T2),
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T2,
    )

    stale_resolution = await second.resolve_alert(
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T1,
        resolved_at=T1 + timedelta(minutes=5),
    )

    assert first_claim.outcome == second_claim.outcome == "accepted"
    assert first_claim.incident_id != second_claim.incident_id
    assert second_claim.generation == first_claim.generation + 1
    assert stale_resolution.outcome == "stale"
    assert (
        await first.active_alert_incident(
            source_id=SOURCE_ID,
            fingerprint=FINGERPRINT,
        )
        == second_claim.incident_id
    )
    latest = await first.get(second_claim.incident_id or "")
    assert latest is not None
    assert latest.record.status == IncidentStatus.INVESTIGATING
    await first.close()
    await second.close()


async def test_missing_timestamp_cannot_guess_that_resolved_alert_reopened(
    tmp_path,
) -> None:
    first, second = await _stores(tmp_path)
    claim = await first.claim_alert_firing(
        _placeholder("missing-time"),
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T1,
    )
    await first.resolve_alert(
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T1,
        resolved_at=T1 + timedelta(minutes=1),
    )

    replay = await second.claim_alert_firing(
        _placeholder("unknown-occurrence"),
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=None,
    )

    assert replay.outcome == "stale"
    assert replay.incident_id == claim.incident_id
    assert len(await first.list()) == 1
    await first.close()
    await second.close()


async def test_resolution_without_occurrence_time_cannot_close_known_firing(
    tmp_path,
) -> None:
    first, second = await _stores(tmp_path)
    claim = await first.claim_alert_firing(
        _placeholder("known-occurrence"),
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=T1,
    )

    ambiguous = await second.resolve_alert(
        source_id=SOURCE_ID,
        fingerprint=FINGERPRINT,
        starts_at=None,
        resolved_at=T1 + timedelta(minutes=5),
    )

    assert ambiguous.outcome == "stale"
    assert ambiguous.incident_id == claim.incident_id
    assert (
        await first.active_alert_incident(
            source_id=SOURCE_ID,
            fingerprint=FINGERPRINT,
        )
        == claim.incident_id
    )
    stored = await first.get(claim.incident_id or "")
    assert stored is not None
    assert stored.record.status == IncidentStatus.INVESTIGATING
    await first.close()
    await second.close()


async def test_same_fingerprint_from_different_sources_is_independent(tmp_path) -> None:
    first, second = await _stores(tmp_path)
    claims = await asyncio.gather(
        first.claim_alert_firing(
            _placeholder("cluster-a"),
            source_id="cluster-a",
            fingerprint=FINGERPRINT,
            starts_at=T1,
        ),
        second.claim_alert_firing(
            _placeholder("cluster-b"),
            source_id="cluster-b",
            fingerprint=FINGERPRINT,
            starts_at=T1,
        ),
    )

    assert [claim.outcome for claim in claims] == ["accepted", "accepted"]
    assert claims[0].incident_id != claims[1].incident_id
    assert len(await first.list()) == 2
    await first.close()
    await second.close()
