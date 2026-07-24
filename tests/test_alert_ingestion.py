from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

import sentinelops.api as api_module
from sentinelops.api import app
from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentRecord, IncidentStatus, TimelineEvent
from sentinelops.storage import SqlIncidentStore


def _database_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'alert-ingestion.db'}"


def _payload(status: str = "firing") -> dict[str, object]:
    return {
        "status": status,
        "receiver": "sentinelops",
        "alerts": [
            {
                "status": status,
                "fingerprint": "cross-replica-fingerprint",
                "startsAt": "2026-07-23T08:00:00Z",
                "endsAt": (
                    "2026-07-23T08:05:00Z"
                    if status == "resolved"
                    else "0001-01-01T00:00:00Z"
                ),
                "labels": {
                    "alertname": "HighOrderServiceErrorRate",
                    "namespace": "payments",
                    "service": "order-service",
                    "severity": "critical",
                },
                "annotations": {"summary": "Order service SLO exceeded"},
            }
        ],
    }


@pytest.mark.asyncio
async def test_webhook_uses_database_for_cross_replica_dedup_and_resolution(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        database_url=_database_url(tmp_path),
        executor_mode="external",
        alertmanager_source_id="cluster-a/alertmanager-main",
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: settings)
    scheduled: list[str] = []
    monkeypatch.setattr(
        api_module,
        "_schedule_investigation",
        lambda incident_id, *_: scheduled.append(incident_id),
    )
    api_module.incident_records.clear()
    api_module.incident_versions.clear()
    api_module.alert_fingerprints.clear()
    first = SqlIncidentStore(settings.database_url or "")
    await api_module.initialize_persistence(first)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://replica-a") as client:
        accepted = await client.post(
            "/api/v1/webhooks/alertmanager",
            json=_payload(),
        )
        duplicate = await client.post(
            "/api/v1/webhooks/alertmanager",
            json=_payload(),
        )

    incident_id = accepted.json()["accepted"][0]["incident_id"]
    assert accepted.json()["accepted"][0]["status"] == "accepted"
    assert duplicate.json()["accepted"][0] == {
        "fingerprint": "cross-replica-fingerprint",
        "status": "deduplicated",
        "incident_id": incident_id,
    }
    assert set(scheduled) == {incident_id}

    await api_module.shutdown_persistence()
    api_module.incident_records.clear()
    api_module.incident_versions.clear()
    api_module.alert_fingerprints.clear()
    second = SqlIncidentStore(settings.database_url or "")
    api_module.incident_store = second

    async with AsyncClient(transport=transport, base_url="http://replica-b") as client:
        resolved = await client.post(
            "/api/v1/webhooks/alertmanager",
            json=_payload("resolved"),
        )

    assert resolved.status_code == 202
    assert resolved.json()["accepted"][0] == {
        "fingerprint": "cross-replica-fingerprint",
        "status": "resolved",
        "incident_id": incident_id,
    }
    durable = await second.get(incident_id)
    assert durable is not None
    assert durable.record.status.value == "resolved"
    assert sum(
        event.type == "alertmanager.resolved"
        for event in durable.record.timeline
    ) == 1

    await api_module.shutdown_persistence()
    api_module.incident_records.clear()
    api_module.incident_versions.clear()
    api_module.alert_fingerprints.clear()
    api_module.resolved_incident_ids.clear()


@pytest.mark.asyncio
async def test_webhook_fails_closed_when_dedup_database_is_unavailable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        database_url=_database_url(tmp_path),
        executor_mode="external",
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: settings)
    store = SqlIncidentStore(settings.database_url or "")
    await store.setup()
    api_module.incident_store = store
    api_module.incident_records.clear()

    async def unavailable(*args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(store, "claim_alert_firing", unavailable)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/webhooks/alertmanager",
            json=_payload(),
        )

    assert response.status_code == 503
    assert api_module.incident_records == {}
    await api_module.shutdown_persistence()


@pytest.mark.asyncio
async def test_startup_reschedules_committed_alert_placeholder(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        database_url=_database_url(tmp_path),
        executor_mode="external",
        alertmanager_source_id="recovery-source",
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: settings)
    fingerprint = "committed-before-schedule"
    store = SqlIncidentStore(settings.database_url or "")
    await store.setup()
    placeholder = IncidentRecord(
        alert=Alert(
            name="CommittedBeforeSchedule",
            namespace="payments",
            service="order-service",
            severity="critical",
            summary="API crashed after commit and before task creation",
            labels={
                "source": "alertmanager",
                "alertmanager_source_id": "recovery-source",
                "alertmanager_fingerprint": fingerprint,
            },
        ),
        status=IncidentStatus.INVESTIGATING,
        timeline=[
            TimelineEvent(
                type="alertmanager.received",
                message="received before process crash",
                data={"fingerprint": fingerprint},
            )
        ],
    )
    claim = await store.claim_alert_firing(
        placeholder,
        source_id="recovery-source",
        fingerprint=fingerprint,
        starts_at=placeholder.alert.starts_at,
    )
    await store.close()
    scheduled: list[str] = []
    monkeypatch.setattr(
        api_module,
        "_schedule_investigation",
        lambda incident_id, *_: scheduled.append(incident_id),
    )

    await api_module.initialize_persistence(
        SqlIncidentStore(settings.database_url or "")
    )

    assert claim.incident_id is not None
    assert scheduled == [claim.incident_id]
    assert api_module.incident_records[claim.incident_id].status == (
        IncidentStatus.INVESTIGATING
    )
    await api_module.shutdown_persistence()
    api_module.incident_records.clear()
    api_module.incident_versions.clear()


@pytest.mark.asyncio
async def test_duplicate_schedule_cannot_restart_advanced_incident(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        database_url=_database_url(tmp_path),
        executor_mode="external",
        alertmanager_source_id="duplicate-schedule",
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: settings)
    fingerprint = "already-investigated"
    store = SqlIncidentStore(settings.database_url or "")
    await store.setup()
    placeholder = IncidentRecord(
        alert=Alert(
            name="AlreadyInvestigated",
            namespace="payments",
            service="order-service",
            severity="critical",
            summary="duplicate scheduler must not restart the graph",
            labels={
                "source": "alertmanager",
                "alertmanager_source_id": "duplicate-schedule",
                "alertmanager_fingerprint": fingerprint,
            },
        ),
        status=IncidentStatus.INVESTIGATING,
    )
    claim = await store.claim_alert_firing(
        placeholder,
        source_id="duplicate-schedule",
        fingerprint=fingerprint,
        starts_at=placeholder.alert.starts_at,
    )
    advanced = placeholder.model_copy(deep=True)
    advanced.status = IncidentStatus.AWAITING_APPROVAL
    await store.save(advanced, expected_version=1, graph_state={"paused": True})
    api_module.incident_store = store
    api_module.incident_records[advanced.id] = advanced
    api_module.incident_versions[advanced.id] = 2
    build_calls = 0

    def forbidden_build(*args, **kwargs):
        nonlocal build_calls
        build_calls += 1
        raise AssertionError("advanced incident was restarted")

    monkeypatch.setattr(api_module, "build_agent", forbidden_build)
    await api_module._investigate_alert(advanced.id, advanced.alert)

    assert claim.incident_id == advanced.id
    assert build_calls == 0
    durable = await store.get(advanced.id)
    assert durable is not None
    assert durable.record.status == IncidentStatus.AWAITING_APPROVAL
    await api_module.shutdown_persistence()
    api_module.incident_records.clear()
    api_module.incident_versions.clear()
