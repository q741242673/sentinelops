from __future__ import annotations

import asyncio
import json

import pytest
from httpx import ASGITransport, AsyncClient

import sentinelops.api as api_module
from sentinelops.api import app


@pytest.mark.asyncio
async def test_api_incident_approval_flow() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/api/v1/incidents",
            json={
                "name": "HighOrderServiceErrorRate",
                "namespace": "sentinelops-demo",
                "service": "order-service",
                "severity": "critical",
                "summary": "Order service exceeded its error budget",
            },
        )
        assert created.status_code == 201
        incident = created.json()
        assert incident["status"] == "awaiting_approval"

        listed = await client.get("/api/v1/incidents")
        assert listed.status_code == 200
        assert incident["id"] in {item["id"] for item in listed.json()}

        runtime = await client.get("/api/v1/runtime")
        assert runtime.status_code == 200
        assert runtime.json()["model_provider"] == "rule_based"
        assert runtime.json()["approval_mode"] == "risk_based"
        assert runtime.json()["alert_ingestion"] == "alertmanager_webhook"

        demo = await client.post("/api/v1/demo/incidents")
        assert demo.status_code == 201
        assert demo.json()["status"] == "awaiting_approval"

        fault = await client.post("/api/v1/demo/faults")
        assert fault.status_code == 202
        fault_job = fault.json()
        assert fault_job["status"] == "injecting"
        for _ in range(20):
            fault_status = await client.get(f"/api/v1/demo/faults/{fault_job['id']}")
            if fault_status.json()["status"] != "injecting":
                break
            await asyncio.sleep(0)
        assert fault_status.json()["status"] == "active"
        assert fault_status.json()["result"]["fault_active"] is True

        auto_fault = await client.post("/api/v1/demo/auto-faults")
        assert auto_fault.status_code == 202
        assert auto_fault.json()["scenario"] == "transient_runtime_fault"

        reflection_fault = await client.post("/api/v1/demo/reflection-faults")
        assert reflection_fault.status_code == 202
        assert reflection_fault.json()["scenario"] == "ambiguous_change_fault"
        api_module.reflection_demo_armed = False

        reset = await client.post("/api/v1/demo/reset")
        assert reset.status_code == 200
        assert reset.json()["baseline_restored"] is True

        decided = await client.post(
            f"/api/v1/incidents/{incident['id']}/approval",
            json={"approved": True, "note": "approved in API test"},
        )
        assert decided.status_code == 200
        assert decided.json()["status"] == "resolved"

        fetched = await client.get(f"/api/v1/incidents/{incident['id']}")
        assert fetched.status_code == 200
        assert fetched.json()["postmortem"].startswith("# 事故报告")

        second = await client.post(
            "/api/v1/incidents",
            json={
                "name": "HighOrderServiceErrorRate",
                "namespace": "sentinelops-demo",
                "service": "order-service",
                "severity": "critical",
                "summary": "A fresh isolated simulation",
            },
        )
        assert second.status_code == 201
        assert second.json()["status"] == "awaiting_approval"
        assert second.json()["id"] != incident["id"]


@pytest.mark.asyncio
async def test_alertmanager_webhook_accepts_and_deduplicates_firing_alerts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_module.alert_fingerprints.clear()
    api_module.incident_records.clear()
    api_module.reflection_demo_armed = True
    monkeypatch.setattr(api_module, "_schedule_investigation", lambda *_: None)
    payload = {
        "status": "firing",
        "receiver": "sentinelops",
        "alerts": [
            {
                "status": "firing",
                "fingerprint": "demo-fingerprint",
                "labels": {
                    "alertname": "HighInventoryErrorRate",
                    "namespace": "sentinelops-demo",
                    "service": "inventory-service",
                    "severity": "critical",
                },
                "annotations": {"summary": "Inventory SLO exceeded"},
            }
        ],
    }
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        accepted = await client.post("/api/v1/webhooks/alertmanager", json=payload)
        duplicate = await client.post("/api/v1/webhooks/alertmanager", json=payload)

        resolved_payload = payload | {
            "status": "resolved",
            "alerts": [payload["alerts"][0] | {"status": "resolved"}],
        }
        resolved = await client.post(
            "/api/v1/webhooks/alertmanager", json=resolved_payload
        )

    assert accepted.status_code == 202
    incident_id = accepted.json()["accepted"][0]["incident_id"]
    assert duplicate.json()["accepted"][0] == {
        "fingerprint": "demo-fingerprint",
        "status": "deduplicated",
        "incident_id": incident_id,
    }
    assert api_module.incident_records[incident_id].alert.labels["source"] == "alertmanager"
    assert api_module.incident_records[incident_id].alert.labels["reflection_demo"] == "true"
    assert api_module.incident_records[incident_id].status == "investigating"
    assert api_module.incident_records[incident_id].active_step_id == "enrich_trace:1"
    assert api_module.incident_records[incident_id].execution_trace[-1].status == "running"
    assert api_module.reflection_demo_armed is False
    assert resolved.json()["accepted"][0]["status"] == "resolved"
    assert "demo-fingerprint" not in api_module.alert_fingerprints


@pytest.mark.asyncio
async def test_publish_incident_notifies_live_stream_queue() -> None:
    record = api_module.IncidentRecord(
        alert=api_module.Alert(
            name="HighErrorRate",
            service="order-service",
            summary="test stream",
        )
    )
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=2)
    feed_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=2)
    api_module.incident_streams[record.id] = {queue}
    api_module.incident_feed_streams.add(feed_queue)

    api_module._publish_incident(record)

    payload = json.loads(await queue.get())
    feed_payload = json.loads(await feed_queue.get())
    assert payload["id"] == record.id
    assert feed_payload["id"] == record.id
    assert payload["execution_trace"] == []
    api_module.incident_streams.clear()
    api_module.incident_feed_streams.clear()
