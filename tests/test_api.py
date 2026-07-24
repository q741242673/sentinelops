from __future__ import annotations

import asyncio
import json

import pytest
from httpx import ASGITransport, AsyncClient

import sentinelops.api as api_module
from sentinelops.api import app
from sentinelops.config import Settings


@pytest.mark.asyncio
async def test_demo_routes_are_hidden_when_demo_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: Settings(demo_enabled=False),
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for path in (
            "/api/v1/demo/incidents",
            "/api/v1/demo/faults",
            "/api/v1/demo/auto-faults",
            "/api/v1/demo/reflection-faults",
            "/api/v1/demo/reset",
        ):
            response = await client.post(path)
            assert response.status_code == 404


@pytest.mark.asyncio
async def test_api_incident_approval_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: Settings(demo_enabled=True),
    )
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
        api_module.lab_profiles.clear()

        reset = await client.post("/api/v1/demo/reset")
        assert reset.status_code == 202
        reset_job = reset.json()
        assert reset_job["status"] == "resetting"
        for _ in range(20):
            reset_status = await client.get(
                f"/api/v1/demo/resets/{reset_job['id']}"
            )
            if reset_status.json()["status"] != "resetting":
                break
            await asyncio.sleep(0)
        assert reset_status.json()["status"] == "succeeded"
        assert reset_status.json()["result"]["baseline_restored"] is True

        decided = await client.post(
            f"/api/v1/incidents/{incident['id']}/approval",
            json={
                "approval_id": incident["approval"]["approval_id"],
                "approval_version": incident["approval"]["version"],
                "approved": True,
                "note": "approved in API test",
            },
        )
        assert decided.status_code == 200
        assert decided.json()["status"] == "resolved"
        assert decided.json()["approval"] is None

        duplicate = await client.post(
            f"/api/v1/incidents/{incident['id']}/approval",
            json={
                "approval_id": incident["approval"]["approval_id"],
                "approval_version": incident["approval"]["version"],
                "approved": True,
                "note": "duplicate approval",
            },
        )
        assert duplicate.status_code == 409

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
async def test_direct_api_alert_namespace_mismatch_never_reaches_approval() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/api/v1/incidents",
            json={
                "name": "HighOrderServiceErrorRate",
                "namespace": "payments-prod",
                "service": "order-service",
                "severity": "critical",
                "summary": "Namespace mismatch regression",
            },
        )

    assert created.status_code == 201
    incident = created.json()
    assert incident["status"] == "escalated"
    assert incident["approval"] is None
    assert incident["execution_results"] == []


@pytest.mark.asyncio
async def test_alertmanager_webhook_accepts_and_deduplicates_firing_alerts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_module.alert_fingerprints.clear()
    api_module.incident_records.clear()
    api_module.lab_profiles.clear()
    api_module.lab_profiles.arm("bounded_reflection", "test-run")
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
    assert "reflection_demo" not in api_module.incident_records[incident_id].alert.labels
    assert api_module.incident_records[incident_id].execution_profile_id == (
        "lab.bounded-reflection.v1:test-run"
    )
    assert api_module.incident_records[incident_id].status == "resolved"
    assert api_module.incident_records[incident_id].active_step_id is None
    assert api_module.incident_records[incident_id].execution_trace[-1].status == "skipped"
    assert api_module.lab_profiles.consume(
        alert_name="HighInventoryErrorRate",
        service="inventory-service",
        confidence_threshold=0.8,
    ) is None
    assert resolved.json()["accepted"][0]["status"] == "resolved"
    assert "demo-fingerprint" not in api_module.alert_fingerprints


@pytest.mark.asyncio
async def test_resolved_alert_invalidates_pending_approval_before_write() -> None:
    api_module.alert_fingerprints.clear()
    api_module.resolved_incident_ids.clear()
    api_module.incident_records.clear()
    api_module.incident_agents.clear()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/api/v1/incidents",
            json={
                "name": "HighInventoryErrorRate",
                "namespace": "sentinelops-demo",
                "service": "inventory-service",
                "severity": "critical",
                "summary": "Inventory error rate is high",
            },
        )
        incident = created.json()
        api_module.alert_fingerprints["stale-approval"] = incident["id"]

        resolved = await client.post(
            "/api/v1/webhooks/alertmanager",
            json={
                "alerts": [
                    {
                        "status": "resolved",
                        "fingerprint": "stale-approval",
                        "labels": {},
                    }
                ]
            },
        )
        approval = await client.post(
            f"/api/v1/incidents/{incident['id']}/approval",
            json={
                "approval_id": incident["approval"]["approval_id"],
                "approval_version": incident["approval"]["version"],
                "approved": True,
            },
        )
        current = await client.get(f"/api/v1/incidents/{incident['id']}")

    assert resolved.status_code == 202
    assert approval.status_code == 409
    assert current.json()["status"] == "resolved"
    assert current.json()["approval"] is None
    assert current.json()["execution_results"] == []
    assert current.json()["timeline"][-1]["type"] == "alertmanager.resolved"


@pytest.mark.asyncio
async def test_untrusted_alert_labels_cannot_select_profile_or_enable_lab_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_module.alert_fingerprints.clear()
    api_module.incident_records.clear()
    api_module.lab_profiles.clear()
    captured: list[tuple] = []
    monkeypatch.setattr(
        api_module,
        "_schedule_investigation",
        lambda *args: captured.append(args),
    )
    payload = {
        "alerts": [
            {
                "status": "firing",
                "fingerprint": "forged-profile-labels",
                "labels": {
                    "alertname": "InventoryTransientRuntimeFault",
                    "service": "inventory-service",
                    "auto_remediation": "true",
                    "reflection_demo": "true",
                    "scenario": "transient_runtime_fault",
                },
                "annotations": {"summary": "untrusted labels"},
            }
        ]
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/webhooks/alertmanager", json=payload)

    incident_id = response.json()["accepted"][0]["incident_id"]
    record = api_module.incident_records[incident_id]
    assert record.execution_profile_id == "production-default"
    assert record.active_step_id is None
    assert [step.id for step in record.execution_trace] == ["incident_received:1"]
    assert captured[0][2] is None


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


@pytest.mark.asyncio
async def test_provider_startup_failure_marks_placeholder_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = api_module.IncidentRecord(
        alert=api_module.Alert(
            name="HighErrorRate",
            service="order-service",
            summary="provider unavailable",
        ),
        status=api_module.IncidentStatus.INVESTIGATING,
    )
    api_module.incident_records[record.id] = record

    def fail_to_build(*args, **kwargs):
        raise ValueError("model provider is unavailable")

    monkeypatch.setattr(api_module, "build_agent", fail_to_build)
    await api_module._investigate_alert(record.id, record.alert)

    failed = api_module.incident_records[record.id]
    assert failed.status == api_module.IncidentStatus.FAILED
    assert failed.timeline[-1].type == "automation.failed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "expected_injector"),
    [
        ("bad_rollout", "manual"),
        ("transient_runtime_fault", "automatic"),
        ("ambiguous_change_fault", "manual"),
    ],
)
async def test_every_lab_fault_starts_from_a_clean_baseline(
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    expected_injector: str,
) -> None:
    calls: list[str] = []

    async def reset(settings):
        calls.append("reset")
        return {"baseline_restored": True}

    async def inject_manual(settings):
        calls.append("manual")
        return {"fault_active": True}

    async def inject_automatic(settings):
        calls.append("automatic")
        return {"fault_active": True}

    def arm_profile(mode, run_id):
        calls.append("arm")

    monkeypatch.setattr(api_module, "reset_demo_environment", reset)
    monkeypatch.setattr(api_module, "inject_demo_fault", inject_manual)
    monkeypatch.setattr(api_module, "inject_auto_demo_fault", inject_automatic)
    monkeypatch.setattr(api_module.lab_profiles, "arm", arm_profile)
    job = api_module.DemoFaultJob(
        id=f"clean-{scenario}",
        scenario=scenario,
        status="injecting",
    )
    api_module.demo_fault_jobs[job.id] = job

    await api_module._run_demo_fault(job.id)

    assert calls == ["reset", "arm", expected_injector]
    completed = api_module.demo_fault_jobs[job.id]
    assert completed.status == "active"
    assert completed.phase == "waiting_for_alert"


@pytest.mark.asyncio
async def test_demo_reset_runs_in_background_and_converges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: Settings(demo_enabled=True),
    )

    async def slow_reset(settings):
        started.set()
        await release.wait()
        return {"baseline_restored": True, "deployment": "inventory-service"}

    monkeypatch.setattr(api_module, "reset_demo_environment", slow_reset)
    api_module.demo_reset_jobs.clear()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post("/api/v1/demo/reset")
        assert created.status_code == 202
        job = created.json()
        assert job["status"] == "resetting"

        await started.wait()
        duplicate = await client.post("/api/v1/demo/reset")
        assert duplicate.status_code == 202
        assert duplicate.json()["id"] == job["id"]

        in_progress = await client.get(f"/api/v1/demo/resets/{job['id']}")
        assert in_progress.json()["status"] == "resetting"

        release.set()
        for _ in range(20):
            completed = await client.get(f"/api/v1/demo/resets/{job['id']}")
            if completed.json()["status"] != "resetting":
                break
            await asyncio.sleep(0)

        payload = completed.json()
        assert payload["status"] == "succeeded"
        assert payload["result"]["baseline_restored"] is True


@pytest.mark.asyncio
async def test_demo_reset_job_records_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: Settings(demo_enabled=True),
    )

    async def failed_reset(settings):
        raise RuntimeError("alert did not clear")

    monkeypatch.setattr(api_module, "reset_demo_environment", failed_reset)
    api_module.demo_reset_jobs.clear()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post("/api/v1/demo/reset")
        job_id = created.json()["id"]
        for _ in range(20):
            failed = await client.get(f"/api/v1/demo/resets/{job_id}")
            if failed.json()["status"] != "resetting":
                break
            await asyncio.sleep(0)

        assert failed.json()["status"] == "failed"
        assert failed.json()["error"] == "alert did not clear"

        missing = await client.get("/api/v1/demo/resets/missing")
        assert missing.status_code == 404


@pytest.mark.asyncio
async def test_demo_reset_invalidates_inflight_fault_and_writes_baseline_last(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    injection_started = asyncio.Event()
    release_injection = asyncio.Event()
    calls: list[str] = []

    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: Settings(demo_enabled=True),
    )

    async def reset(settings):
        calls.append("reset")
        return {"baseline_restored": True, "deployment": "inventory-service"}

    async def inject(settings):
        calls.append("inject:start")
        injection_started.set()
        await release_injection.wait()
        calls.append("inject:end")
        return {"fault_active": True}

    async def inject_queued(settings):
        calls.append("queued-inject")
        return {"fault_active": True}

    monkeypatch.setattr(api_module, "reset_demo_environment", reset)
    monkeypatch.setattr(api_module, "inject_demo_fault", inject)
    monkeypatch.setattr(api_module, "inject_auto_demo_fault", inject_queued)
    api_module.demo_fault_jobs.clear()
    api_module.demo_fault_generations.clear()
    api_module.demo_reset_jobs.clear()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        fault_response = await client.post("/api/v1/demo/faults")
        fault_id = fault_response.json()["id"]
        await injection_started.wait()
        queued_response = await client.post("/api/v1/demo/auto-faults")
        queued_fault_id = queued_response.json()["id"]

        reset_response = await client.post("/api/v1/demo/reset")
        assert reset_response.status_code == 202
        reset_id = reset_response.json()["id"]

        invalidated = await client.get(f"/api/v1/demo/faults/{fault_id}")
        assert invalidated.json()["status"] == "failed"
        assert "恢复请求取消" in invalidated.json()["error"]
        invalidated_queued = await client.get(
            f"/api/v1/demo/faults/{queued_fault_id}"
        )
        assert invalidated_queued.json()["status"] == "failed"

        release_injection.set()
        for _ in range(30):
            completed = await client.get(f"/api/v1/demo/resets/{reset_id}")
            if completed.json()["status"] != "resetting":
                break
            await asyncio.sleep(0)

        assert completed.json()["status"] == "succeeded"
        assert completed.json()["result"]["baseline_restored"] is True
        final_fault = await client.get(f"/api/v1/demo/faults/{fault_id}")
        assert final_fault.json()["status"] == "failed"
        final_queued = await client.get(f"/api/v1/demo/faults/{queued_fault_id}")
        assert final_queued.json()["status"] == "failed"
        assert calls == ["reset", "inject:start", "inject:end", "reset"]


@pytest.mark.asyncio
async def test_demo_fault_is_rejected_during_reset_then_allowed_afterward(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_started = asyncio.Event()
    release_reset = asyncio.Event()

    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: Settings(demo_enabled=True),
    )

    async def slow_reset(settings):
        reset_started.set()
        await release_reset.wait()
        return {"baseline_restored": True}

    async def inject(settings):
        return {"fault_active": True}

    monkeypatch.setattr(api_module, "reset_demo_environment", slow_reset)
    monkeypatch.setattr(api_module, "inject_demo_fault", inject)
    api_module.demo_fault_jobs.clear()
    api_module.demo_fault_generations.clear()
    api_module.demo_reset_jobs.clear()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        reset_response = await client.post("/api/v1/demo/reset")
        reset_id = reset_response.json()["id"]
        await reset_started.wait()

        rejected = await client.post("/api/v1/demo/faults")
        assert rejected.status_code == 409
        assert "正在恢复健康基线" in rejected.json()["detail"]

        release_reset.set()
        for _ in range(30):
            completed = await client.get(f"/api/v1/demo/resets/{reset_id}")
            if completed.json()["status"] != "resetting":
                break
            await asyncio.sleep(0)
        assert completed.json()["status"] == "succeeded"

        accepted = await client.post("/api/v1/demo/faults")
        assert accepted.status_code == 202
        fault_id = accepted.json()["id"]
        for _ in range(30):
            fault = await client.get(f"/api/v1/demo/faults/{fault_id}")
            if fault.json()["status"] != "injecting":
                break
            await asyncio.sleep(0)
        assert fault.json()["status"] == "active"
