from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from sentinelops import __version__
from sentinelops.agent import IncidentAgent
from sentinelops.config import get_settings
from sentinelops.demo import (
    build_demo_alert,
    enrich_alert_with_failed_trace,
    inject_auto_demo_fault,
    inject_demo_fault,
    reset_demo_environment,
)
from sentinelops.domain import Alert, ExecutionStep, IncidentRecord, IncidentStatus, TimelineEvent
from sentinelops.lab_profiles import LabIncidentProfile, LabMode, LabProfileCoordinator
from sentinelops.runtime import build_agent

app = FastAPI(
    title="SentinelOps API",
    version=__version__,
    description="Model-agnostic Kubernetes incident diagnosis and remediation agent",
)
incident_agents: dict[str, IncidentAgent] = {}
incident_records: dict[str, IncidentRecord] = {}
alert_fingerprints: dict[str, str] = {}
incident_tasks: set[asyncio.Task[None]] = set()
demo_fault_tasks: set[asyncio.Task[None]] = set()
lab_profiles = LabProfileCoordinator()
incident_streams: dict[str, set[asyncio.Queue[str]]] = {}
incident_feed_streams: set[asyncio.Queue[str]] = set()


class ApprovalDecision(BaseModel):
    approval_id: str
    approval_version: int = Field(ge=1)
    approved: bool
    note: str = ""


class DemoFaultJob(BaseModel):
    id: str
    scenario: Literal[
        "bad_rollout",
        "transient_runtime_fault",
        "ambiguous_change_fault",
    ]
    status: Literal["injecting", "active", "failed"]
    phase: Literal[
        "resetting_baseline",
        "injecting_fault",
        "waiting_for_alert",
        "incident_started",
    ] = "resetting_baseline"
    incident_id: str | None = None
    result: dict[str, object] | None = None
    error: str | None = None


demo_fault_jobs: dict[str, DemoFaultJob] = {}


class DemoResetJob(BaseModel):
    id: str
    status: Literal["resetting", "succeeded", "failed"]
    result: dict[str, object] | None = None
    error: str | None = None


demo_reset_jobs: dict[str, DemoResetJob] = {}


class RuntimeInfo(BaseModel):
    environment: str
    tool_backend: str
    model_provider: str
    model_name: str
    namespace: str
    approval_mode: str = "human_gated"
    alert_ingestion: str = "alertmanager_webhook"


class AlertmanagerAlert(BaseModel):
    status: str = "firing"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str | None = None
    endsAt: str | None = None
    fingerprint: str = ""


class AlertmanagerPayload(BaseModel):
    status: str = "firing"
    receiver: str = ""
    alerts: list[AlertmanagerAlert] = Field(default_factory=list)


def _fingerprint(alert: AlertmanagerAlert) -> str:
    if alert.fingerprint:
        return alert.fingerprint
    canonical = json.dumps(alert.labels, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:24]


def _alert_from_alertmanager(item: AlertmanagerAlert, fingerprint: str) -> Alert:
    severity = item.labels.get("severity", "warning")
    if severity not in {"info", "warning", "critical"}:
        severity = "warning"
    return Alert(
        name=item.labels.get("alertname", "UnknownAlert"),
        namespace=item.labels.get("namespace", get_settings().kubernetes_namespace),
        service=item.labels.get("service", "unknown-service"),
        severity=severity,
        summary=item.annotations.get("summary", "Alertmanager reported a firing alert"),
        labels={
            **item.labels,
            "source": "alertmanager",
            "alertmanager_fingerprint": fingerprint,
        },
    )


def _publish_incident(record: IncidentRecord) -> None:
    incident_records[record.id] = record
    payload = record.model_dump_json()
    queues = [*incident_streams.get(record.id, set()), *incident_feed_streams]
    for queue in queues:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        queue.put_nowait(payload)


async def _investigate_alert(
    incident_id: str,
    alert: Alert,
    profile: LabIncidentProfile | None = None,
) -> None:
    try:
        settings = get_settings()
        agent = build_agent(
            settings,
            runbook=profile.runbook if profile else None,
            profile_id=profile.id if profile else "production-default",
            auto_approve_max_risk=profile.auto_approve_max_risk if profile else None,
            verification_probe_url=(
                settings.demo_order_url if profile and profile.enrich_failed_trace else None
            ),
            progress_callback=_publish_incident,
        )
        incident_agents[incident_id] = agent
        if profile and profile.enrich_failed_trace:
            alert = await enrich_alert_with_failed_trace(settings, alert)
            current = incident_records[incident_id].model_copy(deep=True)
            preflight = next(
                (step for step in current.execution_trace if step.id == "enrich_trace:1"),
                None,
            )
            if preflight:
                completed_at = datetime.now(UTC)
                preflight.status = "completed"
                preflight.completed_at = completed_at
                preflight.duration_ms = max(
                    0,
                    (completed_at - (preflight.started_at or completed_at)).total_seconds() * 1000,
                )
                preflight.detail = "已关联告警、失败请求和调用链上下文"
                current.active_step_id = None
                _publish_incident(current)
        _publish_incident(await agent.start(alert, incident_id=incident_id))
    except Exception as exc:
        current = incident_records[incident_id]
        _publish_incident(
            current.model_copy(
                update={
                    "status": IncidentStatus.FAILED,
                    "active_step_id": None,
                    "timeline": [
                        *current.timeline,
                        TimelineEvent(
                            type="automation.failed",
                            message="自动调查失败",
                            data={"error": str(exc)},
                        ),
                    ],
                }
            )
        )


def _schedule_investigation(
    incident_id: str,
    alert: Alert,
    profile: LabIncidentProfile | None = None,
) -> None:
    task = asyncio.create_task(_investigate_alert(incident_id, alert, profile))
    incident_tasks.add(task)
    task.add_done_callback(incident_tasks.discard)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/api/v1/incidents", response_model=IncidentRecord, status_code=201)
async def create_incident(alert: Alert) -> IncidentRecord:
    incident_agent = build_agent(progress_callback=_publish_incident)
    record = await incident_agent.start(alert)
    incident_agents[record.id] = incident_agent
    _publish_incident(record)
    return record


@app.post("/api/v1/demo/incidents", response_model=IncidentRecord, status_code=201)
async def create_demo_incident() -> IncidentRecord:
    _require_demo_api_enabled()
    try:
        alert = await build_demo_alert(get_settings())
        return await create_incident(alert)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


async def _run_demo_fault(job_id: str) -> None:
    settings = get_settings()
    job = demo_fault_jobs[job_id]
    try:
        await reset_demo_environment(settings)
        _release_demo_alert_deduplication()
        lab_profiles.arm(_job_profile_mode(job), job.id)
        demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
            update={"phase": "injecting_fault"}
        )
        result = await asyncio.wait_for(
            (
                inject_auto_demo_fault(settings)
                if job.scenario == "transient_runtime_fault"
                else inject_demo_fault(settings)
            ),
            timeout=settings.demo_alert_timeout_seconds + 10,
        )
    except TimeoutError:
        _disarm_job_profile(job)
        demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
            update={
                "status": "failed",
                "error": (
                    "连接 kind Kubernetes API 超时，"
                    "请确认 Docker Desktop 和 kind 集群正在运行。"
                ),
            }
        )
    except Exception as exc:
        _disarm_job_profile(job)
        demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
            update={"status": "failed", "error": str(exc)}
        )
    else:
        if job.scenario == "ambiguous_change_fault":
            result = {
                **result,
                "fault_type": "ambiguous_change_fault",
                "investigation_mode": "bounded_reflection",
            }
        demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
            update={"status": "active", "phase": "waiting_for_alert", "result": result}
        )


@app.post("/api/v1/demo/faults", response_model=DemoFaultJob, status_code=202)
async def create_demo_fault() -> DemoFaultJob:
    _require_demo_api_enabled()
    return _create_demo_fault_job("bad_rollout")


@app.post("/api/v1/demo/auto-faults", response_model=DemoFaultJob, status_code=202)
async def create_auto_demo_fault() -> DemoFaultJob:
    _require_demo_api_enabled()
    return _create_demo_fault_job("transient_runtime_fault")


@app.post("/api/v1/demo/reflection-faults", response_model=DemoFaultJob, status_code=202)
async def create_reflection_demo_fault() -> DemoFaultJob:
    _require_demo_api_enabled()
    return _create_demo_fault_job("ambiguous_change_fault")


async def _run_demo_reset(job_id: str) -> None:
    try:
        result = await reset_demo_environment(get_settings())
        _release_demo_alert_deduplication()
        demo_reset_jobs[job_id] = demo_reset_jobs[job_id].model_copy(
            update={"status": "succeeded", "result": result}
        )
    except Exception as exc:
        demo_reset_jobs[job_id] = demo_reset_jobs[job_id].model_copy(
            update={"status": "failed", "error": str(exc)}
        )


@app.post("/api/v1/demo/reset", response_model=DemoResetJob, status_code=202)
async def reset_demo() -> DemoResetJob:
    _require_demo_api_enabled()
    lab_profiles.clear()
    active_job = next(
        (job for job in demo_reset_jobs.values() if job.status == "resetting"),
        None,
    )
    if active_job:
        return active_job

    job = DemoResetJob(id=str(uuid4()), status="resetting")
    demo_reset_jobs[job.id] = job
    task = asyncio.create_task(_run_demo_reset(job.id))
    demo_fault_tasks.add(task)
    task.add_done_callback(demo_fault_tasks.discard)
    return job


@app.get("/api/v1/demo/resets/{job_id}", response_model=DemoResetJob)
async def get_demo_reset(job_id: str) -> DemoResetJob:
    _require_demo_api_enabled()
    try:
        return demo_reset_jobs[job_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="演示环境恢复任务不存在") from exc


def _create_demo_fault_job(
    scenario: Literal[
        "bad_rollout",
        "transient_runtime_fault",
        "ambiguous_change_fault",
    ],
) -> DemoFaultJob:
    active_job = next(
        (
            job
            for job in demo_fault_jobs.values()
            if job.status == "injecting" and job.scenario == scenario
        ),
        None,
    )
    if active_job:
        return active_job

    job = DemoFaultJob(id=str(uuid4()), scenario=scenario, status="injecting")
    demo_fault_jobs[job.id] = job
    task = asyncio.create_task(_run_demo_fault(job.id))
    demo_fault_tasks.add(task)
    task.add_done_callback(demo_fault_tasks.discard)
    return job


def _require_demo_api_enabled() -> None:
    settings = get_settings()
    environment = settings.environment.strip().casefold()
    namespace_mismatch = (
        settings.tool_backend == "kubernetes"
        and settings.kubernetes_namespace != settings.demo_namespace
    )
    if not settings.demo_enabled or environment in {"prod", "production"}:
        raise HTTPException(status_code=404, detail="Not Found")
    if namespace_mismatch:
        raise HTTPException(
            status_code=503,
            detail="Demo Kubernetes namespace is not isolated from the configured runtime",
        )


def _disarm_job_profile(job: DemoFaultJob) -> None:
    if job.scenario == "bad_rollout":
        lab_profiles.disarm("manual_approval")
    elif job.scenario == "transient_runtime_fault":
        lab_profiles.disarm("automatic_remediation")
    elif job.scenario == "ambiguous_change_fault":
        lab_profiles.disarm("bounded_reflection")


def _job_profile_mode(job: DemoFaultJob) -> LabMode:
    if job.scenario == "bad_rollout":
        return "manual_approval"
    if job.scenario == "transient_runtime_fault":
        return "automatic_remediation"
    return "bounded_reflection"


def _release_demo_alert_deduplication() -> None:
    demo_alerts = {"HighInventoryErrorRate", "InventoryTransientRuntimeFault"}
    for fingerprint, incident_id in list(alert_fingerprints.items()):
        record = incident_records.get(incident_id)
        if record and record.alert.name in demo_alerts:
            alert_fingerprints.pop(fingerprint, None)


@app.get("/api/v1/demo/faults/{job_id}", response_model=DemoFaultJob)
async def get_demo_fault(job_id: str) -> DemoFaultJob:
    _require_demo_api_enabled()
    try:
        return demo_fault_jobs[job_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="故障注入任务不存在") from exc


@app.post("/api/v1/webhooks/alertmanager", status_code=202)
async def receive_alertmanager_webhook(payload: AlertmanagerPayload) -> dict[str, object]:
    accepted: list[dict[str, object]] = []
    for item in payload.alerts:
        fingerprint = _fingerprint(item)
        if item.status == "resolved":
            incident_id = alert_fingerprints.pop(fingerprint, None)
            accepted.append(
                {"fingerprint": fingerprint, "status": "resolved", "incident_id": incident_id}
            )
            continue
        if item.status != "firing":
            continue
        existing_id = alert_fingerprints.get(fingerprint)
        if existing_id:
            accepted.append(
                {
                    "fingerprint": fingerprint,
                    "status": "deduplicated",
                    "incident_id": existing_id,
                }
            )
            continue
        alert = _alert_from_alertmanager(item, fingerprint)
        profile = lab_profiles.consume(
            alert_name=alert.name,
            service=alert.service,
            confidence_threshold=get_settings().diagnosis_confidence_threshold,
        )
        now = datetime.now(UTC)
        execution_trace = [
            ExecutionStep(
                id="incident_received:1",
                kind="graph",
                title="接收事故告警",
                detail=alert.summary,
                status="completed",
                started_at=now,
                completed_at=now,
                duration_ms=0,
            )
        ]
        active_step_id = None
        if profile and profile.enrich_failed_trace:
            execution_trace.append(
                ExecutionStep(
                    id="enrich_trace:1",
                    kind="tool",
                    title="关联告警与失败调用链",
                    detail="正在从 Tempo 补齐触发告警的失败请求上下文",
                    status="running",
                    started_at=now,
                )
            )
            active_step_id = "enrich_trace:1"
        placeholder = IncidentRecord(
            alert=alert,
            execution_profile_id=profile.id if profile else "production-default",
            status=IncidentStatus.INVESTIGATING,
            timeline=[
                TimelineEvent(
                    type="alertmanager.received",
                    message="Alertmanager 自动推送了一个真实告警",
                    data={"fingerprint": fingerprint},
                )
            ],
            execution_trace=execution_trace,
            active_step_id=active_step_id,
        )
        _publish_incident(placeholder)
        if profile and profile.run_id in demo_fault_jobs:
            demo_fault_jobs[profile.run_id] = demo_fault_jobs[profile.run_id].model_copy(
                update={"phase": "incident_started", "incident_id": placeholder.id}
            )
        alert_fingerprints[fingerprint] = placeholder.id
        _schedule_investigation(placeholder.id, alert, profile)
        accepted.append(
            {
                "fingerprint": fingerprint,
                "status": "accepted",
                "incident_id": placeholder.id,
            }
        )
    return {"accepted": accepted}


@app.get("/api/v1/incidents", response_model=list[IncidentRecord])
async def list_incidents() -> list[IncidentRecord]:
    return sorted(incident_records.values(), key=lambda record: record.created_at, reverse=True)


@app.get("/api/v1/runtime", response_model=RuntimeInfo)
async def get_runtime() -> RuntimeInfo:
    settings = get_settings()
    return RuntimeInfo(
        environment=settings.environment,
        tool_backend=settings.tool_backend,
        model_provider=settings.model_provider,
        model_name=settings.model_name,
        namespace=settings.kubernetes_namespace,
        approval_mode="risk_based",
    )


@app.get("/api/v1/incidents/events")
async def stream_all_incidents() -> StreamingResponse:
    async def events() -> AsyncIterator[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=50)
        incident_feed_streams.add(queue)
        try:
            yield ": connected\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {payload}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            incident_feed_streams.discard(queue)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentRecord)
async def get_incident(incident_id: str) -> IncidentRecord:
    try:
        return incident_records[incident_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Incident not found") from exc


@app.get("/api/v1/incidents/{incident_id}/events")
async def stream_incident(incident_id: str) -> StreamingResponse:
    if incident_id not in incident_records:
        raise HTTPException(status_code=404, detail="Incident not found")

    async def events() -> AsyncIterator[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=20)
        subscribers = incident_streams.setdefault(incident_id, set())
        subscribers.add(queue)
        try:
            yield f"data: {incident_records[incident_id].model_dump_json()}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {payload}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            subscribers.discard(queue)
            if not subscribers:
                incident_streams.pop(incident_id, None)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.post("/api/v1/incidents/{incident_id}/approval", response_model=IncidentRecord)
async def decide_incident(incident_id: str, decision: ApprovalDecision) -> IncidentRecord:
    try:
        record = await incident_agents[incident_id].resume(
            incident_id,
            approval_id=decision.approval_id,
            approval_version=decision.approval_version,
            approved=decision.approved,
            note=decision.note,
        )
        _publish_incident(record)
        return record
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Incident not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
