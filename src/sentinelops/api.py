from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from sentinelops import __version__
from sentinelops.agent import IncidentAgent
from sentinelops.config import get_settings
from sentinelops.demo import (
    build_demo_alert,
    enrich_alert_with_failed_trace,
    inject_auto_demo_fault,
    inject_demo_fault,
)
from sentinelops.domain import Alert, IncidentRecord, IncidentStatus, TimelineEvent
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


class ApprovalDecision(BaseModel):
    approved: bool
    note: str = ""


class DemoFaultJob(BaseModel):
    id: str
    scenario: Literal["bad_rollout", "transient_runtime_fault"]
    status: Literal["injecting", "active", "failed"]
    result: dict[str, object] | None = None
    error: str | None = None


demo_fault_jobs: dict[str, DemoFaultJob] = {}


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


async def _investigate_alert(incident_id: str, alert: Alert) -> None:
    settings = get_settings()
    if alert.labels.get("auto_remediation") == "true":
        settings = settings.model_copy(update={"auto_approve_max_risk": "medium"})
    agent = build_agent(settings)
    incident_agents[incident_id] = agent
    try:
        alert = await enrich_alert_with_failed_trace(settings, alert)
        incident_records[incident_id] = await agent.start(alert, incident_id=incident_id)
    except Exception as exc:
        current = incident_records[incident_id]
        incident_records[incident_id] = current.model_copy(
            update={
                "status": IncidentStatus.FAILED,
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


def _schedule_investigation(incident_id: str, alert: Alert) -> None:
    task = asyncio.create_task(_investigate_alert(incident_id, alert))
    incident_tasks.add(task)
    task.add_done_callback(incident_tasks.discard)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/api/v1/incidents", response_model=IncidentRecord, status_code=201)
async def create_incident(alert: Alert) -> IncidentRecord:
    incident_agent = build_agent()
    record = await incident_agent.start(alert)
    incident_agents[record.id] = incident_agent
    incident_records[record.id] = record
    return record


@app.post("/api/v1/demo/incidents", response_model=IncidentRecord, status_code=201)
async def create_demo_incident() -> IncidentRecord:
    try:
        alert = await build_demo_alert(get_settings())
        return await create_incident(alert)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


async def _run_demo_fault(job_id: str) -> None:
    settings = get_settings()
    job = demo_fault_jobs[job_id]
    try:
        result = await asyncio.wait_for(
            (
                inject_auto_demo_fault(settings)
                if job.scenario == "transient_runtime_fault"
                else inject_demo_fault(settings)
            ),
            timeout=settings.demo_alert_timeout_seconds + 10,
        )
    except TimeoutError:
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
        demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
            update={"status": "failed", "error": str(exc)}
        )
    else:
        demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
            update={"status": "active", "result": result}
        )


@app.post("/api/v1/demo/faults", response_model=DemoFaultJob, status_code=202)
async def create_demo_fault() -> DemoFaultJob:
    return _create_demo_fault_job("bad_rollout")


@app.post("/api/v1/demo/auto-faults", response_model=DemoFaultJob, status_code=202)
async def create_auto_demo_fault() -> DemoFaultJob:
    return _create_demo_fault_job("transient_runtime_fault")


def _create_demo_fault_job(
    scenario: Literal["bad_rollout", "transient_runtime_fault"],
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


@app.get("/api/v1/demo/faults/{job_id}", response_model=DemoFaultJob)
async def get_demo_fault(job_id: str) -> DemoFaultJob:
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
        placeholder = IncidentRecord(
            alert=alert,
            status=IncidentStatus.RECEIVED,
            timeline=[
                TimelineEvent(
                    type="alertmanager.received",
                    message="Alertmanager 自动推送了一个真实告警",
                    data={"fingerprint": fingerprint},
                )
            ],
        )
        incident_records[placeholder.id] = placeholder
        alert_fingerprints[fingerprint] = placeholder.id
        _schedule_investigation(placeholder.id, alert)
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


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentRecord)
async def get_incident(incident_id: str) -> IncidentRecord:
    try:
        return incident_records[incident_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Incident not found") from exc


@app.post("/api/v1/incidents/{incident_id}/approval", response_model=IncidentRecord)
async def decide_incident(incident_id: str, decision: ApprovalDecision) -> IncidentRecord:
    try:
        record = await incident_agents[incident_id].resume(
            incident_id,
            approved=decision.approved,
            note=decision.note,
        )
        incident_records[incident_id] = record
        return record
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Incident not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
