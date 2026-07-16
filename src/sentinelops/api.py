from __future__ import annotations

import asyncio
import hashlib
import json

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from sentinelops import __version__
from sentinelops.agent import IncidentAgent
from sentinelops.config import get_settings
from sentinelops.demo import (
    build_demo_alert,
    enrich_alert_with_failed_trace,
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


class ApprovalDecision(BaseModel):
    approved: bool
    note: str = ""


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
    agent = build_agent()
    incident_agents[incident_id] = agent
    try:
        alert = await enrich_alert_with_failed_trace(get_settings(), alert)
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


@app.post("/api/v1/demo/faults")
async def create_demo_fault() -> dict[str, object]:
    try:
        return await inject_demo_fault(get_settings())
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


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
