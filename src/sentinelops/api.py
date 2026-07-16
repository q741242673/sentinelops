from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from sentinelops import __version__
from sentinelops.agent import IncidentAgent
from sentinelops.config import get_settings
from sentinelops.demo import build_demo_alert, inject_demo_fault
from sentinelops.domain import Alert, IncidentRecord
from sentinelops.runtime import build_agent

app = FastAPI(
    title="SentinelOps API",
    version=__version__,
    description="Model-agnostic Kubernetes incident diagnosis and remediation agent",
)
incident_agents: dict[str, IncidentAgent] = {}
incident_records: dict[str, IncidentRecord] = {}


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
