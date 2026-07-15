from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from sentinelops import __version__
from sentinelops.domain import Alert, IncidentRecord
from sentinelops.runtime import build_agent

app = FastAPI(
    title="SentinelOps API",
    version=__version__,
    description="Model-agnostic Kubernetes incident diagnosis and remediation agent",
)
agent = build_agent()


class ApprovalDecision(BaseModel):
    approved: bool
    note: str = ""


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/api/v1/incidents", response_model=IncidentRecord, status_code=201)
async def create_incident(alert: Alert) -> IncidentRecord:
    return await agent.start(alert)


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentRecord)
async def get_incident(incident_id: str) -> IncidentRecord:
    try:
        return agent.get(incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Incident not found") from exc


@app.post("/api/v1/incidents/{incident_id}/approval", response_model=IncidentRecord)
async def decide_incident(incident_id: str, decision: ApprovalDecision) -> IncidentRecord:
    try:
        return await agent.resume(
            incident_id,
            approved=decision.approved,
            note=decision.note,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Incident not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
