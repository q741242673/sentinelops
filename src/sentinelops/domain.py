from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class IncidentStatus(StrEnum):
    RECEIVED = "received"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    REMEDIATING = "remediating"
    RESOLVED = "resolved"
    FAILED = "failed"
    REJECTED = "rejected"
    ESCALATED = "escalated"


class RiskLevel(StrEnum):
    READ_ONLY = "read_only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.READ_ONLY: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


class Alert(BaseModel):
    name: str
    namespace: str = "default"
    service: str
    severity: Literal["info", "warning", "critical"] = "warning"
    summary: str
    labels: dict[str, str] = Field(default_factory=dict)
    starts_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Evidence(BaseModel):
    source: str
    query: str
    finding: str
    supports_hypothesis: bool = True
    raw: dict[str, Any] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    statement: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[Evidence] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)


class Diagnosis(BaseModel):
    root_cause: str
    confidence: float = Field(ge=0, le=1)
    hypotheses: list[Hypothesis]
    evidence_summary: list[str]


class FollowUpQuery(BaseModel):
    source: Literal[
        "kubernetes_pods",
        "kubernetes_events",
        "kubernetes_logs",
        "kubernetes_rollout",
        "prometheus_errors",
        "prometheus_latency",
        "loki_errors",
        "tempo_trace",
        "git_changes",
    ]
    reason: str


class DiagnosisReview(BaseModel):
    sufficient: bool
    confidence: float = Field(ge=0, le=1)
    contradictions: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    follow_up_queries: list[FollowUpQuery] = Field(default_factory=list, max_length=4)


class RemediationAction(BaseModel):
    tool_name: str
    arguments: dict[str, Any]
    rationale: str
    expected_outcome: str
    risk: RiskLevel


class RemediationPlan(BaseModel):
    summary: str
    actions: list[RemediationAction]
    rollback: str
    verification: list[str]


class ApprovalRequest(BaseModel):
    incident_id: str
    action: RemediationAction
    reason: str


class ToolResult(BaseModel):
    tool_name: str
    success: bool
    content: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0


class TimelineEvent(BaseModel):
    type: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IncidentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    alert: Alert
    status: IncidentStatus = IncidentStatus.RECEIVED
    diagnosis: Diagnosis | None = None
    diagnosis_review: DiagnosisReview | None = None
    reflection_rounds: int = 0
    change_evidence: dict[str, Any] | None = None
    plan: RemediationPlan | None = None
    approval: ApprovalRequest | None = None
    execution_results: list[ToolResult] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    postmortem: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
