from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


class IncidentState(TypedDict, total=False):
    incident_id: str
    alert: dict[str, Any]
    status: str
    observations: dict[str, Any]
    evidence_snapshots: dict[str, dict[str, Any]]
    diagnosis: dict[str, Any]
    diagnosis_generation_failed: bool
    diagnosis_review: dict[str, Any]
    follow_up_queries: list[dict[str, Any]]
    reflection_rounds: int
    plan: dict[str, Any]
    preflight_snapshot: dict[str, Any]
    preflight_passed: bool
    execution_precondition: dict[str, Any]
    approval_request: dict[str, Any] | None
    approved: bool | None
    execution_results: Annotated[list[dict[str, Any]], operator.add]
    timeline: Annotated[list[dict[str, Any]], operator.add]
    postmortem: str | None
