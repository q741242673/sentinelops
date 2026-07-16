from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


class IncidentState(TypedDict, total=False):
    incident_id: str
    alert: dict[str, Any]
    status: str
    observations: dict[str, Any]
    diagnosis: dict[str, Any]
    diagnosis_review: dict[str, Any]
    follow_up_queries: list[dict[str, Any]]
    reflection_rounds: int
    plan: dict[str, Any]
    approval_request: dict[str, Any] | None
    approved: bool | None
    execution_results: Annotated[list[dict[str, Any]], operator.add]
    timeline: Annotated[list[dict[str, Any]], operator.add]
    postmortem: str | None
