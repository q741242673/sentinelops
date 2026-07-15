from __future__ import annotations

import pytest

from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentStatus
from sentinelops.runtime import build_agent


def make_alert() -> Alert:
    return Alert(
        name="HighErrorRate",
        namespace="sentinelops-demo",
        service="order-service",
        severity="critical",
        summary="Error rate exceeded SLO",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["bad_rollout", "db_pool_exhaustion"])
async def test_incident_requires_approval_and_recovers(scenario: str) -> None:
    settings = Settings(tool_backend="simulator", model_provider="rule_based")
    agent = build_agent(settings, scenario=scenario)

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert record.diagnosis is not None
    assert record.diagnosis.evidence_summary
    assert record.approval is not None

    record = await agent.resume(record.id, approved=True, note="test approval")

    assert record.status == IncidentStatus.RESOLVED
    assert record.execution_results[0].success is True
    assert record.postmortem is not None


@pytest.mark.asyncio
async def test_rejected_action_is_not_executed() -> None:
    settings = Settings(tool_backend="simulator", model_provider="rule_based")
    agent = build_agent(settings, scenario="bad_rollout")

    record = await agent.start(make_alert())
    record = await agent.resume(record.id, approved=False, note="change freeze")

    assert record.status == IncidentStatus.REJECTED
    assert record.execution_results == []
