from __future__ import annotations

import pytest

from sentinelops.agent import IncidentAgent
from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentStatus, RiskLevel, ToolResult
from sentinelops.llm.rule_based import RuleBasedProvider
from sentinelops.runtime import build_agent
from sentinelops.tools.base import CompositeBackend, ToolSpec
from sentinelops.tools.registry import KUBERNETES_TOOL_SPECS, ToolRegistry
from sentinelops.tools.simulator import SimulatedKubernetesBackend


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


@pytest.mark.asyncio
async def test_agent_collects_configured_observability_evidence() -> None:
    class RecordingObservabilityBackend:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def call(self, name, arguments) -> ToolResult:
            self.calls.append(name)
            return ToolResult(
                tool_name=name,
                success=True,
                content={"source": name, "result": []},
            )

    kubernetes = SimulatedKubernetesBackend(scenario="bad_rollout")
    observability = RecordingObservabilityBackend()
    observability_specs = [
        ToolSpec(
            name="query_prometheus",
            description="test",
            risk=RiskLevel.READ_ONLY,
            input_schema={"required": ["query"]},
        ),
        ToolSpec(
            name="search_loki",
            description="test",
            risk=RiskLevel.READ_ONLY,
            input_schema={"required": ["query"]},
        ),
    ]
    routes = {spec.name: kubernetes for spec in KUBERNETES_TOOL_SPECS}
    routes.update({spec.name: observability for spec in observability_specs})
    registry = ToolRegistry(
        CompositeBackend(routes),
        [*KUBERNETES_TOOL_SPECS, *observability_specs],
    )
    agent = IncidentAgent(provider=RuleBasedProvider(), tools=registry)
    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert observability.calls == ["query_prometheus", "search_loki"]
