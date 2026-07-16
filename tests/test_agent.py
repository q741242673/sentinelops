from __future__ import annotations

import pytest

from sentinelops.agent import IncidentAgent
from sentinelops.config import Settings
from sentinelops.domain import (
    Alert,
    IncidentStatus,
    RemediationAction,
    RemediationPlan,
    RiskLevel,
    ToolResult,
)
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


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ({"result": [{"value": [1_700_000_000, "0.0"]}]}, 0.0),
        ({"result": [{"value": [1_700_000_000, "0.25"]}]}, 0.25),
        ({"result": []}, None),
        ({"result": [{"value": [1_700_000_000, "NaN"]}]}, None),
    ],
)
def test_prometheus_scalar_parsing(content, expected) -> None:
    result = ToolResult(tool_name="query_prometheus", success=True, content=content)

    assert IncidentAgent._prometheus_scalar(result) == expected


def test_restart_is_rejected_when_it_preserves_a_faulty_rollout() -> None:
    plan = RemediationPlan(
        summary="Restart the deployment",
        actions=[
            RemediationAction(
                tool_name="restart_deployment",
                arguments={"name": "inventory-service"},
                rationale="Recycle the pod",
                expected_outcome="Requests recover",
                risk=RiskLevel.MEDIUM,
            )
        ],
        rollback="Stop the action",
        verification=["Error rate is below 1%"],
    )
    state = {
        "observations": {
            "rollout": {
                "revisions": [
                    {
                        "revision": 5,
                        "replicas": 0,
                        "change_cause": "healthy-baseline",
                    },
                    {
                        "revision": 6,
                        "replicas": 1,
                        "change_cause": "enable-every-third-inventory-failure",
                    },
                ]
            }
        }
    }

    feedback = IncidentAgent._plan_feedback(
        state,  # type: ignore[arg-type]
        plan,
        {
            "restart_deployment": ToolSpec(
                name="restart_deployment",
                description="Restart a deployment",
                risk=RiskLevel.MEDIUM,
            )
        },
    )

    assert feedback is not None
    assert "rollback_deployment" in feedback
    assert "revision 5" in feedback


def test_unknown_rollback_revision_is_rejected_in_favor_of_exact_prior() -> None:
    plan = RemediationPlan(
        summary="Rollback the deployment",
        actions=[
            RemediationAction(
                tool_name="rollback_deployment",
                arguments={"name": "inventory-service", "revision": 1},
                rationale="Restore the last working version",
                expected_outcome="Requests recover",
                risk=RiskLevel.HIGH,
            )
        ],
        rollback="Roll forward",
        verification=["Error rate is below 1%"],
    )
    state = {
        "observations": {
            "rollout": {
                "revisions": [
                    {"revision": 11, "replicas": 0, "change_cause": "healthy-baseline"},
                    {"revision": 12, "replicas": 1, "change_cause": "enable-failure"},
                ]
            }
        }
    }

    feedback = IncidentAgent._plan_feedback(state, plan)  # type: ignore[arg-type]

    assert feedback is not None
    assert "revision 11" in feedback


def test_planning_diagnosis_drops_large_raw_evidence() -> None:
    compact = IncidentAgent._compact_diagnosis(
        {
            "root_cause": "Faulty rollout",
            "confidence": 0.95,
            "evidence_summary": ["Trace failed"],
            "hypotheses": [
                {
                    "statement": "Revision caused failures",
                    "confidence": 0.95,
                    "contradictions": [],
                    "evidence": [
                        {
                            "source": "tempo",
                            "query": "get_trace",
                            "finding": "Trace failed",
                            "raw": {"large": ["payload"] * 100},
                        }
                    ],
                }
            ],
        }
    )

    assert "raw" not in compact["hypotheses"][0]["evidence"][0]
    assert compact["hypotheses"][0]["evidence"][0]["finding"] == "Trace failed"


def test_chinese_output_detection() -> None:
    assert IncidentAgent._contains_chinese("回滚 inventory-service") is True
    assert IncidentAgent._contains_chinese("Rollback inventory-service") is False
