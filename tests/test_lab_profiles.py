from __future__ import annotations

import pytest

from sentinelops.agent import IncidentAgent
from sentinelops.domain import (
    Alert,
    Diagnosis,
    Evidence,
    Hypothesis,
    IncidentStatus,
    RiskLevel,
)
from sentinelops.lab_profiles import FaultyRolloutRunbook, LabProfileCoordinator
from sentinelops.llm.rule_based import RuleBasedProvider
from sentinelops.tools.registry import ToolRegistry
from sentinelops.tools.simulator import SimulatedKubernetesBackend


class AlternativeEliminationProvider(RuleBasedProvider):
    async def structured(self, *, system, prompt, schema, metadata=None):
        result = await super().structured(
            system=system,
            prompt=prompt,
            schema=schema,
            metadata=metadata,
        )
        if schema is Diagnosis:
            alternative = Hypothesis(
                statement="Kubernetes 基础设施故障",
                confidence=0.05,
                evidence=[
                    Evidence(
                        evidence_id="collect_context:1:tool:pods",
                        source="kubernetes_pods",
                        query="list_pods",
                        finding="Pod 基础设施健康，排除了基础设施故障",
                        supports_hypothesis=False,
                    )
                ],
                contradictions=["Pod Ready 且无基础设施异常事件"],
            )
            return result.model_copy(
                update={"hypotheses": [result.hypotheses[0], alternative]}
            )
        return result


@pytest.mark.asyncio
async def test_manual_lab_runbook_reaches_human_gate_with_verified_rollout() -> None:
    agent = IncidentAgent(
        provider=AlternativeEliminationProvider(),
        tools=ToolRegistry(SimulatedKubernetesBackend(scenario="bad_rollout")),
        runbook=FaultyRolloutRunbook(),
        profile_id="lab.manual-approval.v1:test",
    )
    alert = Alert(
        name="HighInventoryErrorRate",
        service="order-service",
        severity="critical",
        summary="显式注入的故障发布",
    )

    record = await agent.start(alert)

    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert record.reflection_rounds == 0
    assert record.plan is not None
    assert record.plan.actions[0].tool_name == "rollback_deployment"
    assert record.plan.actions[0].risk == RiskLevel.HIGH


@pytest.mark.asyncio
async def test_rejected_alternative_does_not_invalidate_primary_root_cause() -> None:
    agent = IncidentAgent(
        provider=AlternativeEliminationProvider(),
        tools=ToolRegistry(SimulatedKubernetesBackend(scenario="bad_rollout")),
    )

    record = await agent.start(
        Alert(
            name="HighErrorRate",
            service="order-service",
            severity="critical",
            summary="故障发布",
        )
    )

    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert record.reflection_rounds == 0
    assert record.diagnosis_review is not None
    assert record.diagnosis_review.sufficient is True


def test_arming_a_lab_profile_replaces_stale_profiles() -> None:
    profiles = LabProfileCoordinator()
    profiles.arm("bounded_reflection", "stale-reflection")
    profiles.arm("manual_approval", "fresh-manual")

    assert profiles.consume(
        alert_name="InventoryTransientRuntimeFault",
        service="inventory-service",
        confidence_threshold=0.8,
    ) is None
    profile = profiles.consume(
        alert_name="HighInventoryErrorRate",
        service="inventory-service",
        confidence_threshold=0.8,
    )

    assert profile is not None
    assert profile.id == "lab.manual-approval.v1:fresh-manual"
    assert profile.auto_approve_max_risk == RiskLevel.LOW
