from __future__ import annotations

import json

import pytest

from sentinelops.domain import Diagnosis, RemediationPlan
from sentinelops.llm.rule_based import RuleBasedProvider


@pytest.mark.asyncio
async def test_inventory_fault_uses_cross_signal_evidence_and_rolls_back() -> None:
    provider = RuleBasedProvider()
    alert = {
        "service": "inventory-service",
        "summary": "Inventory HTTP 503 rate exceeded the checkout SLO",
    }
    observations = {
        "logs": {"lines": ["inventory_reservation_failed reason=synthetic_timeout"]},
        "prometheus": {"result": [{"metric": {"status": "503"}}]},
        "loki": {"result": [{"values": [["1", "inventory_reservation_failed"]]}]},
        "trace": {"trace": {"resourceSpans": [{"service.name": "inventory-service"}]}},
        "rollout": {"revisions": [{"revision": 1}, {"revision": 2}]},
        "scenario": "live_cluster",
    }
    diagnosis = await provider.structured(
        system="diagnose",
        prompt=json.dumps({"alert": alert, "observations": observations}),
        schema=Diagnosis,
    )

    assert "revision 2" in diagnosis.root_cause.lower()
    assert {item.source for item in diagnosis.hypotheses[0].evidence} == {
        "prometheus",
        "loki",
        "tempo",
        "kubernetes.rollout",
    }

    plan = await provider.structured(
        system="plan",
        prompt=json.dumps(
            {
                "alert": alert,
                "observations": observations,
                "diagnosis": diagnosis.model_dump(mode="json"),
            }
        ),
        schema=RemediationPlan,
    )

    assert plan.actions[0].tool_name == "rollback_deployment"
    assert plan.actions[0].arguments == {"name": "inventory-service", "revision": 1}
    assert "修复" in plan.summary
