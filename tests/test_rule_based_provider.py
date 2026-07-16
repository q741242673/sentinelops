from __future__ import annotations

import json

import pytest

from sentinelops.domain import Diagnosis, RemediationPlan
from sentinelops.llm.rule_based import RuleBasedProvider


def test_infers_runtime_state_fault_before_generic_inventory_failure() -> None:
    observations = {
        "logs": {
            "lines": [
                "inventory_reservation_failed reason=transient_runtime_fault",
                "transient_runtime_fault_enabled restart_required=true",
            ]
        }
    }

    assert RuleBasedProvider._infer_scenario(observations) == "transient_runtime_fault"


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
        "rollout": {"revisions": [{"revision": 11}, {"revision": 12}]},
        "scenario": "live_cluster",
        "evidence_catalog": {
            "collect_context:1:tool:logs": {
                "evidence_id": "collect_context:1:tool:logs",
                "source": "kubernetes_logs",
                "tool": "get_pod_logs",
                "success": True,
            },
            "collect_context:1:tool:prometheus": {
                "evidence_id": "collect_context:1:tool:prometheus",
                "source": "prometheus",
                "tool": "query_prometheus",
                "success": True,
            },
            "collect_context:1:tool:loki": {
                "evidence_id": "collect_context:1:tool:loki",
                "source": "loki",
                "tool": "search_loki",
                "success": True,
            },
            "collect_context:1:tool:trace": {
                "evidence_id": "collect_context:1:tool:trace",
                "source": "tempo",
                "tool": "get_trace",
                "success": True,
            },
            "collect_context:1:tool:rollout": {
                "evidence_id": "collect_context:1:tool:rollout",
                "source": "kubernetes_rollout",
                "tool": "get_rollout_history",
                "success": True,
            },
        },
    }
    diagnosis = await provider.structured(
        system="diagnose",
        prompt=json.dumps({"alert": alert, "observations": observations}),
        schema=Diagnosis,
    )

    assert "revision 12" in diagnosis.root_cause.lower()
    assert {item.source for item in diagnosis.hypotheses[0].evidence} == {
        "kubernetes_logs",
        "prometheus",
        "loki",
        "tempo",
        "kubernetes_rollout",
    }
    assert all(item.evidence_id for item in diagnosis.hypotheses[0].evidence)

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
    assert plan.actions[0].arguments == {"name": "inventory-service", "revision": 11}
    assert "修复" in plan.summary
