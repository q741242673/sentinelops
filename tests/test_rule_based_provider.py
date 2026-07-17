from __future__ import annotations

import json

import pytest

from sentinelops.agent import IncidentAgent
from sentinelops.domain import Alert, Diagnosis, IncidentStatus, RemediationPlan, ToolResult
from sentinelops.llm.rule_based import RuleBasedProvider
from sentinelops.tools.registry import ToolRegistry


class EmptyEvidenceBackend:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def call(self, name: str, arguments: dict[str, object]) -> ToolResult:
        self.calls.append(name)
        content: dict[str, object]
        if name == "list_pods":
            content = {"items": []}
        elif name == "list_events":
            content = {"items": []}
        elif name == "get_pod_logs":
            content = {"lines": []}
        elif name == "get_rollout_history":
            content = {"revisions": []}
        else:
            content = {}
        return ToolResult(tool_name=name, success=True, content=content)


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


@pytest.mark.parametrize(
    "observations",
    [
        {},
        {"logs": {"lines": []}, "metrics": {}},
        {
            "pods": {"items": [{"ready": True, "restarts": 0}]},
            "logs": {"lines": ["INFO: service healthy"]},
            "metrics": {"error_rate": 0.0, "db_pool_utilization": 0.42},
        },
        {
            "logs": {"lines": ["payment provider returned HTTP 429"]},
            "prometheus": {"result": []},
        },
        {
            "logs": {"lines": ["unrelated worker reported a fatal request error"]},
        },
    ],
)
def test_empty_healthy_or_unrelated_observations_are_unknown(
    observations: dict[str, object],
) -> None:
    assert RuleBasedProvider._infer_scenario(observations) == "unknown"


@pytest.mark.parametrize(
    "observations",
    [
        {"metrics": {"scenario": "db_pool_exhaustion"}},
        {
            "logs": {
                "lines": ["ERROR: timeout acquiring database connection from pool"]
            }
        },
        {"metrics": {"db_pool_utilization": 0.97}},
    ],
)
def test_db_pool_requires_an_explicit_supported_signal(
    observations: dict[str, object],
) -> None:
    assert RuleBasedProvider._infer_scenario(observations) == "db_pool_exhaustion"


@pytest.mark.asyncio
async def test_unknown_diagnosis_is_low_confidence_without_invented_evidence_or_plan() -> None:
    provider = RuleBasedProvider()
    alert = {"service": "order-service", "summary": "request failures"}
    observations = {
        "logs": {"lines": []},
        "prometheus": {"result": []},
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
        },
    }

    diagnosis = await provider.structured(
        system="diagnose",
        prompt=json.dumps({"alert": alert, "observations": observations}),
        schema=Diagnosis,
    )

    assert diagnosis.root_cause == "现有证据不足，无法确认根本原因"
    assert diagnosis.confidence == 0.1
    assert diagnosis.evidence_summary == []
    assert diagnosis.hypotheses[0].evidence == []
    assert "数据库连接池" not in diagnosis.model_dump_json()

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

    assert plan.actions == []
    assert plan.summary == "证据不足，不生成自动修复方案"


@pytest.mark.asyncio
async def test_empty_evidence_is_rechecked_then_escalated_without_a_write() -> None:
    backend = EmptyEvidenceBackend()
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
    )

    record = await agent.start(
        Alert(
            name="HighErrorRate",
            namespace="sentinelops-demo",
            service="order-service",
            summary="query succeeded but returned no diagnostic evidence",
        )
    )

    assert record.status == IncidentStatus.ESCALATED
    assert record.reflection_rounds == 1
    assert record.plan is None
    assert record.execution_results == []
    assert not {
        "restart_deployment",
        "rollback_deployment",
        "scale_deployment",
    }.intersection(backend.calls)


@pytest.mark.asyncio
async def test_db_pool_findings_only_describe_matching_payload_content() -> None:
    provider = RuleBasedProvider()
    observations = {
        "metrics": {
            "scenario": "db_pool_exhaustion",
            "db_pool_utilization": 1.0,
        },
        "logs": {"lines": ["INFO: unrelated healthy request"]},
        "evidence_catalog": {
            "collect_context:1:tool:logs": {
                "evidence_id": "collect_context:1:tool:logs",
                "source": "kubernetes_logs",
                "tool": "get_pod_logs",
                "success": True,
            },
            "collect_context:1:tool:metrics": {
                "evidence_id": "collect_context:1:tool:metrics",
                "source": "workload_metrics",
                "tool": "get_service_metrics",
                "success": True,
            },
        },
    }

    diagnosis = await provider.structured(
        system="diagnose",
        prompt=json.dumps({"alert": {}, "observations": observations}),
        schema=Diagnosis,
    )

    assert [evidence.source for evidence in diagnosis.hypotheses[0].evidence] == [
        "workload_metrics"
    ]
    assert diagnosis.evidence_summary == ["数据库连接池利用率达到 95% 以上"]


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
    assert diagnosis.root_cause == diagnosis.hypotheses[0].statement
    assert diagnosis.confidence == diagnosis.hypotheses[0].confidence
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
