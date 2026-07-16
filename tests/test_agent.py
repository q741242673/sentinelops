from __future__ import annotations

import pytest

from sentinelops.agent import IncidentAgent
from sentinelops.config import Settings
from sentinelops.domain import (
    Alert,
    Diagnosis,
    DiagnosisReview,
    Evidence,
    FollowUpQuery,
    Hypothesis,
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


class ReflectionProvider:
    name = "reflection_test"

    def __init__(self, *, recover_confidence: bool) -> None:
        self.recover_confidence = recover_confidence
        self.diagnosis_calls = 0
        self.review_calls = 0
        self.plan_calls = 0
        self.fallback = RuleBasedProvider()

    async def structured(self, *, system, prompt, schema, metadata=None):
        if schema is Diagnosis:
            self.diagnosis_calls += 1
            confidence = 0.95 if self.recover_confidence and self.diagnosis_calls > 1 else 0.55
            return Diagnosis(
                root_cause="最新发布可能导致服务启动失败",
                confidence=confidence,
                hypotheses=[
                    Hypothesis(
                        statement="最新发布引入错误配置",
                        confidence=confidence,
                        evidence=[
                            Evidence(
                                source="kubernetes.rollout",
                                query="get_rollout_history",
                                finding="故障与 revision 2 同时出现",
                            )
                        ],
                    )
                ],
                evidence_summary=["故障与 revision 2 同时出现"],
            )
        if schema is DiagnosisReview:
            self.review_calls += 1
            return DiagnosisReview(
                sufficient=False,
                confidence=0.55,
                missing_evidence=["缺少目标 Pod 的最新日志"],
                follow_up_queries=[
                    FollowUpQuery(
                        source="kubernetes_logs",
                        reason="补充日志验证配置错误",
                    )
                ],
            )
        if schema is RemediationPlan:
            self.plan_calls += 1
            return await self.fallback.structured(
                system=system,
                prompt=prompt,
                schema=schema,
                metadata=metadata,
            )
        raise TypeError(schema)


class RecordingSimulator(SimulatedKubernetesBackend):
    def __init__(self) -> None:
        super().__init__(scenario="bad_rollout")
        self.calls: list[str] = []

    async def call(self, name, arguments) -> ToolResult:
        self.calls.append(name)
        return await super().call(name, arguments)


class ContradictoryTransientProvider(RuleBasedProvider):
    def __init__(self) -> None:
        super().__init__()
        self.review_calls = 0

    async def structured(self, *, system, prompt, schema, metadata=None):
        result = await super().structured(
            system=system,
            prompt=prompt,
            schema=schema,
            metadata=metadata,
        )
        if schema is Diagnosis:
            primary = result.hypotheses[0].model_copy(
                update={
                    "contradictions": [
                        "当前与上一 revision 使用相同代码提交，但故障在运行时才出现"
                    ]
                }
            )
            return result.model_copy(
                update={"hypotheses": [primary, *result.hypotheses[1:]]}
            )
        if schema is DiagnosisReview:
            self.review_calls += 1
        return result


def make_alert() -> Alert:
    return Alert(
        name="HighErrorRate",
        namespace="sentinelops-demo",
        service="order-service",
        severity="critical",
        summary="Error rate exceeded SLO",
    )


@pytest.mark.asyncio
async def test_low_confidence_diagnosis_collects_one_bounded_follow_up_round() -> None:
    provider = ReflectionProvider(recover_confidence=True)
    backend = RecordingSimulator()
    agent = IncidentAgent(provider=provider, tools=ToolRegistry(backend))

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert record.reflection_rounds == 1
    assert provider.diagnosis_calls == 2
    assert provider.review_calls == 1
    assert provider.plan_calls == 1
    assert backend.calls.count("get_pod_logs") == 2
    assert any(event.type == "investigation.reflection_requested" for event in record.timeline)
    assert any(event.type == "evidence.supplemented" for event in record.timeline)


@pytest.mark.asyncio
async def test_persistently_weak_diagnosis_escalates_without_cluster_write() -> None:
    provider = ReflectionProvider(recover_confidence=False)
    backend = RecordingSimulator()
    agent = IncidentAgent(provider=provider, tools=ToolRegistry(backend))

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.ESCALATED
    assert record.reflection_rounds == 1
    assert record.plan is None
    assert record.approval is None
    assert record.execution_results == []
    assert provider.plan_calls == 0
    assert not {"restart_deployment", "rollback_deployment"}.intersection(backend.calls)
    assert any(event.type == "investigation.escalated" for event in record.timeline)


@pytest.mark.asyncio
async def test_high_confidence_diagnosis_skips_reflection_call() -> None:
    provider = RuleBasedProvider()
    agent = IncidentAgent(provider=provider, tools=ToolRegistry(SimulatedKubernetesBackend()))

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert record.reflection_rounds == 0
    assert record.diagnosis_review is not None
    assert record.diagnosis_review.sufficient is True


@pytest.mark.asyncio
async def test_progress_callback_exposes_live_graph_and_tool_steps() -> None:
    snapshots = []
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(SimulatedKubernetesBackend()),
        progress_callback=lambda record: snapshots.append(record),
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert any(
        snapshot.active_step_id == "collect_context:1:tool:pods"
        for snapshot in snapshots
    )
    assert any(
        snapshot.active_step_id == "diagnose:1"
        and next(
            step for step in snapshot.execution_trace if step.id == "diagnose:1"
        ).title
        == "Agent 正在分析"
        for snapshot in snapshots
    )
    assert snapshots[-1].active_step_id == "human_gate:1"
    visible_trace = " ".join(
        f"{step.title} {step.detail}"
        for snapshot in snapshots
        for step in snapshot.execution_trace
    ).lower()
    assert "deepseek" not in visible_trace
    assert "openai" not in visible_trace


@pytest.mark.asyncio
async def test_complex_demo_forces_one_visible_reflection_round() -> None:
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(SimulatedKubernetesBackend()),
    )
    alert = make_alert().model_copy(
        update={"labels": {"reflection_demo": "true"}}
    )

    record = await agent.start(alert)

    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert record.reflection_rounds == 1
    assert any(event.type == "investigation.reflection_requested" for event in record.timeline)
    assert any(event.type == "evidence.supplemented" for event in record.timeline)


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
async def test_transient_runtime_fault_is_auto_remediated_without_human_gate() -> None:
    settings = Settings(
        tool_backend="simulator",
        model_provider="rule_based",
        auto_approve_max_risk="medium",
    )
    agent = build_agent(settings, scenario="transient_runtime_fault")
    alert = Alert(
        name="InventoryTransientRuntimeFault",
        namespace="sentinelops-demo",
        service="inventory-service",
        severity="warning",
        summary="库存服务存在进程内瞬态故障",
        labels={
            "scenario": "transient_runtime_fault",
            "auto_remediation": "true",
        },
    )

    record = await agent.start(alert)

    assert record.status == IncidentStatus.RESOLVED
    assert record.approval is None
    assert record.plan is not None
    assert record.plan.actions[0].tool_name == "restart_deployment"
    assert record.execution_results[0].success is True
    assert any(event.type == "approval.auto_approved" for event in record.timeline)
    assert IncidentAgent._diagnosis_needs_localization(record.diagnosis) is False
    assert IncidentAgent._plan_needs_localization(record.plan) is False


@pytest.mark.asyncio
async def test_verified_transient_fault_ignores_non_causal_revision_contradiction() -> None:
    provider = ContradictoryTransientProvider()
    backend = SimulatedKubernetesBackend(scenario="transient_runtime_fault")
    agent = IncidentAgent(
        provider=provider,
        tools=ToolRegistry(backend),
        auto_approve_max_risk=RiskLevel.MEDIUM,
    )
    alert = Alert(
        name="InventoryTransientRuntimeFault",
        namespace="sentinelops-demo",
        service="inventory-service",
        severity="warning",
        summary="库存服务存在进程内瞬态故障",
        labels={
            "scenario": "transient_runtime_fault",
            "auto_remediation": "true",
        },
    )

    record = await agent.start(alert)

    assert record.status == IncidentStatus.RESOLVED
    assert record.reflection_rounds == 0
    assert record.plan is not None
    assert record.plan.actions[0].tool_name == "restart_deployment"
    assert provider.review_calls == 0


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
