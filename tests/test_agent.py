from __future__ import annotations

import json

import pytest

from sentinelops.agent import IncidentAgent
from sentinelops.agent.runbook import IncidentRunbook
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
from sentinelops.lab_profiles import (
    BoundedReflectionRunbook,
    VerifiedRuntimeStateRunbook,
    build_simulated_lab_agent,
)
from sentinelops.llm.rule_based import RuleBasedProvider
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
                root_cause="最新发布引入错误配置",
                confidence=confidence,
                hypotheses=[
                    Hypothesis(
                        statement="最新发布引入错误配置",
                        confidence=confidence,
                        evidence=[
                            Evidence(
                                evidence_id="collect_context:1:tool:rollout",
                                source="kubernetes_rollout",
                                query="get_rollout_history",
                                finding="故障与 revision 2 同时出现",
                            ),
                            Evidence(
                                evidence_id="collect_context:1:tool:events",
                                source="kubernetes_events",
                                query="list_events",
                                finding="发布后出现容器启动失败事件",
                            ),
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


class PreflightMutationSimulator(RecordingSimulator):
    def __init__(self, mutation: str) -> None:
        super().__init__()
        self.mutation = mutation
        self.rollout_reads = 0

    async def call(self, name, arguments) -> ToolResult:
        if name == "get_rollout_history":
            self.calls.append(name)
            self.rollout_reads += 1
            if self.rollout_reads > 2 and self.mutation == "read_failure":
                return ToolResult(
                    tool_name=name,
                    success=False,
                    error="Kubernetes API unavailable during preflight",
                )
            result = await SimulatedKubernetesBackend.call(self, name, arguments)
            if self.rollout_reads > 2 and self.mutation == "new_revision":
                result.content["generation"] = 3
                result.content["resource_version"] = "sim-rv-3"
                result.content["current_revision"] = 3
                result.content["revisions"].append(
                    {
                        "uid": "sim-rs-3",
                        "revision": 3,
                        "replicas": 1,
                        "ready_replicas": 1,
                        "status": "current",
                        "health_status": "unknown",
                        "health_proof": {"valid": False, "status": "unknown"},
                    }
                )
            if self.rollout_reads > 2 and self.mutation == "proof_revoked":
                target = result.content["revisions"][0]
                target["health_status"] = "unknown"
                target["health_proof"] = {
                    "valid": False,
                    "status": "unknown",
                    "subject": target["health_proof"]["subject"],
                }
            if self.rollout_reads > 2 and self.mutation == "resource_version_only":
                result.content["resource_version"] = "sim-rv-status-update"
            if self.rollout_reads > 2 and self.mutation == "self_recovered":
                current = result.content["revisions"][1]
                current["ready_replicas"] = current["replicas"]
                current["status"] = "stable"
            return result
        if name == "rollback_deployment" and self.mutation == "backend_guard_failure":
            self.calls.append(name)
            return ToolResult(
                tool_name=name,
                success=False,
                error="Execution precondition failed: resource_version",
            )
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


class InvalidEvidenceProvider:
    name = "invalid_evidence_test"

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.diagnosis_calls = 0
        self.review_calls = 0
        self.plan_calls = 0

    async def structured(self, *, system, prompt, schema, metadata=None):
        if schema is Diagnosis:
            self.diagnosis_calls += 1
            if self.mode == "empty":
                evidence = []
            elif self.mode == "failed":
                evidence = [
                    Evidence(
                        evidence_id=(
                            "collect_follow_up:1:tool:kubernetes_logs"
                            if self.diagnosis_calls > 1
                            else "collect_context:1:tool:logs"
                        ),
                        source="kubernetes_logs",
                        query="get_pod_logs",
                        finding="模型错误地把失败的日志查询当作根因证据",
                    )
                ]
            elif self.mode == "source_mismatch":
                evidence = [
                    Evidence(
                        evidence_id="collect_context:1:tool:rollout",
                        source="logs",
                        query="get_rollout_history",
                        finding="模型篡改了证据来源",
                    )
                ]
            elif self.mode == "query_mismatch":
                evidence = [
                    Evidence(
                        evidence_id="collect_context:1:tool:rollout",
                        source="kubernetes_rollout",
                        query="get_pod_logs",
                        finding="模型把发布历史伪装成了日志查询",
                    )
                ]
            else:
                evidence = [
                    Evidence(
                        evidence_id="collect_context:1:tool:never-existed",
                        source="fabricated",
                        query="fabricated_tool",
                        finding="模型引用了不存在的证据",
                    )
                ]
            return Diagnosis(
                root_cause="结构合法但证据无效的主假设",
                confidence=0.99,
                hypotheses=[
                    Hypothesis(
                        statement="结构合法但证据无效的主假设",
                        confidence=0.99,
                        evidence=evidence,
                    )
                ],
                evidence_summary=["模型声称证据充分"],
            )
        if schema is DiagnosisReview:
            self.review_calls += 1
            return DiagnosisReview(
                sufficient=False,
                confidence=0.99,
                follow_up_queries=[
                    FollowUpQuery(
                        source="kubernetes_logs",
                        reason="补查日志以验证模型引用",
                    )
                ],
            )
        if schema is RemediationPlan:
            self.plan_calls += 1
            raise AssertionError("无效证据不得进入修复规划")
        raise TypeError(schema)


class MismatchedRootFieldsProvider(RuleBasedProvider):
    def __init__(self) -> None:
        super().__init__()
        self.diagnosis_calls = 0
        self.review_calls = 0
        self.plan_calls = 0

    async def structured(self, *, system, prompt, schema, metadata=None):
        if schema is RemediationPlan:
            self.plan_calls += 1
            raise AssertionError("未绑定主假设的根因不得进入修复规划")
        result = await super().structured(
            system=system,
            prompt=prompt,
            schema=schema,
            metadata=metadata,
        )
        if schema is Diagnosis:
            self.diagnosis_calls += 1
            primary = result.hypotheses[0].model_copy(update={"confidence": 0.05})
            return result.model_copy(
                update={
                    "root_cause": "没有证据支持的数据库损坏",
                    "confidence": 0.99,
                    "hypotheses": [primary],
                }
            )
        if schema is DiagnosisReview:
            self.review_calls += 1
        return result


class FailedLogSimulator(RecordingSimulator):
    async def call(self, name, arguments) -> ToolResult:
        self.calls.append(name)
        if name == "get_pod_logs":
            return ToolResult(tool_name=name, success=False, error="RBAC forbidden")
        return await SimulatedKubernetesBackend.call(self, name, arguments)


class NeverReflectRunbook(IncidentRunbook):
    def reflection_decision(self, state, diagnosis):
        return False


class CrossServicePlanProvider(RuleBasedProvider):
    async def structured(self, *, system, prompt, schema, metadata=None):
        if schema is RemediationPlan:
            return RemediationPlan(
                summary="修改另一个服务",
                actions=[
                    RemediationAction(
                        tool_name="restart_deployment",
                        arguments={"name": "payment-service"},
                        rationale="尝试扩大事故修复范围",
                        expected_outcome="另一个服务被重启",
                        risk=RiskLevel.MEDIUM,
                    )
                ],
                rollback="停止操作",
                verification=["检查服务"],
            )
        return await super().structured(
            system=system,
            prompt=prompt,
            schema=schema,
            metadata=metadata,
        )


class UnsafeScalePlanProvider(RuleBasedProvider):
    def __init__(self) -> None:
        self.plan_calls = 0

    async def structured(self, *, system, prompt, schema, metadata=None):
        if schema is RemediationPlan:
            self.plan_calls += 1
            return RemediationPlan(
                summary="扩容到不安全的副本数",
                actions=[
                    RemediationAction(
                        tool_name="scale_deployment",
                        arguments={"name": "order-service", "replicas": 1_000_000},
                        rationale="尝试绕过参数范围",
                        expected_outcome="创建大量副本",
                        risk=RiskLevel.HIGH,
                    )
                ],
                rollback="停止操作",
                verification=["检查服务"],
            )
        return await super().structured(
            system=system,
            prompt=prompt,
            schema=schema,
            metadata=metadata,
        )


class MutatingPlanRunbook(IncidentRunbook):
    def plan_feedback(self, state, plan, specs):
        plan.actions[0].arguments["name"] = "payment-service"
        plan.actions[0].arguments["unexpected"] = True
        return None


class InvalidStructuredDiagnosisProvider:
    name = "invalid_structured_diagnosis"

    def __init__(self) -> None:
        self.diagnosis_calls = 0

    async def structured(self, *, system, prompt, schema, metadata=None):
        if schema is Diagnosis:
            self.diagnosis_calls += 1
            raise RuntimeError("模型连续两次未返回合法 Diagnosis JSON")
        raise AssertionError("结构无效的诊断不得进入质量审查模型或修复规划")


class CatalogCapturingProvider(RuleBasedProvider):
    def __init__(self) -> None:
        super().__init__()
        self.catalog: dict = {}

    async def structured(self, *, system, prompt, schema, metadata=None):
        if schema is Diagnosis and not self.catalog:
            self.catalog = json.loads(prompt)["observations"]["evidence_catalog"]
        return await super().structured(
            system=system,
            prompt=prompt,
            schema=schema,
            metadata=metadata,
        )


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
@pytest.mark.parametrize(
    "mode", ["empty", "fabricated", "source_mismatch", "query_mismatch"]
)
async def test_invalid_model_evidence_escalates_without_planning_or_writes(mode: str) -> None:
    provider = InvalidEvidenceProvider(mode)
    backend = RecordingSimulator()
    agent = IncidentAgent(
        provider=provider,
        tools=ToolRegistry(backend),
        auto_approve_max_risk=RiskLevel.CRITICAL,
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.ESCALATED
    assert record.reflection_rounds == 1
    assert record.plan is None
    assert record.execution_results == []
    assert provider.diagnosis_calls == 2
    assert provider.review_calls == 1
    assert provider.plan_calls == 0
    assert not {"restart_deployment", "rollback_deployment", "scale_deployment"}.intersection(
        backend.calls
    )
    assert record.diagnosis_review is not None
    assert record.diagnosis_review.missing_evidence


@pytest.mark.asyncio
async def test_unbound_root_cause_and_confidence_cannot_enter_planning() -> None:
    provider = MismatchedRootFieldsProvider()
    backend = RecordingSimulator()
    agent = IncidentAgent(
        provider=provider,
        tools=ToolRegistry(backend),
        auto_approve_max_risk=RiskLevel.CRITICAL,
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.ESCALATED
    assert record.reflection_rounds == 1
    assert record.plan is None
    assert provider.diagnosis_calls == 2
    assert provider.review_calls == 1
    assert provider.plan_calls == 0
    assert record.diagnosis_review is not None
    assert "顶层 root_cause 与有证据的主假设 statement 不一致" in (
        record.diagnosis_review.missing_evidence
    )
    assert "顶层 confidence 与有证据的主假设 confidence 不一致" in (
        record.diagnosis_review.missing_evidence
    )
    assert not {"restart_deployment", "rollback_deployment", "scale_deployment"}.intersection(
        backend.calls
    )


@pytest.mark.asyncio
async def test_failed_tool_result_cannot_be_cited_as_supporting_evidence() -> None:
    provider = InvalidEvidenceProvider("failed")
    backend = FailedLogSimulator()
    agent = IncidentAgent(
        provider=provider,
        tools=ToolRegistry(backend),
        auto_approve_max_risk=RiskLevel.CRITICAL,
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.ESCALATED
    assert record.plan is None
    assert provider.plan_calls == 0
    assert backend.calls.count("get_pod_logs") == 2
    assert not {"restart_deployment", "rollback_deployment", "scale_deployment"}.intersection(
        backend.calls
    )


@pytest.mark.asyncio
async def test_lab_runbook_cannot_bypass_evidence_authenticity_gate() -> None:
    provider = InvalidEvidenceProvider("fabricated")
    backend = RecordingSimulator()
    agent = IncidentAgent(
        provider=provider,
        tools=ToolRegistry(backend),
        runbook=NeverReflectRunbook(),
        auto_approve_max_risk=RiskLevel.CRITICAL,
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.ESCALATED
    assert record.plan is None
    assert provider.plan_calls == 0


@pytest.mark.asyncio
async def test_structurally_invalid_diagnosis_safely_escalates() -> None:
    provider = InvalidStructuredDiagnosisProvider()
    backend = RecordingSimulator()
    agent = IncidentAgent(
        provider=provider,
        tools=ToolRegistry(backend),
        auto_approve_max_risk=RiskLevel.CRITICAL,
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.ESCALATED
    assert record.plan is None
    assert record.execution_results == []
    assert provider.diagnosis_calls == 1
    assert record.reflection_rounds == 0
    assert not {"restart_deployment", "rollback_deployment", "scale_deployment"}.intersection(
        backend.calls
    )


@pytest.mark.asyncio
async def test_cross_service_plan_is_rejected_before_any_write() -> None:
    backend = RecordingSimulator()
    agent = IncidentAgent(
        provider=CrossServicePlanProvider(),
        tools=ToolRegistry(backend),
        auto_approve_max_risk=RiskLevel.CRITICAL,
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.ESCALATED
    assert record.plan is None
    assert any(event.type == "remediation.plan_rejected" for event in record.timeline)
    assert any(
        event.type == "investigation.escalated" and "安全检查" in event.message
        for event in record.timeline
    )
    assert not {"restart_deployment", "rollback_deployment", "scale_deployment"}.intersection(
        backend.calls
    )


@pytest.mark.asyncio
async def test_extreme_scale_plan_is_retried_once_then_safely_escalated() -> None:
    provider = UnsafeScalePlanProvider()
    backend = RecordingSimulator()
    agent = IncidentAgent(
        provider=provider,
        tools=ToolRegistry(backend),
        auto_approve_max_risk=RiskLevel.CRITICAL,
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.ESCALATED
    assert record.plan is None
    assert provider.plan_calls == 2
    assert not {"restart_deployment", "rollback_deployment", "scale_deployment"}.intersection(
        backend.calls
    )


@pytest.mark.asyncio
async def test_runbook_mutation_is_revalidated_before_any_write() -> None:
    backend = RecordingSimulator()
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
        runbook=MutatingPlanRunbook(),
        auto_approve_max_risk=RiskLevel.CRITICAL,
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.ESCALATED
    assert record.plan is None
    assert any(event.type == "remediation.plan_rejected" for event in record.timeline)
    assert not {"restart_deployment", "rollback_deployment", "scale_deployment"}.intersection(
        backend.calls
    )


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
async def test_context_queries_publish_stable_server_evidence_catalog() -> None:
    provider = CatalogCapturingProvider()
    agent = IncidentAgent(
        provider=provider,
        tools=ToolRegistry(SimulatedKubernetesBackend()),
    )

    await agent.start(make_alert())

    assert provider.catalog["collect_context:1:tool:logs"] == {
        "evidence_id": "collect_context:1:tool:logs",
        "source": "kubernetes_logs",
        "tool": "get_pod_logs",
        "success": True,
    }
    assert provider.catalog["collect_context:1:tool:rollout"]["source"] == (
        "kubernetes_rollout"
    )


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
        runbook=BoundedReflectionRunbook(),
    )

    record = await agent.start(make_alert())

    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert record.reflection_rounds == 1
    assert any(event.type == "investigation.reflection_requested" for event in record.timeline)
    assert any(event.type == "evidence.supplemented" for event in record.timeline)


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["bad_rollout", "db_pool_exhaustion"])
async def test_incident_requires_approval_and_recovers(scenario: str) -> None:
    settings = Settings(tool_backend="simulator", model_provider="rule_based")
    agent = build_simulated_lab_agent(settings, scenario=scenario)

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
async def test_approved_action_runs_fresh_preflight_before_write() -> None:
    backend = RecordingSimulator()
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
    )

    record = await agent.start(make_alert())
    assert record.approval is not None
    assert record.approval.preflight_snapshot["current_revision"] == 2

    record = await agent.resume(record.id, approved=True, note="approve stable snapshot")

    assert record.status == IncidentStatus.RESOLVED
    assert backend.calls.count("get_rollout_history") == 3
    assert backend.calls.count("rollback_deployment") == 1
    event_types = [event.type for event in record.timeline]
    assert event_types.index("remediation.preflight_passed") < event_types.index(
        "action.executed"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation", ["new_revision", "proof_revoked", "read_failure", "self_recovered"]
)
async def test_approval_is_invalidated_when_fresh_preflight_changes(
    mutation: str,
) -> None:
    backend = PreflightMutationSimulator(mutation)
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
    )

    record = await agent.start(make_alert())
    assert record.status == IncidentStatus.AWAITING_APPROVAL
    record = await agent.resume(record.id, approved=True, note="approve stale plan")

    assert record.status == IncidentStatus.ESCALATED
    assert record.plan is None
    assert record.approval is None
    assert record.execution_results == []
    assert "rollback_deployment" not in backend.calls
    invalidated = next(
        event for event in record.timeline if event.type == "approval.invalidated"
    )
    if mutation == "self_recovered":
        assert "current_ready_replicas" in invalidated.data["reason"]
    preflight = next(step for step in record.execution_trace if step.id == "preflight:1")
    assert preflight.status == "blocked"
    assert not any(step.id == "execute:1" for step in record.execution_trace)


@pytest.mark.asyncio
async def test_status_only_resource_version_change_does_not_invalidate_approval() -> None:
    backend = PreflightMutationSimulator("resource_version_only")
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
    )

    record = await agent.start(make_alert())
    record = await agent.resume(record.id, approved=True, note="status update is harmless")

    assert record.status == IncidentStatus.RESOLVED
    assert backend.calls.count("rollback_deployment") == 1


@pytest.mark.asyncio
async def test_backend_cas_failure_cannot_be_reported_as_recovered() -> None:
    backend = PreflightMutationSimulator("backend_guard_failure")
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
    )

    record = await agent.start(make_alert())
    record = await agent.resume(record.id, approved=True, note="race after preflight")

    assert record.status == IncidentStatus.ESCALATED
    assert record.execution_results[0].success is False
    assert record.plan is None
    assert record.approval is None
    assert any(event.type == "approval.invalidated" for event in record.timeline)
    assert not any(step.id == "verify:1" for step in record.execution_trace)


@pytest.mark.asyncio
async def test_rejected_action_is_not_executed() -> None:
    settings = Settings(tool_backend="simulator", model_provider="rule_based")
    agent = build_simulated_lab_agent(settings, scenario="bad_rollout")

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
    agent = build_simulated_lab_agent(
        settings,
        scenario="transient_runtime_fault",
        runbook=VerifiedRuntimeStateRunbook(confidence_threshold=0.8),
        auto_approve_max_risk=RiskLevel.MEDIUM,
    )
    alert = Alert(
        name="InventoryTransientRuntimeFault",
        namespace="sentinelops-demo",
        service="inventory-service",
        severity="warning",
        summary="库存服务存在进程内瞬态故障",
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
        runbook=VerifiedRuntimeStateRunbook(confidence_threshold=0.8),
    )
    alert = Alert(
        name="InventoryTransientRuntimeFault",
        namespace="sentinelops-demo",
        service="inventory-service",
        severity="warning",
        summary="库存服务存在进程内瞬态故障",
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
        "alert": {"service": "inventory-service"},
        "observations": {
            "evidence_catalog": {
                "collect_context:1:tool:rollout": {
                    "evidence_id": "collect_context:1:tool:rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": True,
                }
            },
            "rollout": {
                "revisions": [
                    {
                        "revision": 5,
                        "replicas": 0,
                        "change_cause": "healthy-baseline",
                        "health_status": "healthy",
                        "health_proof": {"valid": True, "status": "healthy"},
                    },
                    {
                        "revision": 6,
                        "replicas": 1,
                        "change_cause": "routine-config-change",
                        "health_status": "unhealthy",
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
        "alert": {"service": "inventory-service"},
        "observations": {
            "evidence_catalog": {
                "collect_context:1:tool:rollout": {
                    "evidence_id": "collect_context:1:tool:rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": True,
                }
            },
            "rollout": {
                "revisions": [
                    {
                        "revision": 11,
                        "replicas": 0,
                        "change_cause": "healthy-baseline",
                        "health_status": "healthy",
                        "health_proof": {"valid": True, "status": "healthy"},
                    },
                    {"revision": 12, "replicas": 1, "change_cause": "enable-failure"},
                ]
            }
        }
    }

    feedback = IncidentAgent._plan_feedback(state, plan)  # type: ignore[arg-type]

    assert feedback is not None
    assert "revision 11" in feedback


def test_rollback_without_successful_rollout_history_fails_closed() -> None:
    plan = RemediationPlan(
        summary="回滚服务",
        actions=[
            RemediationAction(
                tool_name="rollback_deployment",
                arguments={"name": "inventory-service", "revision": 1},
                rationale="尝试回滚",
                expected_outcome="服务恢复",
                risk=RiskLevel.HIGH,
            )
        ],
        rollback="停止操作",
        verification=["检查错误率"],
    )
    state = {
        "alert": {"service": "inventory-service"},
        "observations": {
            "evidence_catalog": {
                "collect_context:1:tool:rollout": {
                    "evidence_id": "collect_context:1:tool:rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": False,
                }
            },
            "rollout": {"error": "RBAC forbidden"},
        },
    }

    feedback = IncidentAgent._plan_feedback(state, plan)  # type: ignore[arg-type]

    assert feedback is not None
    assert "采集成功" in feedback


def test_rollback_without_positive_health_marker_fails_closed() -> None:
    plan = RemediationPlan(
        summary="回滚服务",
        actions=[
            RemediationAction(
                tool_name="rollback_deployment",
                arguments={"name": "inventory-service", "revision": 1},
                rationale="回滚到上一版本",
                expected_outcome="服务恢复",
                risk=RiskLevel.HIGH,
            )
        ],
        rollback="停止操作",
        verification=["检查错误率"],
    )
    state = {
        "alert": {"service": "inventory-service"},
        "observations": {
            "evidence_catalog": {
                "collect_context:1:tool:rollout": {
                    "evidence_id": "collect_context:1:tool:rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": True,
                }
            },
            "rollout": {
                "revisions": [
                    {"revision": 1, "replicas": 0},
                    {"revision": 2, "replicas": 1, "change_cause": "failure"},
                ]
            },
        },
    }

    feedback = IncidentAgent._plan_feedback(state, plan)  # type: ignore[arg-type]

    assert feedback is not None
    assert "没有可信健康标记" in feedback


@pytest.mark.parametrize(
    "revision",
    [
        {"change_cause": "unhealthy-release"},
        {"change_cause": "unstable-config"},
        {"change_cause": "not-healthy"},
        {"change_cause": "healthy-baseline"},
        {"health_status": "unhealthy", "change_cause": "healthy-baseline"},
        {"health_status": "unknown"},
        {"health_status": "HEALTHY"},
        {"health_status": "stable"},
        {},
    ],
)
def test_revision_health_never_uses_free_text_or_unknown_values(
    revision: dict,
) -> None:
    assert IncidentAgent._revision_is_known_healthy(revision) is False


def test_valid_health_proof_overrides_misleading_free_text() -> None:
    revision = {
        "health_status": "healthy",
        "health_proof": {"valid": True, "status": "healthy"},
        "change_cause": "unhealthy-release",
    }

    assert IncidentAgent._revision_is_known_healthy(revision) is True


def test_unsorted_hypothesis_cannot_lend_evidence_to_root_cause() -> None:
    state = {
        "observations": {
            "evidence_catalog": {
                "rollout": {
                    "evidence_id": "rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": True,
                },
                "events": {
                    "evidence_id": "events",
                    "source": "kubernetes_events",
                    "tool": "list_events",
                    "success": True,
                },
            }
        }
    }
    diagnosis = Diagnosis(
        root_cause="没有证据的真正根因",
        confidence=0.8,
        hypotheses=[
            Hypothesis(statement="没有证据的真正根因", confidence=0.8),
            Hypothesis(
                statement="有证据但无关的假设",
                confidence=0.9,
                evidence=[
                    Evidence(
                        evidence_id="rollout",
                        source="kubernetes_rollout",
                        query="get_rollout_history",
                        finding="发布历史存在",
                    ),
                    Evidence(
                        evidence_id="events",
                        source="kubernetes_events",
                        query="list_events",
                        finding="事件存在",
                    ),
                ],
            ),
        ],
        evidence_summary=[],
    )

    issues = IncidentAgent._diagnosis_evidence_issues(  # type: ignore[arg-type]
        state, diagnosis
    )

    assert "诊断假设未按置信度从高到低排列" in issues
    assert "主假设至少需要两个独立且采集成功的证据来源" in issues


@pytest.mark.parametrize(
    ("root_cause", "confidence", "expected_issue", "unexpected_issue"),
    [
        (
            "没有证据支持的另一个根因",
            0.95,
            "顶层 root_cause 与有证据的主假设 statement 不一致",
            "顶层 confidence 与有证据的主假设 confidence 不一致",
        ),
        (
            "有两条合法证据支持的根因",
            0.99,
            "顶层 confidence 与有证据的主假设 confidence 不一致",
            "顶层 root_cause 与有证据的主假设 statement 不一致",
        ),
    ],
)
def test_root_cause_and_confidence_binding_rules_are_independent(
    root_cause: str,
    confidence: float,
    expected_issue: str,
    unexpected_issue: str,
) -> None:
    state = {
        "observations": {
            "evidence_catalog": {
                "rollout": {
                    "evidence_id": "rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": True,
                },
                "events": {
                    "evidence_id": "events",
                    "source": "kubernetes_events",
                    "tool": "list_events",
                    "success": True,
                },
            }
        }
    }
    diagnosis = Diagnosis(
        root_cause=root_cause,
        confidence=confidence,
        hypotheses=[
            Hypothesis(
                statement="有两条合法证据支持的根因",
                confidence=0.95,
                evidence=[
                    Evidence(
                        evidence_id="rollout",
                        source="kubernetes_rollout",
                        query="get_rollout_history",
                        finding="发布历史支持根因",
                    ),
                    Evidence(
                        evidence_id="events",
                        source="kubernetes_events",
                        query="list_events",
                        finding="事件支持根因",
                    ),
                ],
            )
        ],
        evidence_summary=[],
    )

    issues = IncidentAgent._diagnosis_evidence_issues(  # type: ignore[arg-type]
        state, diagnosis
    )

    assert expected_issue in issues
    assert unexpected_issue not in issues
    assert "主假设至少需要两个独立且采集成功的证据来源" not in issues


@pytest.mark.parametrize(
    ("invalid_evidence", "expected_issue"),
    [
        (
            Evidence(
                evidence_id="never-existed",
                source="kubernetes_logs",
                query="get_pod_logs",
                finding="伪造证据",
            ),
            "诊断引用了不存在的证据 never-existed",
        ),
        (
            Evidence(
                evidence_id="logs",
                source="tampered_source",
                query="get_pod_logs",
                finding="篡改来源",
            ),
            "证据 logs 的 source 与服务端目录不一致",
        ),
        (
            Evidence(
                evidence_id="logs",
                source="kubernetes_logs",
                query="list_events",
                finding="篡改工具",
            ),
            "证据 logs 的 query 与实际工具不一致",
        ),
        (
            Evidence(
                evidence_id="failed",
                source="loki",
                query="search_loki",
                finding="引用失败查询",
            ),
            "诊断引用的证据采集失败：failed",
        ),
    ],
)
def test_each_evidence_authenticity_rule_is_enforced_independently(
    invalid_evidence: Evidence,
    expected_issue: str,
) -> None:
    state = {
        "observations": {
            "evidence_catalog": {
                "rollout": {
                    "evidence_id": "rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": True,
                },
                "events": {
                    "evidence_id": "events",
                    "source": "kubernetes_events",
                    "tool": "list_events",
                    "success": True,
                },
                "logs": {
                    "evidence_id": "logs",
                    "source": "kubernetes_logs",
                    "tool": "get_pod_logs",
                    "success": True,
                },
                "failed": {
                    "evidence_id": "failed",
                    "source": "loki",
                    "tool": "search_loki",
                    "success": False,
                },
            }
        }
    }
    diagnosis = Diagnosis(
        root_cause="有两条合法证据支持的根因",
        confidence=0.95,
        hypotheses=[
            Hypothesis(
                statement="有两条合法证据支持的根因",
                confidence=0.95,
                evidence=[
                    Evidence(
                        evidence_id="rollout",
                        source="kubernetes_rollout",
                        query="get_rollout_history",
                        finding="发布历史支持根因",
                    ),
                    Evidence(
                        evidence_id="events",
                        source="kubernetes_events",
                        query="list_events",
                        finding="事件支持根因",
                    ),
                    invalid_evidence,
                ],
            )
        ],
        evidence_summary=[],
    )

    issues = IncidentAgent._diagnosis_evidence_issues(  # type: ignore[arg-type]
        state, diagnosis
    )

    assert expected_issue in issues
    assert "主假设至少需要两个独立且采集成功的证据来源" not in issues


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
