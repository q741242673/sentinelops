from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

import sentinelops.agent.engine as engine_module
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
from sentinelops.tools.registry import (
    KUBERNETES_TOOL_SPECS,
    OBSERVABILITY_TOOL_SPECS,
    ToolRegistry,
)
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
            if self.rollout_reads > 2 and self.mutation == "namespace":
                result.content["namespace"] = "another-namespace"
            return result
        if name == "rollback_deployment" and self.mutation == "backend_guard_failure":
            self.calls.append(name)
            return ToolResult(
                tool_name=name,
                success=False,
                error="Execution precondition failed: resource_version",
            )
        return await super().call(name, arguments)


class BlockingRollbackSimulator(RecordingSimulator):
    def __init__(self) -> None:
        super().__init__()
        self.rollback_started = asyncio.Event()
        self.never_finish = asyncio.Event()

    async def call(self, name, arguments) -> ToolResult:
        if name != "rollback_deployment":
            return await super().call(name, arguments)
        self.calls.append(name)
        result = await SimulatedKubernetesBackend.call(self, name, arguments)
        self.rollback_started.set()
        await self.never_finish.wait()
        return result


class BlockingPreflightSimulator(RecordingSimulator):
    def __init__(self) -> None:
        super().__init__()
        self.rollout_reads = 0
        self.preflight_started = asyncio.Event()
        self.release_preflight = asyncio.Event()

    async def call(self, name, arguments) -> ToolResult:
        if name == "get_rollout_history":
            self.rollout_reads += 1
            if self.rollout_reads == 3:
                self.preflight_started.set()
                await self.release_preflight.wait()
        return await super().call(name, arguments)


class BlockingFailedVerificationSimulator(RecordingSimulator):
    def __init__(self) -> None:
        super().__init__()
        self.write_completed = False
        self.verify_started = asyncio.Event()
        self.release_verify = asyncio.Event()
        self.blocked_once = False

    async def call(self, name, arguments) -> ToolResult:
        if name == "rollback_deployment":
            result = await super().call(name, arguments)
            self.write_completed = True
            return result
        if name == "get_service_metrics" and self.write_completed:
            self.calls.append(name)
            if not self.blocked_once:
                self.blocked_once = True
                self.verify_started.set()
                await self.release_verify.wait()
            return ToolResult(
                tool_name=name,
                success=True,
                content={"error_rate": 0.5, "availability": 0.5},
            )
        return await super().call(name, arguments)


class CrossNamespaceAlertSimulator(RecordingSimulator):
    def __init__(self) -> None:
        super().__init__()
        self.alert_queries: list[str] = []

    async def call(self, name, arguments) -> ToolResult:
        if name == "query_prometheus":
            self.calls.append(name)
            query = arguments["query"]
            if query.startswith("ALERTS{"):
                self.alert_queries.append(query)
                return ToolResult(
                    tool_name=name,
                    success=True,
                    content={
                        "result": [
                            {
                                "metric": {
                                    "alertname": "HighErrorRate",
                                    "alertstate": "firing",
                                    "service": "order-service",
                                    "namespace": "other-namespace",
                                },
                                "value": [0, "1"],
                            }
                        ]
                    },
                )
            return ToolResult(tool_name=name, success=True, content={"result": []})
        if name in {"search_loki", "get_trace"}:
            self.calls.append(name)
            return ToolResult(tool_name=name, success=True, content={"result": []})
        return await super().call(name, arguments)


class ScaleEvidenceSimulator(SimulatedKubernetesBackend):
    def __init__(self) -> None:
        super().__init__(scenario="db_pool_exhaustion")

    async def call(self, name, arguments) -> ToolResult:
        result = await super().call(name, arguments)
        if name == "get_rollout_history" and result.success:
            result.content["desired_replicas"] = 3
            result.content["revisions"][0]["replicas"] = 3
            result.content["revisions"][0]["ready_replicas"] = 3
        return result


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
        self.diagnosis_prompts: list[dict] = []
        self.review_calls = 0
        self.plan_calls = 0

    async def structured(self, *, system, prompt, schema, metadata=None):
        if schema is Diagnosis:
            self.diagnosis_calls += 1
            self.diagnosis_prompts.append(json.loads(prompt))
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


class ScalePlanProvider(RuleBasedProvider):
    def __init__(self, replicas: int) -> None:
        self.replicas = replicas

    async def structured(self, *, system, prompt, schema, metadata=None):
        if schema is RemediationPlan:
            return RemediationPlan(
                summary="根据容量饱和证据扩容服务",
                actions=[
                    RemediationAction(
                        tool_name="scale_deployment",
                        arguments={"name": "order-service", "replicas": self.replicas},
                        rationale="连接池和错误率同时达到容量上限",
                        expected_outcome="增加处理容量",
                        risk=RiskLevel.HIGH,
                    )
                ],
                rollback="恢复原副本数",
                verification=["错误率和延迟恢复"],
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
async def test_reflection_receives_server_evidence_rejection_reasons() -> None:
    provider = InvalidEvidenceProvider("query_mismatch")
    agent = IncidentAgent(
        provider=provider,
        tools=ToolRegistry(RecordingSimulator()),
    )

    await agent.start(make_alert())

    assert len(provider.diagnosis_prompts) == 2
    retry = provider.diagnosis_prompts[1]
    assert "previous_diagnosis_rejection_reasons" in retry
    assert any(
        "query 与实际工具不一致" in reason
        for reason in retry["previous_diagnosis_rejection_reasons"]
    )
    assert "逐项修正" in retry["instruction"]


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

    record = await agent.resume(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="test approval",
    )

    assert record.status == IncidentStatus.RESOLVED
    assert record.approval is None
    assert record.execution_results[0].success is True
    assert record.postmortem is not None
    decision = next(event for event in record.timeline if event.type == "approval.decided")
    assert decision.data["approved"] is True
    assert decision.data["approval_id"]
    assert decision.data["approval_version"] == 1


@pytest.mark.asyncio
async def test_approved_action_runs_fresh_preflight_before_write() -> None:
    backend = RecordingSimulator()
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
        verification_policy="offline",
    )

    record = await agent.start(make_alert())
    assert record.approval is not None
    assert record.approval.preflight_snapshot["current_revision"] == 2

    record = await agent.resume(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="approve stable snapshot",
    )

    assert record.status == IncidentStatus.RESOLVED
    assert backend.calls.count("get_rollout_history") == 3
    assert backend.calls.count("rollback_deployment") == 1
    event_types = [event.type for event in record.timeline]
    assert event_types.index("remediation.preflight_passed") < event_types.index(
        "action.executed"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ["new_revision", "proof_revoked", "read_failure", "self_recovered", "namespace"],
)
async def test_approval_is_invalidated_when_fresh_preflight_changes(
    mutation: str,
) -> None:
    backend = PreflightMutationSimulator(mutation)
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
        verification_policy="offline",
    )

    record = await agent.start(make_alert())
    assert record.status == IncidentStatus.AWAITING_APPROVAL
    assert record.approval is not None
    record = await agent.resume(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="approve stale plan",
    )

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
async def test_alert_namespace_mismatch_is_rejected_before_approval_or_write() -> None:
    backend = RecordingSimulator()
    agent = IncidentAgent(provider=RuleBasedProvider(), tools=ToolRegistry(backend))
    alert = make_alert().model_copy(update={"namespace": "payments-prod"})

    record = await agent.start(alert)

    assert record.status == IncidentStatus.ESCALATED
    assert record.approval is None
    assert record.execution_results == []
    assert "rollback_deployment" not in backend.calls
    invalidated = next(
        event for event in record.timeline if event.type == "approval.invalidated"
    )
    assert "namespace" in invalidated.data["reason"]


@pytest.mark.asyncio
async def test_resolved_signal_cancels_before_waiting_for_resume_lock() -> None:
    backend = BlockingPreflightSimulator()
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
        verification_policy="offline",
    )
    record = await agent.start(make_alert())
    assert record.approval is not None

    resume_task = asyncio.create_task(
        agent.resume(
            record.id,
            approval_id=record.approval.approval_id,
            approval_version=record.approval.version,
            approved=True,
        )
    )
    await asyncio.wait_for(backend.preflight_started.wait(), timeout=1)
    invalidate_task = asyncio.create_task(
        agent.invalidate_pending_approval(record.id, reason="alert resolved")
    )
    await asyncio.sleep(0)
    assert not invalidate_task.done()

    backend.release_preflight.set()
    await resume_task
    current = await invalidate_task

    assert current is not None
    assert current.status == IncidentStatus.RESOLVED
    assert backend.calls.count("rollback_deployment") == 0
    assert not any(event.type == "action.executed" for event in current.timeline)
    assert current.timeline[-1].type == "alertmanager.resolved"
    assert "未执行集群写入" in current.timeline[-1].message


@pytest.mark.asyncio
async def test_resolved_during_write_records_unknown_outcome() -> None:
    backend = BlockingRollbackSimulator()
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
        verification_policy="offline",
    )
    record = await agent.start(make_alert())
    assert record.approval is not None
    resume_task = asyncio.create_task(
        agent.resume(
            record.id,
            approval_id=record.approval.approval_id,
            approval_version=record.approval.version,
            approved=True,
        )
    )
    await asyncio.wait_for(backend.rollback_started.wait(), timeout=1)
    invalidate_task = asyncio.create_task(
        agent.invalidate_pending_approval(record.id, reason="alert resolved")
    )
    await asyncio.sleep(0)
    assert not invalidate_task.done()

    backend.never_finish.set()
    await resume_task
    current = await invalidate_task

    assert current is not None
    assert current.status == IncidentStatus.ESCALATED
    unknown = next(event for event in current.timeline if event.type == "action.outcome_unknown")
    assert unknown.data["execution_outcome"] == "unknown"
    assert current.timeline[-1].type == "alertmanager.resolved"
    assert current.timeline[-1].data["execution_outcome"] == "unknown"
    assert "未执行写操作" not in current.timeline[-1].message


@pytest.mark.asyncio
async def test_resolved_during_verification_preserves_failed_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = BlockingFailedVerificationSimulator()
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
        verification_policy="offline",
    )
    record = await agent.start(make_alert())
    assert record.approval is not None
    original_sleep = asyncio.sleep

    async def no_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr(engine_module.asyncio, "sleep", no_sleep)
    resume_task = asyncio.create_task(
        agent.resume(
            record.id,
            approval_id=record.approval.approval_id,
            approval_version=record.approval.version,
            approved=True,
        )
    )
    await asyncio.wait_for(backend.verify_started.wait(), timeout=1)
    invalidate_task = asyncio.create_task(
        agent.invalidate_pending_approval(record.id, reason="alert resolved during verification")
    )
    await original_sleep(0)
    assert not invalidate_task.done()

    backend.release_verify.set()
    await resume_task
    current = await invalidate_task

    assert current is not None
    assert current.status == IncidentStatus.FAILED
    assert len(current.execution_results) == 1
    assert any(event.type == "action.executed" for event in current.timeline)
    recovery = next(event for event in current.timeline if event.type == "recovery.verified")
    assert recovery.message == "恢复标准未满足"
    assert current.postmortem is not None
    assert "状态：修复失败" in current.postmortem
    assert current.timeline[-1].type == "alertmanager.resolved"
    assert "保持原有终态" in current.timeline[-1].message


@pytest.mark.asyncio
async def test_cross_namespace_alert_cannot_authorize_preflight() -> None:
    backend = CrossNamespaceAlertSimulator()
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(
            backend,
            [*KUBERNETES_TOOL_SPECS, *OBSERVABILITY_TOOL_SPECS],
        ),
        verification_policy="strict",
    )
    alert = make_alert().model_copy(
        update={"labels": {"source": "alertmanager"}}
    )
    record = await agent.start(alert)
    assert record.approval is not None

    record = await agent.resume(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
    )

    assert record.status == IncidentStatus.ESCALATED
    assert backend.calls.count("rollback_deployment") == 0
    assert backend.alert_queries
    assert 'namespace="sentinelops-demo"' in backend.alert_queries[-1]
    invalidated = next(
        event for event in record.timeline if event.type == "approval.invalidated"
    )
    assert "原告警仍处于 firing" in invalidated.data["reason"]


@pytest.mark.asyncio
async def test_duplicate_approval_is_consumed_exactly_once() -> None:
    backend = RecordingSimulator()
    agent = IncidentAgent(provider=RuleBasedProvider(), tools=ToolRegistry(backend))
    record = await agent.start(make_alert())
    assert record.approval is not None
    approval = record.approval

    outcomes = await asyncio.gather(
        agent.resume(
            record.id,
            approval_id=approval.approval_id,
            approval_version=approval.version,
            approved=True,
        ),
        agent.resume(
            record.id,
            approval_id=approval.approval_id,
            approval_version=approval.version,
            approved=True,
        ),
        return_exceptions=True,
    )

    assert sum(isinstance(item, RuntimeError) for item in outcomes) == 1
    assert backend.calls.count("rollback_deployment") == 1
    assert agent.get(record.id).approval is None


@pytest.mark.asyncio
async def test_conflicting_approval_decisions_cannot_both_take_effect() -> None:
    backend = RecordingSimulator()
    agent = IncidentAgent(provider=RuleBasedProvider(), tools=ToolRegistry(backend))
    record = await agent.start(make_alert())
    assert record.approval is not None
    approval = record.approval

    outcomes = await asyncio.gather(
        agent.resume(
            record.id,
            approval_id=approval.approval_id,
            approval_version=approval.version,
            approved=True,
        ),
        agent.resume(
            record.id,
            approval_id=approval.approval_id,
            approval_version=approval.version,
            approved=False,
        ),
        return_exceptions=True,
    )

    assert sum(isinstance(item, RuntimeError) for item in outcomes) == 1
    assert backend.calls.count("rollback_deployment") <= 1
    assert agent.get(record.id).approval is None


@pytest.mark.asyncio
async def test_cancelled_resume_records_unknown_outcome_and_clears_approval() -> None:
    backend = BlockingRollbackSimulator()
    agent = IncidentAgent(provider=RuleBasedProvider(), tools=ToolRegistry(backend))
    record = await agent.start(make_alert())
    assert record.approval is not None
    approval = record.approval

    task = asyncio.create_task(
        agent.resume(
            record.id,
            approval_id=approval.approval_id,
            approval_version=approval.version,
            approved=True,
            note="cancel after write started",
        )
    )
    await asyncio.wait_for(backend.rollback_started.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    current = agent.get(record.id)
    assert backend.calls.count("rollback_deployment") == 1
    assert current.status == IncidentStatus.FAILED
    assert current.approval is None
    assert current.active_step_id is None
    assert not any(step.status == "running" for step in current.execution_trace)
    cancelled = next(
        event for event in current.timeline if event.type == "approval.resume_cancelled"
    )
    assert cancelled.data["execution_outcome"] == "unknown"
    assert cancelled.data["approval_id"] == approval.approval_id

    with pytest.raises(RuntimeError, match="没有可处理的审批"):
        await agent.resume(
            record.id,
            approval_id=approval.approval_id,
            approval_version=approval.version,
            approved=True,
        )


@pytest.mark.asyncio
async def test_stale_or_expired_approval_cannot_resume_graph() -> None:
    backend = RecordingSimulator()
    agent = IncidentAgent(provider=RuleBasedProvider(), tools=ToolRegistry(backend))
    record = await agent.start(make_alert())
    assert record.approval is not None

    with pytest.raises(RuntimeError, match="标识或版本已失效"):
        await agent.resume(
            record.id,
            approval_id="stale-approval",
            approval_version=record.approval.version,
            approved=True,
        )

    record.approval.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(RuntimeError, match="已过期"):
        await agent.resume(
            record.id,
            approval_id=record.approval.approval_id,
            approval_version=record.approval.version,
            approved=True,
        )
    assert backend.calls.count("rollback_deployment") == 0
    assert record.status == IncidentStatus.ESCALATED
    assert record.approval is None
    expired = next(event for event in record.timeline if event.type == "approval.expired")
    assert expired.data["approval_id"]
    assert expired.data["approval_version"] == 1


@pytest.mark.asyncio
async def test_status_only_resource_version_change_does_not_invalidate_approval() -> None:
    backend = PreflightMutationSimulator("resource_version_only")
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(backend),
        verification_policy="offline",
    )

    record = await agent.start(make_alert())
    assert record.approval is not None
    record = await agent.resume(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="status update is harmless",
    )

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
    assert record.approval is not None
    record = await agent.resume(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=True,
        note="race after preflight",
    )

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
    assert record.approval is not None
    record = await agent.resume(
        record.id,
        approval_id=record.approval.approval_id,
        approval_version=record.approval.version,
        approved=False,
        note="change freeze",
    )

    assert record.status == IncidentStatus.REJECTED
    assert record.approval is None
    assert record.execution_results == []
    decision = next(event for event in record.timeline if event.type == "approval.decided")
    assert decision.data["approved"] is False


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
        verification_policy="offline",
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


def test_restart_requires_deterministic_causal_evidence() -> None:
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(SimulatedKubernetesBackend()),
    )
    action = RemediationAction(
        tool_name="restart_deployment",
        arguments={"name": "order-service"},
        rationale="重启服务",
        expected_outcome="服务恢复",
        risk=RiskLevel.MEDIUM,
    )

    unsupported = agent._causal_action_feedback(
        {"observations": {"logs": {"lines": []}, "metrics": {}}},  # type: ignore[arg-type]
        action,
    )
    supported = agent._causal_action_feedback(
        {
            "observations": {
                "logs": {
                    "lines": ["ERROR timeout acquiring database connection from pool"]
                },
                "metrics": {"db_pool_utilization": 0.98},
            }
        },  # type: ignore[arg-type]
        action,
    )

    assert unsupported is not None
    assert supported is None


@pytest.mark.parametrize(
    ("requested_replicas", "allowed"),
    [(0, False), (2, False), (3, False), (4, True)],
)
def test_scale_requires_positive_growth_from_current_desired_replicas(
    requested_replicas: int,
    allowed: bool,
) -> None:
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(SimulatedKubernetesBackend()),
    )
    action = RemediationAction(
        tool_name="scale_deployment",
        arguments={"name": "order-service", "replicas": requested_replicas},
        rationale="扩容服务",
        expected_outcome="服务恢复",
        risk=RiskLevel.HIGH,
    )
    feedback = agent._causal_action_feedback(
        {
            "observations": {
                "rollout": {"desired_replicas": 3},
                "metrics": {"cpu_utilization": 0.95, "error_rate": 0.12},
            }
        },  # type: ignore[arg-type]
        action,
    )

    assert (feedback is None) is allowed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requested_replicas", "expected_status"),
    [
        (0, IncidentStatus.ESCALATED),
        (2, IncidentStatus.ESCALATED),
        (3, IncidentStatus.ESCALATED),
        (4, IncidentStatus.AWAITING_APPROVAL),
    ],
)
async def test_scale_plan_direction_is_enforced_before_approval(
    requested_replicas: int,
    expected_status: IncidentStatus,
) -> None:
    agent = IncidentAgent(
        provider=ScalePlanProvider(requested_replicas),
        tools=ToolRegistry(ScaleEvidenceSimulator()),
    )

    record = await agent.start(make_alert())

    assert record.status == expected_status
    if expected_status == IncidentStatus.ESCALATED:
        assert record.approval is None
        assert record.plan is None
        assert record.execution_results == []
    else:
        assert record.approval is not None


def test_scale_still_requires_saturation_and_user_impact_evidence() -> None:
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(SimulatedKubernetesBackend()),
    )
    action = RemediationAction(
        tool_name="scale_deployment",
        arguments={"name": "order-service", "replicas": 4},
        rationale="扩容服务",
        expected_outcome="服务恢复",
        risk=RiskLevel.HIGH,
    )

    feedback = agent._causal_action_feedback(
        {
            "observations": {
                "rollout": {"desired_replicas": 3},
                "metrics": {"cpu_utilization": 0.95},
            }
        },  # type: ignore[arg-type]
        action,
    )

    assert feedback is not None


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


def test_rollback_requires_a_current_fault_or_trusted_change_correlation() -> None:
    plan = RemediationPlan(
        summary="回滚服务",
        actions=[
            RemediationAction(
                tool_name="rollback_deployment",
                arguments={"name": "order-service", "revision": 1},
                rationale="上一版本健康",
                expected_outcome="服务恢复",
                risk=RiskLevel.HIGH,
            )
        ],
        rollback="停止操作",
        verification=["检查错误率"],
    )
    state = {
        "alert": {"service": "order-service"},
        "observations": {
            "evidence_catalog": {
                "rollout": {
                    "evidence_id": "rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": True,
                }
            },
            "pods": {
                "items": [
                    {
                        "revision": 2,
                        "phase": "Running",
                        "ready": False,
                        "restarts": 7,
                        "waiting_reasons": [],
                    }
                ]
            },
            "events": {"items": [{"type": "Normal", "message": "No warnings"}]},
            "logs": {"lines": ["INFO: service healthy"]},
            "metrics": {"error_rate": 0.0, "p95_ms": 100},
            "rollout": {
                "current_revision": 2,
                "revisions": [
                    {
                        "revision": 1,
                        "replicas": 0,
                        "ready_replicas": 0,
                        "status": "stable",
                        "health_proof": {"valid": True, "status": "healthy"},
                    },
                    {
                        "revision": 2,
                        "replicas": 1,
                        "ready_replicas": 1,
                        "status": "stable",
                        "health_status": "healthy",
                    },
                ],
            },
        },
    }

    feedback = IncidentAgent._plan_feedback(state, plan)  # type: ignore[arg-type]

    assert feedback is not None
    assert "没有明确异常" in feedback


def test_rollback_accepts_kind_bad_rollout_marker_with_observed_failure() -> None:
    plan = RemediationPlan(
        summary="回滚服务",
        actions=[
            RemediationAction(
                tool_name="rollback_deployment",
                arguments={"name": "order-service", "revision": 1},
                rationale="上一版本健康",
                expected_outcome="服务恢复",
                risk=RiskLevel.HIGH,
            )
        ],
        rollback="停止操作",
        verification=["检查错误率"],
    )
    state = {
        "alert": {"service": "order-service"},
        "observations": {
            "evidence_catalog": {
                "rollout": {
                    "evidence_id": "rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": True,
                }
            },
            # The real Kubernetes backend omits revision from Pod summaries.
            "pods": {
                "items": [
                    {
                        "phase": "Running",
                        "ready": False,
                        "restarts": 3,
                        "waiting_reasons": ["CrashLoopBackOff"],
                    }
                ]
            },
            "logs": {
                "lines": ["FATAL: application configuration is invalid"]
            },
            "metrics": {
                "desired_replicas": 1,
                "available_replicas": 0,
                "availability": 0.0,
            },
            "rollout": {
                "current_revision": 2,
                "revisions": [
                    {
                        "revision": 1,
                        "replicas": 0,
                        "ready_replicas": 0,
                        "health_proof": {"valid": True, "status": "healthy"},
                    },
                    {
                        "revision": 2,
                        "replicas": 1,
                        "ready_replicas": 0,
                        "change_cause": "bad-rollout",
                        "health_proof": {"valid": False, "status": "unknown"},
                    },
                ],
            },
        },
    }

    assert IncidentAgent._plan_feedback(state, plan) is None  # type: ignore[arg-type]


def test_supporting_finding_must_match_server_raw_observation() -> None:
    state = {
        "evidence_snapshots": {
            "events": {"items": [{"type": "Normal", "message": "No warning events"}]},
            "rollout": {
                "current_revision": 2,
                "revisions": [{"revision": 2, "replicas": 1, "status": "failed"}],
            },
        },
        "observations": {
            "events": {"items": [{"type": "Normal", "message": "No warning events"}]},
            "rollout": {
                "current_revision": 2,
                "revisions": [{"revision": 2, "replicas": 1, "status": "failed"}],
            },
            "evidence_catalog": {
                "events": {
                    "evidence_id": "events",
                    "source": "kubernetes_events",
                    "tool": "list_events",
                    "success": True,
                },
                "rollout": {
                    "evidence_id": "rollout",
                    "source": "kubernetes_rollout",
                    "tool": "get_rollout_history",
                    "success": True,
                },
            },
        }
    }
    diagnosis = Diagnosis(
        root_cause="最新发布导致容器启动失败",
        confidence=0.95,
        hypotheses=[
            Hypothesis(
                statement="最新发布导致容器启动失败",
                confidence=0.95,
                evidence=[
                    Evidence(
                        evidence_id="events",
                        source="kubernetes_events",
                        query="list_events",
                        finding="事件明确显示 CrashLoopBackOff",
                    ),
                    Evidence(
                        evidence_id="rollout",
                        source="kubernetes_rollout",
                        query="get_rollout_history",
                        finding="当前 revision 明确失败",
                    ),
                ],
            )
        ],
        evidence_summary=[],
    )

    issues = IncidentAgent._diagnosis_evidence_issues(  # type: ignore[arg-type]
        state, diagnosis
    )

    assert "证据 events 的 finding 没有对应原始观测支持" in issues


def test_model_supplied_raw_cannot_replace_server_observation() -> None:
    state = {
        "evidence_snapshots": {
            "events": {"items": [{"type": "Normal", "message": "No warning events"}]}
        },
        "observations": {
            "events": {"items": [{"type": "Normal", "message": "No warning events"}]},
            "evidence_catalog": {
                "events": {
                    "evidence_id": "events",
                    "source": "kubernetes_events",
                    "tool": "list_events",
                    "success": True,
                }
            },
        }
    }
    diagnosis = Diagnosis(
        root_cause="容器启动失败",
        confidence=0.95,
        hypotheses=[
            Hypothesis(
                statement="容器启动失败",
                confidence=0.95,
                evidence=[
                    Evidence(
                        evidence_id="events",
                        source="kubernetes_events",
                        query="list_events",
                        finding="事件明确显示 CrashLoopBackOff",
                        raw={"items": [{"message": "CrashLoopBackOff"}]},
                    )
                ],
            )
        ],
        evidence_summary=[],
    )

    issues = IncidentAgent._diagnosis_evidence_issues(  # type: ignore[arg-type]
        state, diagnosis
    )

    assert "证据 events 的 raw 与服务端原始观测不一致" in issues


def test_server_predicates_ignore_query_metadata_and_negated_failures() -> None:
    assert not IncidentAgent._loki_has_explicit_failure(
        {
            "query": '|~ "(error|failed|fatal|timeout|exception)"',
            "result": [],
        }
    )
    assert not IncidentAgent._logs_have_explicit_failure(
        {"lines": ["INFO: error budget is healthy; no request failures detected"]}
    )
    assert not IncidentAgent._logs_have_explicit_failure(
        {"lines": ["transient_runtime_fault_enabled=false restart_required=true"]}
    )
    assert IncidentAgent._logs_have_explicit_failure(
        {"lines": ["transient_runtime_fault_enabled restart_required=true"]}
    )
    assert not IncidentAgent._events_have_explicit_failure(
        {
            "items": [
                {
                    "type": "Normal",
                    "reason": "Pulled",
                    "message": "No readiness probe failed",
                }
            ]
        }
    )


@pytest.mark.asyncio
async def test_strict_verification_escalates_when_required_capabilities_are_missing() -> None:
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(SimulatedKubernetesBackend()),
        verification_policy="strict",
    )

    result = await agent._verify(  # type: ignore[arg-type]
        {
            "incident_id": "strict-verification",
            "alert": {
                "name": "HighOrderServiceErrorRate",
                "service": "order-service",
                "labels": {},
            },
        }
    )

    assert result["status"] == IncidentStatus.ESCALATED.value
    assert result["timeline"][0]["type"] == "recovery.verification_incomplete"
    assert result["timeline"][0]["data"]["missing_capabilities"] == [
        "prometheus",
        "active_probe",
        "tempo",
    ]


def test_unbound_cross_service_event_cannot_authorize_rollback() -> None:
    events = {
        "items": [
            {
                "type": "Warning",
                "reason": "Unhealthy",
                "message": "revision 7 readiness probe failed",
                "object": "unrelated-api-abc",
                "object_uid": "unrelated-uid",
            }
        ]
    }
    observations = {
        "pods": {"items": []},
        "logs": {"lines": ["ERROR: timeout acquiring database connection from pool"]},
        "metrics": {"error_rate": 0.2},
        "events": events,
    }
    current = {"revision": 7, "status": "stable", "change_cause": "ordinary release"}

    assert not IncidentAgent._events_have_explicit_failure(events)
    assert not IncidentAgent._rollback_has_causal_evidence(observations, current)


def test_trace_failure_predicate_parses_false_and_active_values() -> None:
    healthy = {
        "trace": {
            "attributes": {
                "inventory_reservation_failed": False,
                "synthetic_timeout": "disabled",
            }
        }
    }
    failed = {
        "trace": {
            "attributes": {
                "inventory_reservation_failed": True,
                "synthetic_timeout": "active",
            }
        }
    }

    assert not IncidentAgent._trace_has_explicit_failure(healthy)
    assert IncidentAgent._trace_has_explicit_failure(failed)


@pytest.mark.parametrize(
    "span",
    [
        {
            "traceId": "0123456789abcdef",
            "spanId": "0123456789abcdef",
            "status": {"code": 2},
        },
        {
            "traceId": "0123456789abcdef",
            "spanId": "0123456789abcdef",
            "attributes": [
                {
                    "key": "inventory_reservation_failed",
                    "value": {"boolValue": True},
                }
            ],
        },
        {
            "traceId": "0123456789abcdef",
            "spanId": "0123456789abcdef",
            "attributes": [
                {
                    "key": "http.response.status_code",
                    "value": {"intValue": "503"},
                }
            ],
        },
    ],
)
def test_trace_failure_predicate_parses_otlp_spans(span: dict) -> None:
    payload = {
        "trace": {
            "resourceSpans": [
                {"scopeSpans": [{"spans": [span]}]}
            ]
        }
    }

    assert IncidentAgent._trace_has_valid_span(payload)
    assert IncidentAgent._trace_has_explicit_failure(payload)


def test_empty_or_unknown_trace_has_no_valid_span() -> None:
    assert not IncidentAgent._trace_has_valid_span({"trace": {}})
    assert not IncidentAgent._trace_has_valid_span(
        {"trace": {"batches": [{"scopeSpans": []}]}}
    )
    assert not IncidentAgent._trace_has_valid_span(
        {
            "trace": {
                "resourceSpans": [
                    {
                        "scopeSpans": [
                            {"spans": [{"traceId": "0123456789abcdef"}]}
                        ]
                    }
                ]
            }
        }
    )


@pytest.mark.asyncio
async def test_strict_verification_escalates_on_empty_tempo_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EmptyTraceBackend:
        async def call(self, name, arguments) -> ToolResult:
            if name == "get_service_metrics":
                content = {"availability": 1.0, "error_rate": 0.0}
            elif name == "list_pods":
                content = {"items": [{"name": "order-1", "ready": True}]}
            elif name == "get_trace":
                content = {"trace": {}}
            elif name == "query_prometheus":
                query = arguments["query"]
                if query.startswith("ALERTS{"):
                    content = {"result": []}
                elif query.startswith("sum(rate"):
                    content = {"result": [{"value": [0, "1"]}]}
                else:
                    content = {"result": [{"value": [0, "0"]}]}
            else:
                content = {}
            return ToolResult(tool_name=name, success=True, content=content)

    class ProbeResponse:
        status_code = 200

        @staticmethod
        def json() -> dict[str, str]:
            return {"trace_id": "0123456789abcdef"}

    class ProbeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def post(self, url: str) -> ProbeResponse:
            return ProbeResponse()

        async def aclose(self) -> None:
            pass

    async def no_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr(engine_module.httpx, "AsyncClient", ProbeClient)
    monkeypatch.setattr(engine_module.asyncio, "sleep", no_sleep)
    agent = IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(
            EmptyTraceBackend(),
            [*KUBERNETES_TOOL_SPECS, *OBSERVABILITY_TOOL_SPECS],
        ),
        verification_policy="strict",
        verification_probe_url="http://probe",
    )

    result = await agent._verify(  # type: ignore[arg-type]
        {
            "incident_id": "empty-trace",
            "alert": {
                "name": "HighErrorRate",
                "namespace": "sentinelops-demo",
                "service": "order-service",
                "labels": {},
            },
        }
    )

    assert result["status"] == IncidentStatus.ESCALATED.value
    assert result["timeline"][0]["type"] == "recovery.verification_incomplete"
    assert result["timeline"][0]["data"]["trace_structure_valid"] is False
    assert result["timeline"][0]["data"]["successful_trace_verified"] is False


@pytest.mark.parametrize(
    "line",
    [
        "No invalid configuration was detected",
        "invalid configuration was not detected",
        "service started without invalid configuration",
        "we never observed invalid configuration",
        "monitor did not report invalid configuration",
        "未发现 invalid configuration",
        "没有 inventory_reservation_failed",
        "无 synthetic_timeout",
    ],
)
def test_log_failure_predicate_rejects_negated_assertions(line: str) -> None:
    assert not IncidentAgent._logs_have_explicit_failure({"lines": [line]})


@pytest.mark.parametrize(
    "line",
    [
        "required environment variable DATABASE_URL is present",
        "invalid configuration count=0",
        "inventory_reservation_failed=false",
        "synthetic_timeout disabled",
        "FATAL: required environment variable DATABASE_URL is present",
        "required environment variable DATABASE_URL missing=false",
        "required environment variable DATABASE_URL is not missing",
        "ERROR: invalid configuration count=0",
        "invalid configuration=false",
        "exception: inventory_reservation_failed=false",
        "inventory_reservation_failed count=0",
        "ERROR: synthetic_timeout inactive",
        "synthetic_timeout count=0",
    ],
)
def test_log_failure_predicate_rejects_structured_false_values(line: str) -> None:
    assert not IncidentAgent._logs_have_explicit_failure({"lines": [line]})


@pytest.mark.parametrize(
    "line",
    [
        "FATAL: required environment variable DATABASE_URL is missing",
        "ERROR: timeout acquiring database connection from pool",
        "invalid configuration was detected",
        "invalid configuration count=2",
        "inventory_reservation_failed=true",
        "inventory_reservation_failed reason=synthetic_timeout",
        "synthetic_timeout active",
        "transient_runtime_fault_enabled restart_required=true",
    ],
)
def test_log_failure_predicate_preserves_asserted_failures(line: str) -> None:
    assert IncidentAgent._logs_have_explicit_failure({"lines": [line]})


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("No invalid configuration was detected", False),
        ("invalid configuration was not detected", False),
        ("service started without invalid configuration", False),
        ("we never observed invalid configuration", False),
        ("monitor did not report invalid configuration", False),
        ("未发现 invalid configuration", False),
        ("required environment variable DATABASE_URL is present", False),
        ("invalid configuration count=0", False),
        ("inventory_reservation_failed=false", False),
        ("synthetic_timeout disabled", False),
        ("FATAL: required environment variable DATABASE_URL is missing", True),
        ("ERROR: timeout acquiring database connection from pool", True),
        ("invalid configuration count=2", True),
        ("inventory_reservation_failed=true", True),
        ("inventory_reservation_failed reason=synthetic_timeout", True),
        ("synthetic_timeout active", True),
        ("transient_runtime_fault_enabled restart_required=true", True),
    ],
)
def test_rollback_causal_gate_requires_an_asserted_log_failure(
    line: str, expected: bool
) -> None:
    current = {
        "revision": 2,
        "replicas": 1,
        "ready_replicas": 1,
        "status": "stable",
        "change_cause": "bad-rollout",
    }
    observations = {
        "pods": {"items": []},
        "logs": {"lines": [line]},
        "metrics": {"error_rate": 0.0, "p95_ms": 100},
        "events": {"items": []},
    }

    assert IncidentAgent._rollback_has_causal_evidence(  # type: ignore[arg-type]
        observations, current
    ) is expected


def test_negation_does_not_suppress_a_later_positive_log_assertion() -> None:
    assert IncidentAgent._logs_have_explicit_failure(
        {
            "lines": [
                "No invalid configuration was detected. "
                "FATAL: required environment variable DATABASE_URL is missing"
            ]
        }
    )


def test_evidence_id_resolves_its_immutable_snapshot_after_follow_up() -> None:
    healthy_logs = {"lines": ["INFO: service healthy"]}
    failed_logs = {"lines": ["FATAL: application configuration is invalid"]}
    rollout = {
        "current_revision": 2,
        "revisions": [{"revision": 2, "replicas": 1, "status": "failed"}],
    }
    catalog = {
        "collect_context:1:tool:logs": {
            "evidence_id": "collect_context:1:tool:logs",
            "source": "kubernetes_logs",
            "tool": "get_pod_logs",
            "success": True,
        },
        "collect_follow_up:1:tool:kubernetes_logs": {
            "evidence_id": "collect_follow_up:1:tool:kubernetes_logs",
            "source": "kubernetes_logs",
            "tool": "get_pod_logs",
            "success": True,
        },
        "rollout": {
            "evidence_id": "rollout",
            "source": "kubernetes_rollout",
            "tool": "get_rollout_history",
            "success": True,
        },
    }
    state = {
        "evidence_snapshots": {
            "collect_context:1:tool:logs": healthy_logs,
            "collect_follow_up:1:tool:kubernetes_logs": failed_logs,
            "rollout": rollout,
        },
        "observations": {
            "logs": failed_logs,
            "rollout": rollout,
            "evidence_catalog": catalog,
        },
    }
    diagnosis = Diagnosis(
        root_cause="当前日志包含启动配置错误",
        confidence=0.95,
        hypotheses=[
            Hypothesis(
                statement="当前日志包含启动配置错误",
                confidence=0.95,
                evidence=[
                    Evidence(
                        evidence_id="collect_context:1:tool:logs",
                        source="kubernetes_logs",
                        query="get_pod_logs",
                        finding="初始日志包含 FATAL 配置错误",
                    ),
                    Evidence(
                        evidence_id="rollout",
                        source="kubernetes_rollout",
                        query="get_rollout_history",
                        finding="当前 revision 明确失败",
                    ),
                ],
            )
        ],
        evidence_summary=[],
    )

    issues = IncidentAgent._diagnosis_evidence_issues(  # type: ignore[arg-type]
        state, diagnosis
    )
    assert (
        "证据 collect_context:1:tool:logs 的 finding 没有对应原始观测支持"
        in issues
    )

    state["observations"]["logs"] = healthy_logs
    diagnosis.hypotheses[0].evidence[0] = Evidence(
        evidence_id="collect_follow_up:1:tool:kubernetes_logs",
        source="kubernetes_logs",
        query="get_pod_logs",
        finding="补查日志包含 FATAL 配置错误",
        raw=failed_logs,
    )

    assert IncidentAgent._diagnosis_evidence_issues(  # type: ignore[arg-type]
        state, diagnosis
    ) == []


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
        "evidence_snapshots": {
            "rollout": {
                "current_revision": 2,
                "revisions": [{"revision": 2, "replicas": 1, "status": "failed"}],
            },
            "events": {
                "items": [
                    {
                        "type": "Warning",
                        "reason": "BackOff",
                        "message": "Back-off restarting failed container",
                        "target_bound": True,
                    }
                ]
            },
        },
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
        "evidence_snapshots": {
            "rollout": {
                "current_revision": 2,
                "revisions": [{"revision": 2, "replicas": 1, "status": "failed"}],
            },
            "events": {
                "items": [
                    {
                        "type": "Warning",
                        "reason": "BackOff",
                        "message": "Back-off restarting failed container",
                        "target_bound": True,
                    }
                ]
            },
            "logs": {"lines": ["FATAL: application configuration is invalid"]},
            "failed": {"result": []},
        },
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
