from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import httpx
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from sentinelops.agent.policy import ActionPolicy
from sentinelops.agent.state import IncidentState
from sentinelops.domain import (
    RISK_ORDER,
    Alert,
    ApprovalRequest,
    Diagnosis,
    IncidentRecord,
    IncidentStatus,
    RemediationAction,
    RemediationPlan,
    RiskLevel,
    TimelineEvent,
    ToolResult,
)
from sentinelops.llm.base import LLMProvider
from sentinelops.tools.registry import ToolRegistry


def _event(event_type: str, message: str, **data: Any) -> dict[str, Any]:
    return TimelineEvent(type=event_type, message=message, data=data).model_dump(mode="json")


class IncidentAgent:
    def __init__(
        self,
        *,
        provider: LLMProvider,
        tools: ToolRegistry,
        auto_approve_max_risk: RiskLevel = RiskLevel.LOW,
        verification_probe_url: str | None = None,
    ) -> None:
        self.provider = provider
        self.tools = tools
        self.policy = ActionPolicy(auto_approve_max_risk)
        self.verification_probe_url = (
            verification_probe_url.rstrip("/") if verification_probe_url else None
        )
        self.checkpointer = MemorySaver()
        self.graph = self._build_graph()
        self.records: dict[str, IncidentRecord] = {}

    def _build_graph(self):
        builder = StateGraph(IncidentState)
        builder.add_node("collect_context", self._collect_context)
        builder.add_node("diagnose", self._diagnose)
        builder.add_node("plan", self._plan)
        builder.add_node("prepare_approval", self._prepare_approval)
        builder.add_node("human_gate", self._human_gate)
        builder.add_node("execute", self._execute)
        builder.add_node("verify", self._verify)
        builder.add_node("postmortem", self._postmortem)

        builder.add_edge(START, "collect_context")
        builder.add_edge("collect_context", "diagnose")
        builder.add_edge("diagnose", "plan")
        builder.add_edge("plan", "prepare_approval")
        builder.add_conditional_edges(
            "prepare_approval",
            self._route_approval,
            {"human_gate": "human_gate", "execute": "execute"},
        )
        builder.add_conditional_edges(
            "human_gate",
            lambda state: "execute" if state.get("approved") else "end",
            {"execute": "execute", "end": END},
        )
        builder.add_edge("execute", "verify")
        builder.add_edge("verify", "postmortem")
        builder.add_edge("postmortem", END)
        return builder.compile(checkpointer=self.checkpointer)

    async def start(self, alert: Alert, *, incident_id: str | None = None) -> IncidentRecord:
        record = (
            IncidentRecord(id=incident_id, alert=alert)
            if incident_id
            else IncidentRecord(alert=alert)
        )
        self.records[record.id] = record
        timeline = [_event("incident.received", alert.summary)]
        if alert.labels.get("source") == "alertmanager":
            timeline.insert(
                0,
                _event(
                    "alertmanager.received",
                    "Alertmanager 自动推送了一个真实告警",
                    fingerprint=alert.labels.get("alertmanager_fingerprint"),
                ),
            )
        state: IncidentState = {
            "incident_id": record.id,
            "alert": alert.model_dump(mode="json"),
            "status": IncidentStatus.RECEIVED.value,
            "execution_results": [],
            "timeline": timeline,
        }
        result = await self.graph.ainvoke(state, self._config(record.id))
        return self._sync_record(record.id, result)

    async def resume(self, incident_id: str, *, approved: bool, note: str = "") -> IncidentRecord:
        if incident_id not in self.records:
            raise KeyError(incident_id)
        result = await self.graph.ainvoke(
            Command(resume={"approved": approved, "note": note}),
            self._config(incident_id),
        )
        return self._sync_record(incident_id, result)

    def get(self, incident_id: str) -> IncidentRecord:
        return self.records[incident_id]

    @staticmethod
    def _config(incident_id: str) -> dict[str, Any]:
        return {"configurable": {"thread_id": incident_id}}

    async def _collect_context(self, state: IncidentState) -> dict[str, Any]:
        service = state["alert"]["service"]
        calls = {
            "pods": ("list_pods", {"label_selector": f"app={service}"}),
            "events": ("list_events", {}),
            "logs": ("get_pod_logs", {"label_selector": f"app={service}", "tail_lines": 200}),
            "rollout": ("get_rollout_history", {"name": service}),
            "metrics": ("get_service_metrics", {"name": service}),
        }
        service_label = json.dumps(service)
        if self.tools.has_tool("query_prometheus"):
            calls["prometheus"] = (
                "query_prometheus",
                {
                    "query": (
                        "sum by (status) (rate(http_requests_total{"
                        f"service={service_label}"
                        "}[5m]))"
                    )
                },
            )
        if self.tools.has_tool("search_loki"):
            calls["loki"] = (
                "search_loki",
                {
                    "query": (
                        f"{{service_name={service_label}}} "
                        '|~ "(?i)(error|failed|fatal|timeout|exception)"'
                    ),
                    "limit": 100,
                },
            )
        trace_id = state["alert"].get("labels", {}).get("trace_id")
        if trace_id and self.tools.has_tool("get_trace"):
            calls["trace"] = ("get_trace", {"trace_id": trace_id})
        observations: dict[str, Any] = {}
        for key, (tool_name, arguments) in calls.items():
            result = await self.tools.call(tool_name, arguments)
            observations[key] = result.content if result.success else {"error": result.error}
        observations["scenario"] = observations.get("metrics", {}).get("scenario", "live_cluster")
        return {
            "status": IncidentStatus.INVESTIGATING.value,
            "observations": observations,
            "timeline": [_event("context.collected", "已采集 Kubernetes 与可观测性诊断上下文")],
        }

    async def _diagnose(self, state: IncidentState) -> dict[str, Any]:
        prompt = json.dumps(
            {"alert": state["alert"], "observations": state["observations"]},
            ensure_ascii=False,
        )
        diagnosis = await self.provider.structured(
            system=(
                "你是一名以证据为依据的 Kubernetes 事故调查专家。没有观测证据时不得断言根因。"
                "必须综合分析 Pod、事件、日志、发布历史以及已配置的全部可观测性数据源。"
                "如果发布历史包含因果变更，必须将该发布记录作为独立证据明确引用。"
                "root_cause、hypotheses.statement、evidence.finding、contradictions 和 "
                "evidence_summary 等所有面向用户的文字必须使用简体中文。技术标识符、"
                "查询语句、工具名和 Kubernetes 资源名保持原样。"
            ),
            prompt=prompt,
            schema=Diagnosis,
            metadata={"incident_id": state["incident_id"], "node": "diagnose"},
        )
        if self._diagnosis_needs_localization(diagnosis):
            diagnosis = await self.provider.structured(
                system=(
                    "你是技术内容本地化助手。必须把所有面向用户的文字字段翻译成简体中文，"
                    "不得修改事实、置信度、查询语句、技术标识符、Kubernetes 资源名或工具名。"
                    "只返回符合指定结构的数据。"
                ),
                prompt=json.dumps(
                    self._compact_diagnosis(diagnosis.model_dump(mode="json")),
                    ensure_ascii=False,
                ),
                schema=Diagnosis,
                metadata={
                    "incident_id": state["incident_id"],
                    "node": "diagnose_localization",
                },
            )
        return {
            "diagnosis": diagnosis.model_dump(mode="json"),
            "timeline": [
                _event(
                    "diagnosis.completed",
                    diagnosis.root_cause,
                    confidence=diagnosis.confidence,
                )
            ],
        }

    async def _plan(self, state: IncidentState) -> dict[str, Any]:
        specs = {spec.name: spec for spec in self.tools.list_specs()}
        planning_observations = {
            key: state["observations"][key]
            for key in ("pods", "events", "logs", "rollout", "metrics", "scenario")
            if key in state["observations"]
        }
        payload = {
            "alert": state["alert"],
            "observations": planning_observations,
            "diagnosis": self._compact_diagnosis(state["diagnosis"]),
            "available_tools": [
                spec.model_dump(mode="json")
                for spec in specs.values()
                if spec.risk != RiskLevel.READ_ONLY
            ],
        }
        system = (
            "你是一名保守的 Kubernetes 修复规划专家。只能选择白名单工具，优先选择可逆操作，"
            "并给出明确的验证标准。工具声明的风险等级是最低风险等级，不得降低。"
            "如果发布历史证明当前 revision 引入故障且存在更早的健康 revision，必须精确回滚到"
            "该健康 revision；不能用重启替代，因为重启会保留故障镜像或配置。"
            "如果 alert.labels.scenario 为 transient_runtime_fault，说明故障仅存在于进程内存且"
            "当前发布版本没有变化，应选择 restart_deployment 清除瞬态状态。"
            "summary、rationale、expected_outcome、rollback 和 verification 等所有面向用户的"
            "文字必须使用简体中文；技术标识符、命令、参数和工具名保持原样。"
        )
        plan: RemediationPlan | None = None
        for attempt in range(2):
            plan = await self.provider.structured(
                system=system,
                prompt=json.dumps(payload, ensure_ascii=False),
                schema=RemediationPlan,
                metadata={"incident_id": state["incident_id"], "node": "plan"},
            )
            if self._plan_needs_localization(plan):
                plan = await self.provider.structured(
                    system=(
                        "你是技术内容本地化助手。必须把修复方案中的 summary、rationale、"
                        "expected_outcome、rollback 和 verification 翻译成简体中文。"
                        "不得修改 tool_name、arguments、risk、事实或技术标识符。"
                        "只返回符合指定结构的数据。"
                    ),
                    prompt=json.dumps(plan.model_dump(mode="json"), ensure_ascii=False),
                    schema=RemediationPlan,
                    metadata={
                        "incident_id": state["incident_id"],
                        "node": "plan_localization",
                    },
                )
            feedback = self._plan_feedback(state, plan, specs)
            if feedback is None:
                break
            if attempt == 1:
                raise PermissionError(f"Model plan remained unsafe after replanning: {feedback}")
            payload["rejected_plan"] = plan.model_dump(mode="json")
            payload["planning_feedback"] = feedback

        assert plan is not None
        for action in plan.actions:
            self.policy.validate(action)
            if action.tool_name not in specs:
                raise PermissionError(f"Model selected a non-allowlisted tool: {action.tool_name}")
            minimum_risk = specs[action.tool_name].risk
            if RISK_ORDER[action.risk] < RISK_ORDER[minimum_risk]:
                raise PermissionError(
                    f"Model under-classified {action.tool_name}: "
                    f"declared={action.risk.value}, minimum={minimum_risk.value}"
                )
        return {
            "plan": plan.model_dump(mode="json"),
            "timeline": [_event("remediation.planned", plan.summary)],
        }

    @staticmethod
    def _compact_diagnosis(diagnosis: dict[str, Any]) -> dict[str, Any]:
        return {
            "root_cause": diagnosis.get("root_cause"),
            "confidence": diagnosis.get("confidence"),
            "evidence_summary": diagnosis.get("evidence_summary", []),
            "hypotheses": [
                {
                    "statement": hypothesis.get("statement"),
                    "confidence": hypothesis.get("confidence"),
                    "contradictions": hypothesis.get("contradictions", []),
                    "evidence": [
                        {key: value for key, value in evidence.items() if key != "raw"}
                        for evidence in hypothesis.get("evidence", [])
                    ],
                }
                for hypothesis in diagnosis.get("hypotheses", [])
            ],
        }

    @staticmethod
    def _contains_chinese(value: str) -> bool:
        return any("\u4e00" <= character <= "\u9fff" for character in value)

    @classmethod
    def _diagnosis_needs_localization(cls, diagnosis: Diagnosis) -> bool:
        values = [diagnosis.root_cause, *diagnosis.evidence_summary]
        for hypothesis in diagnosis.hypotheses:
            values.extend([hypothesis.statement, *hypothesis.contradictions])
            values.extend(evidence.finding for evidence in hypothesis.evidence)
        return any(value and not cls._contains_chinese(value) for value in values)

    @classmethod
    def _plan_needs_localization(cls, plan: RemediationPlan) -> bool:
        values = [plan.summary, plan.rollback, *plan.verification]
        for action in plan.actions:
            values.extend([action.rationale, action.expected_outcome])
        return any(value and not cls._contains_chinese(value) for value in values)

    @staticmethod
    def _plan_feedback(
        state: IncidentState,
        plan: RemediationPlan,
        specs: dict[str, Any] | None = None,
    ) -> str | None:
        if not plan.actions:
            return "A remediation plan must contain at least one allowlisted action"
        action = plan.actions[0]
        spec = (specs or {}).get(action.tool_name)
        if spec is not None and spec.risk == RiskLevel.READ_ONLY:
            return (
                f"{action.tool_name} is read-only and cannot remediate the incident; select one "
                "of the provided mutating remediation tools"
            )
        scenario = state.get("alert", {}).get("labels", {}).get("scenario")
        if scenario == "transient_runtime_fault":
            if action.tool_name != "restart_deployment":
                return (
                    "transient_runtime_fault is an in-memory process fault with no rollout "
                    "change; replan with restart_deployment"
                )
            if action.arguments.get("name") != state["alert"]["service"]:
                return (
                    "restart_deployment must target the alerted service "
                    f"{state['alert']['service']}"
                )
            return None

        revisions = state.get("observations", {}).get("rollout", {}).get("revisions", [])
        active = [
            revision
            for revision in revisions
            if (revision.get("replicas") or 0) > 0 or (revision.get("ready_replicas") or 0) > 0
        ]
        if not active:
            return None
        current = max(active, key=lambda revision: int(revision.get("revision", 0)))
        current_revision = int(current.get("revision", 0))
        previous = [
            revision
            for revision in revisions
            if int(revision.get("revision", 0)) < current_revision
        ]
        if not previous:
            return None
        target = max(previous, key=lambda revision: int(revision.get("revision", 0)))
        target_revision = int(target.get("revision", 0))

        if action.tool_name == "rollback_deployment":
            requested = action.arguments.get("revision")
            try:
                requested_revision = int(requested)
            except (TypeError, ValueError):
                requested_revision = 0
            available = {int(revision.get("revision", 0)) for revision in revisions}
            if requested_revision not in available or requested_revision != target_revision:
                return (
                    f"rollback revision {requested!r} is not the exact prior known revision; "
                    f"replan rollback_deployment with revision {target_revision} based on the "
                    "provided rollout history"
                )
            return None

        change_cause = str(current.get("change_cause") or "").lower()
        fault_markers = {"failure", "fault", "error", "broken", "timeout"}
        if action.tool_name == "restart_deployment" and any(
            marker in change_cause for marker in fault_markers
        ):
            return (
                f"restart_deployment preserves suspect revision {current_revision} "
                f"({current.get('change_cause')}); replan with rollback_deployment to the known "
                f"prior revision {target_revision}"
            )
        return None

    async def _prepare_approval(self, state: IncidentState) -> dict[str, Any]:
        action = RemediationAction.model_validate(state["plan"]["actions"][0])
        if not self.policy.requires_approval(action):
            risk_label = {
                RiskLevel.READ_ONLY: "只读",
                RiskLevel.LOW: "低",
                RiskLevel.MEDIUM: "中",
                RiskLevel.HIGH: "高",
                RiskLevel.CRITICAL: "严重",
            }[action.risk]
            return {
                "approved": True,
                "approval_request": None,
                "timeline": [
                    _event(
                        "approval.auto_approved",
                        f"策略已自动批准{risk_label}风险操作",
                    )
                ],
            }
        request = ApprovalRequest(
            incident_id=state["incident_id"],
            action=action,
            reason=f"{action.risk.value} 风险操作需要人工明确批准",
        )
        return {
            "status": IncidentStatus.AWAITING_APPROVAL.value,
            "approval_request": request.model_dump(mode="json"),
            "timeline": [_event("approval.requested", request.reason)],
        }

    def _route_approval(self, state: IncidentState) -> str:
        return "human_gate" if state.get("approval_request") else "execute"

    async def _human_gate(self, state: IncidentState) -> dict[str, Any]:
        decision = interrupt(state["approval_request"])
        approved = bool(decision.get("approved"))
        return {
            "approved": approved,
            "status": (
                IncidentStatus.REMEDIATING.value if approved else IncidentStatus.REJECTED.value
            ),
            "timeline": [
                _event(
                    "approval.decided",
                    "修复操作已批准" if approved else "修复操作已拒绝",
                    note=decision.get("note", ""),
                )
            ],
        }

    async def _execute(self, state: IncidentState) -> dict[str, Any]:
        action = RemediationAction.model_validate(state["plan"]["actions"][0])
        self.policy.validate(action)
        result = await self.tools.call(action.tool_name, action.arguments)
        return {
            "status": (
                IncidentStatus.REMEDIATING.value if result.success else IncidentStatus.FAILED.value
            ),
            "execution_results": [result.model_dump(mode="json")],
            "timeline": [
                _event(
                    "action.executed",
                    f"{action.tool_name}：{'执行成功' if result.success else '执行失败'}",
                )
            ],
        }

    async def _verify(self, state: IncidentState) -> dict[str, Any]:
        service = state["alert"]["service"]
        healthy = False
        metrics: ToolResult | None = None
        pods: ToolResult | None = None
        prometheus: ToolResult | None = None
        traffic: ToolResult | None = None
        alert_state: ToolResult | None = None
        trace_result: ToolResult | None = None
        request_error_rate: float | None = None
        request_rate: float | None = None
        alert_firing: bool | None = None
        successful_probes = 0
        probe_statuses: list[int | str] = []
        successful_trace_id: str | None = None
        healthy_windows = 0
        attempts = 0
        probe_client = (
            httpx.AsyncClient(timeout=3, trust_env=False) if self.verification_probe_url else None
        )
        try:
            for attempt_index in range(1, 31):
                attempts = attempt_index
                if probe_client:
                    try:
                        response = await probe_client.post(
                            f"{self.verification_probe_url}/checkout"
                        )
                        probe_statuses.append(response.status_code)
                        if response.status_code == 200:
                            successful_probes += 1
                            if successful_probes == 5:
                                successful_trace_id = (
                                    str(response.json().get("trace_id") or "") or None
                                )
                        else:
                            successful_probes = 0
                            successful_trace_id = None
                    except (httpx.HTTPError, ValueError):
                        probe_statuses.append("network_error")
                        successful_probes = 0
                        successful_trace_id = None

                metrics = await self.tools.call("get_service_metrics", {"name": service})
                pods = await self.tools.call("list_pods", {"label_selector": f"app={service}"})
                pod_items = pods.content.get("items", [])
                pods_healthy = bool(pod_items) and all(item.get("ready") for item in pod_items)
                error_rate = metrics.content.get("error_rate")
                availability = metrics.content.get("availability")
                if self.tools.has_tool("query_prometheus"):
                    service_label = json.dumps(service)
                    prometheus = await self.tools.call(
                        "query_prometheus",
                        {
                            "query": (
                                "(sum(rate(http_requests_total{"
                                f'service={service_label},status=~"5.."'
                                "}[10s])) or vector(0)) / clamp_min(sum(rate("
                                "http_requests_total{"
                                f"service={service_label}"
                                "}[10s])), 0.001)"
                            )
                        },
                    )
                    traffic = await self.tools.call(
                        "query_prometheus",
                        {
                            "query": (
                                "sum(rate(http_requests_total{"
                                f"service={service_label}"
                                "}[10s]))"
                            )
                        },
                    )
                    alert_name = json.dumps(state["alert"]["name"])
                    alert_state = await self.tools.call(
                        "query_prometheus",
                        {
                            "query": (
                                f"ALERTS{{alertname={alert_name},alertstate=\"firing\","
                                f"service={service_label}}}"
                            )
                        },
                    )
                    request_error_rate = self._prometheus_scalar(prometheus)
                    request_rate = self._prometheus_scalar(traffic)
                    alert_firing = bool(alert_state.content.get("result", []))
                    indicators_healthy = (
                        prometheus.success
                        and traffic.success
                        and alert_state.success
                        and request_error_rate is not None
                        and request_error_rate < 0.01
                        and request_rate is not None
                        and request_rate >= 0.1
                        and not alert_firing
                    )
                else:
                    indicators_healthy = (error_rate is not None and error_rate < 0.01) or (
                        availability is not None and availability >= 1.0
                    )

                probes_healthy = probe_client is None or successful_probes >= 5
                trace_healthy = True
                if (
                    successful_trace_id
                    and successful_probes >= 5
                    and self.tools.has_tool("get_trace")
                ):
                    trace_result = await self.tools.call(
                        "get_trace", {"trace_id": successful_trace_id}
                    )
                    trace_healthy = trace_result.success
                window_healthy = (
                    metrics.success
                    and pods.success
                    and pods_healthy
                    and indicators_healthy
                    and probes_healthy
                    and trace_healthy
                )
                healthy_windows = healthy_windows + 1 if window_healthy else 0
                required_windows = 3 if self.tools.has_tool("query_prometheus") else 1
                healthy = healthy_windows >= required_windows
                if healthy:
                    break
                await asyncio.sleep(1)
        finally:
            if probe_client:
                await probe_client.aclose()

        assert metrics is not None and pods is not None
        return {
            "status": IncidentStatus.RESOLVED.value if healthy else IncidentStatus.FAILED.value,
            "timeline": [
                _event(
                    "recovery.verified",
                    "服务已恢复" if healthy else "恢复标准未满足",
                    metrics=metrics.content,
                    pods=pods.content,
                    prometheus=prometheus.content if prometheus else None,
                    request_error_rate=request_error_rate,
                    request_rate=request_rate,
                    alert_firing=alert_firing,
                    active_probe_statuses=probe_statuses,
                    successful_trace_id=successful_trace_id,
                    successful_trace_verified=trace_result.success if trace_result else None,
                    healthy_windows=healthy_windows,
                    attempts=attempts,
                )
            ],
        }

    @staticmethod
    def _prometheus_scalar(result: ToolResult) -> float | None:
        if not result.success:
            return None
        series = result.content.get("result", [])
        if not series:
            return None
        value = series[0].get("value", [])
        if len(value) != 2:
            return None
        try:
            scalar = float(value[1])
        except (TypeError, ValueError):
            return None
        return scalar if scalar == scalar else None

    async def _postmortem(self, state: IncidentState) -> dict[str, Any]:
        diagnosis = Diagnosis.model_validate(state["diagnosis"])
        status = state["status"]
        status_label = {
            IncidentStatus.RECEIVED.value: "已接收",
            IncidentStatus.INVESTIGATING.value: "调查中",
            IncidentStatus.AWAITING_APPROVAL.value: "等待审批",
            IncidentStatus.REMEDIATING.value: "修复中",
            IncidentStatus.RESOLVED.value: "已恢复",
            IncidentStatus.FAILED.value: "修复失败",
            IncidentStatus.REJECTED.value: "已拒绝",
        }.get(status, status)
        report = (
            f"# 事故报告 {state['incident_id']}\n\n"
            f"- 状态：{status_label}\n"
            f"- 根本原因：{diagnosis.root_cause}\n"
            f"- 置信度：{diagnosis.confidence:.0%}\n"
            f"- 证据：{'；'.join(diagnosis.evidence_summary)}\n"
            f"- 生成时间：{datetime.now(UTC).isoformat()}\n"
        )
        return {
            "postmortem": report,
            "timeline": [_event("postmortem.generated", "事故报告已生成")],
        }

    def _sync_record(self, incident_id: str, state: dict[str, Any]) -> IncidentRecord:
        record = self.records[incident_id]
        record.status = IncidentStatus(state.get("status", record.status))
        if state.get("diagnosis"):
            record.diagnosis = Diagnosis.model_validate(state["diagnosis"])
        if state.get("plan"):
            record.plan = RemediationPlan.model_validate(state["plan"])
        if state.get("approval_request"):
            record.approval = ApprovalRequest.model_validate(state["approval_request"])
        record.execution_results = [
            ToolResult.model_validate(item) for item in state.get("execution_results", [])
        ]
        record.timeline = [TimelineEvent.model_validate(item) for item in state.get("timeline", [])]
        record.postmortem = state.get("postmortem")
        record.updated_at = datetime.now(UTC)
        return record
