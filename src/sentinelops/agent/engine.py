from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

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
    ) -> None:
        self.provider = provider
        self.tools = tools
        self.policy = ActionPolicy(auto_approve_max_risk)
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

    async def start(self, alert: Alert) -> IncidentRecord:
        record = IncidentRecord(alert=alert)
        self.records[record.id] = record
        state: IncidentState = {
            "incident_id": record.id,
            "alert": alert.model_dump(mode="json"),
            "status": IncidentStatus.RECEIVED.value,
            "execution_results": [],
            "timeline": [_event("incident.received", alert.summary)],
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
            "timeline": [_event("context.collected", "Collected Kubernetes diagnostic context")],
        }

    async def _diagnose(self, state: IncidentState) -> dict[str, Any]:
        prompt = json.dumps(
            {"alert": state["alert"], "observations": state["observations"]},
            ensure_ascii=False,
        )
        diagnosis = await self.provider.structured(
            system=(
                "You are an evidence-driven Kubernetes incident investigator. "
                "Do not claim a root cause without citing observations. Evaluate Kubernetes "
                "pods, logs, and rollout history together with every configured observability "
                "source. When rollout history contains a causal change, cite that rollout "
                "explicitly using a distinct evidence source."
            ),
            prompt=prompt,
            schema=Diagnosis,
            metadata={"incident_id": state["incident_id"], "node": "diagnose"},
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
            "You are a conservative Kubernetes remediation planner. Choose only allowlisted "
            "tools, prefer reversible actions, and provide explicit verification criteria. "
            "Treat each available tool's declared risk as the minimum risk classification. "
            "When rollout history shows that the active revision introduced the fault and "
            "an earlier healthy revision exists, roll back to that exact healthy revision; "
            "do not restart because a restart preserves the faulty image or configuration."
        )
        plan: RemediationPlan | None = None
        for attempt in range(2):
            plan = await self.provider.structured(
                system=system,
                prompt=json.dumps(payload, ensure_ascii=False),
                schema=RemediationPlan,
                metadata={"incident_id": state["incident_id"], "node": "plan"},
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
            return {"approved": True, "approval_request": None}
        request = ApprovalRequest(
            incident_id=state["incident_id"],
            action=action,
            reason=f"{action.risk.value} risk action requires explicit approval",
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
                    "Remediation approved" if approved else "Remediation rejected",
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
                    f"{action.tool_name}: {'success' if result.success else 'failed'}",
                )
            ],
        }

    async def _verify(self, state: IncidentState) -> dict[str, Any]:
        service = state["alert"]["service"]
        healthy = False
        metrics: ToolResult | None = None
        pods: ToolResult | None = None
        prometheus: ToolResult | None = None
        request_error_rate: float | None = None
        attempts = 0
        for attempt_index in range(1, 31):
            attempts = attempt_index
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
                            "}[10s])) or vector(0)) / clamp_min(sum(rate(http_requests_total{"
                            f"service={service_label}"
                            "}[10s])), 0.001)"
                        )
                    },
                )
                request_error_rate = self._prometheus_scalar(prometheus)
                indicators_healthy = (
                    prometheus.success
                    and request_error_rate is not None
                    and request_error_rate < 0.01
                )
            else:
                indicators_healthy = (error_rate is not None and error_rate < 0.01) or (
                    availability is not None and availability >= 1.0
                )
            healthy = metrics.success and pods.success and pods_healthy and indicators_healthy
            if healthy:
                break
            await asyncio.sleep(1)

        assert metrics is not None and pods is not None
        return {
            "status": IncidentStatus.RESOLVED.value if healthy else IncidentStatus.FAILED.value,
            "timeline": [
                _event(
                    "recovery.verified",
                    "Service recovered" if healthy else "Recovery criteria not met",
                    metrics=metrics.content,
                    pods=pods.content,
                    prometheus=prometheus.content if prometheus else None,
                    request_error_rate=request_error_rate,
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
        report = (
            f"# Incident {state['incident_id']}\n\n"
            f"- Status: {status}\n"
            f"- Root cause: {diagnosis.root_cause}\n"
            f"- Confidence: {diagnosis.confidence:.0%}\n"
            f"- Evidence: {'; '.join(diagnosis.evidence_summary)}\n"
            f"- Generated at: {datetime.now(UTC).isoformat()}\n"
        )
        return {
            "postmortem": report,
            "timeline": [_event("postmortem.generated", "Generated incident report")],
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
