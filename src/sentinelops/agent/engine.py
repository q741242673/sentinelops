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
                    "query": (f'{{app={service_label}}} |~ "(?i)(error|fatal|timeout|exception)"'),
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
                "Do not claim a root cause without citing observations."
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
        prompt = json.dumps(
            {
                "alert": state["alert"],
                "observations": state["observations"],
                "diagnosis": state["diagnosis"],
                "available_tools": [
                    spec.model_dump(mode="json") for spec in self.tools.list_specs()
                ],
            },
            ensure_ascii=False,
        )
        plan = await self.provider.structured(
            system=(
                "You are a conservative Kubernetes remediation planner. Choose only allowlisted "
                "tools, prefer reversible actions, and provide explicit verification criteria."
            ),
            prompt=prompt,
            schema=RemediationPlan,
            metadata={"incident_id": state["incident_id"], "node": "plan"},
        )
        for action in plan.actions:
            self.policy.validate(action)
            if action.tool_name not in {spec.name for spec in self.tools.list_specs()}:
                raise PermissionError(f"Model selected a non-allowlisted tool: {action.tool_name}")
        return {
            "plan": plan.model_dump(mode="json"),
            "timeline": [_event("remediation.planned", plan.summary)],
        }

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
        attempts = 0
        for attempt_index in range(1, 31):
            attempts = attempt_index
            metrics = await self.tools.call("get_service_metrics", {"name": service})
            pods = await self.tools.call("list_pods", {"label_selector": f"app={service}"})
            pod_items = pods.content.get("items", [])
            pods_healthy = bool(pod_items) and all(item.get("ready") for item in pod_items)
            error_rate = metrics.content.get("error_rate")
            availability = metrics.content.get("availability")
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
                    attempts=attempts,
                )
            ],
        }

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
