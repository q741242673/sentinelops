from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from sentinelops.agent import IncidentAgent
from sentinelops.agent.runbook import IncidentRunbook
from sentinelops.agent.state import IncidentState
from sentinelops.config import Settings
from sentinelops.domain import Diagnosis, IncidentRecord, RemediationPlan, RiskLevel
from sentinelops.llm.rule_based import RuleBasedProvider
from sentinelops.tools.registry import ToolRegistry
from sentinelops.tools.simulator import SimulatedKubernetesBackend

LabMode = Literal["automatic_remediation", "bounded_reflection"]


def build_simulated_lab_agent(
    settings: Settings,
    *,
    scenario: str,
    runbook: IncidentRunbook | None = None,
    auto_approve_max_risk: RiskLevel | None = None,
    progress_callback: Callable[[IncidentRecord], None] | None = None,
) -> IncidentAgent:
    """Build the deterministic offline Lab without changing production runtime wiring."""
    return IncidentAgent(
        provider=RuleBasedProvider(),
        tools=ToolRegistry(SimulatedKubernetesBackend(scenario=scenario)),
        auto_approve_max_risk=(
            auto_approve_max_risk or RiskLevel(settings.auto_approve_max_risk)
        ),
        diagnosis_confidence_threshold=settings.diagnosis_confidence_threshold,
        max_reflection_rounds=settings.max_reflection_rounds,
        runbook=runbook,
        profile_id=f"lab.simulated.{scenario}.v1",
        progress_callback=progress_callback,
    )


class VerifiedRuntimeStateRunbook(IncidentRunbook):
    id = "lab.verified-runtime-state.v1"

    def __init__(self, *, confidence_threshold: float) -> None:
        self.confidence_threshold = confidence_threshold

    def reflection_decision(
        self,
        state: IncidentState,
        diagnosis: Diagnosis,
    ) -> bool | None:
        if diagnosis.confidence < self.confidence_threshold:
            return None
        observations = state.get("observations", {})
        logs = json.dumps(observations.get("logs", {}), ensure_ascii=False).lower()
        live_marker = (
            "transient_runtime_fault_enabled" in logs and "restart_required=true" in logs
        )
        simulated_marker = (
            observations.get("metrics", {}).get("scenario") == "transient_runtime_fault"
        )
        return False if live_marker or simulated_marker else None

    def planning_guidance(self, state: IncidentState) -> str:
        service = state["alert"]["service"]
        return (
            "当采集日志已经证明故障仅存在于进程内存、明确需要重启清除，且发布证据未显示"
            f"代码或配置回归时，只允许对受影响工作负载 {service} 提议 restart_deployment。"
        )

    def plan_feedback(
        self,
        state: IncidentState,
        plan: RemediationPlan,
        specs: dict[str, Any],
    ) -> str | None:
        if not plan.actions:
            return "The trusted runbook requires one remediation action"
        action = plan.actions[0]
        if action.tool_name != "restart_deployment":
            return "The trusted runtime-state runbook permits only restart_deployment"
        if action.arguments.get("name") != state["alert"]["service"]:
            return "restart_deployment must target the alerted service"
        return None


class BoundedReflectionRunbook(IncidentRunbook):
    id = "lab.bounded-reflection.v1"

    def reflection_decision(
        self,
        state: IncidentState,
        diagnosis: Diagnosis,
    ) -> bool | None:
        return True if state.get("reflection_rounds", 0) == 0 else None


@dataclass(frozen=True)
class LabIncidentProfile:
    id: str
    mode: LabMode
    expected_alert: str
    expected_service: str
    runbook: IncidentRunbook
    auto_approve_max_risk: RiskLevel
    enrich_failed_trace: bool = True


class LabProfileCoordinator:
    """Binds an explicitly started lab run to its next matching alert.

    The binding lives on the trusted server side. Incoming Alertmanager labels cannot create,
    select, or raise the privileges of an execution profile.
    """

    def __init__(self) -> None:
        self._armed: dict[LabMode, str] = {}

    def arm(self, mode: LabMode, run_id: str) -> None:
        self._armed[mode] = run_id

    def disarm(self, mode: LabMode) -> None:
        self._armed.pop(mode, None)

    def clear(self) -> None:
        self._armed.clear()

    def consume(
        self,
        *,
        alert_name: str,
        service: str,
        confidence_threshold: float,
    ) -> LabIncidentProfile | None:
        if (
            "automatic_remediation" in self._armed
            and alert_name == "InventoryTransientRuntimeFault"
            and service == "inventory-service"
        ):
            run_id = self._armed.pop("automatic_remediation")
            return LabIncidentProfile(
                id=f"lab.auto-remediation.v1:{run_id}",
                mode="automatic_remediation",
                expected_alert=alert_name,
                expected_service=service,
                runbook=VerifiedRuntimeStateRunbook(
                    confidence_threshold=confidence_threshold
                ),
                auto_approve_max_risk=RiskLevel.MEDIUM,
            )
        if (
            "bounded_reflection" in self._armed
            and alert_name == "HighInventoryErrorRate"
            and service == "inventory-service"
        ):
            run_id = self._armed.pop("bounded_reflection")
            return LabIncidentProfile(
                id=f"lab.bounded-reflection.v1:{run_id}",
                mode="bounded_reflection",
                expected_alert=alert_name,
                expected_service=service,
                runbook=BoundedReflectionRunbook(),
                auto_approve_max_risk=RiskLevel.LOW,
            )
        return None
