from __future__ import annotations

from typing import Any

from sentinelops.config import Settings
from sentinelops.domain import RiskLevel, ToolResult
from sentinelops.tools.base import ToolBackend, ToolSpec
from sentinelops.tools.kubernetes import KubernetesBackend
from sentinelops.tools.simulator import SimulatedKubernetesBackend

TOOL_SPECS = [
    ToolSpec(
        name="list_pods",
        description="List pod health and restart counts",
        risk=RiskLevel.READ_ONLY,
    ),
    ToolSpec(
        name="list_events",
        description="List recent Kubernetes events",
        risk=RiskLevel.READ_ONLY,
    ),
    ToolSpec(
        name="get_pod_logs",
        description="Read bounded pod log tail",
        risk=RiskLevel.READ_ONLY,
    ),
    ToolSpec(
        name="get_rollout_history",
        description="Inspect deployment and replica set history",
        risk=RiskLevel.READ_ONLY,
    ),
    ToolSpec(
        name="get_service_metrics",
        description="Read service or workload health metrics",
        risk=RiskLevel.READ_ONLY,
    ),
    ToolSpec(
        name="restart_deployment",
        description="Trigger a rolling restart of a deployment",
        risk=RiskLevel.MEDIUM,
        input_schema={"required": ["name"]},
    ),
    ToolSpec(
        name="rollback_deployment",
        description="Rollback a deployment to a known revision",
        risk=RiskLevel.HIGH,
        input_schema={"required": ["name", "revision"]},
    ),
    ToolSpec(
        name="scale_deployment",
        description="Change desired deployment replicas",
        risk=RiskLevel.HIGH,
        input_schema={"required": ["name", "replicas"]},
    ),
]


class ToolRegistry:
    def __init__(self, backend: ToolBackend) -> None:
        self.backend = backend
        self.specs = {spec.name: spec for spec in TOOL_SPECS}

    def list_specs(self) -> list[ToolSpec]:
        return list(self.specs.values())

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        spec = self.specs.get(name)
        if spec is None:
            return ToolResult(tool_name=name, success=False, error="Tool is not allowlisted")
        missing = [key for key in spec.input_schema.get("required", []) if key not in arguments]
        if missing:
            return ToolResult(
                tool_name=name,
                success=False,
                error=f"Missing required arguments: {', '.join(missing)}",
            )
        return await self.backend.call(name, arguments)


def build_tool_registry(settings: Settings, *, scenario: str = "bad_rollout") -> ToolRegistry:
    if settings.tool_backend == "simulator":
        return ToolRegistry(SimulatedKubernetesBackend(scenario=scenario))
    return ToolRegistry(KubernetesBackend(namespace=settings.kubernetes_namespace))
