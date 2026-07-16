from __future__ import annotations

from typing import Any

from sentinelops.config import Settings
from sentinelops.domain import RiskLevel, ToolResult
from sentinelops.tools.base import CompositeBackend, ToolBackend, ToolSpec
from sentinelops.tools.change import GitChangeBackend
from sentinelops.tools.kubernetes import KubernetesBackend
from sentinelops.tools.observability import ObservabilityBackend
from sentinelops.tools.simulator import SimulatedKubernetesBackend

KUBERNETES_TOOL_SPECS = [
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

OBSERVABILITY_TOOL_SPECS = [
    ToolSpec(
        name="query_prometheus",
        description="Run a bounded instant PromQL query",
        risk=RiskLevel.READ_ONLY,
        input_schema={"required": ["query"]},
    ),
    ToolSpec(
        name="search_loki",
        description="Search a bounded range of Loki log streams",
        risk=RiskLevel.READ_ONLY,
        input_schema={"required": ["query"]},
    ),
    ToolSpec(
        name="get_trace",
        description="Fetch a Tempo trace by trace ID",
        risk=RiskLevel.READ_ONLY,
        input_schema={"required": ["trace_id"]},
    ),
]

CHANGE_TOOL_SPECS = [
    ToolSpec(
        name="get_change_evidence",
        description="Correlate Kubernetes rollout revisions with verified Git commits",
        risk=RiskLevel.READ_ONLY,
        input_schema={"required": ["service"]},
    )
]


class ToolRegistry:
    def __init__(self, backend: ToolBackend, specs: list[ToolSpec] | None = None) -> None:
        self.backend = backend
        self.specs = {spec.name: spec for spec in (specs or KUBERNETES_TOOL_SPECS)}

    def list_specs(self) -> list[ToolSpec]:
        return list(self.specs.values())

    def has_tool(self, name: str) -> bool:
        return name in self.specs

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


def build_tool_registry(settings: Settings) -> ToolRegistry:
    if settings.tool_backend == "simulator":
        kubernetes: ToolBackend = SimulatedKubernetesBackend()
    else:
        kubernetes = KubernetesBackend(namespace=settings.kubernetes_namespace)
    specs = list(KUBERNETES_TOOL_SPECS)
    routes: dict[str, ToolBackend] = {spec.name: kubernetes for spec in KUBERNETES_TOOL_SPECS}
    if settings.tool_backend == "kubernetes" and (
        settings.prometheus_url or settings.loki_url or settings.tempo_url
    ):
        observability = ObservabilityBackend(
            prometheus_url=settings.prometheus_url,
            loki_url=settings.loki_url,
            tempo_url=settings.tempo_url,
            timeout_seconds=settings.observability_timeout_seconds,
        )
        configured = {
            "query_prometheus": bool(settings.prometheus_url),
            "search_loki": bool(settings.loki_url),
            "get_trace": bool(settings.tempo_url),
        }
        for spec in OBSERVABILITY_TOOL_SPECS:
            if configured[spec.name]:
                specs.append(spec)
                routes[spec.name] = observability
    if settings.change_repository_path:
        changes = GitChangeBackend(
            settings.change_repository_path,
            kubernetes,
            history_hours=settings.change_history_hours,
            history_limit=settings.change_history_limit,
        )
        specs.extend(CHANGE_TOOL_SPECS)
        routes["get_change_evidence"] = changes
    return ToolRegistry(CompositeBackend(routes), specs)
