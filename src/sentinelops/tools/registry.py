from __future__ import annotations

import re
from typing import Any

from sentinelops.config import Settings
from sentinelops.domain import RiskLevel, ToolResult
from sentinelops.tools.base import (
    CompositeBackend,
    ToolBackend,
    ToolSpec,
    tool_call_fingerprint,
)
from sentinelops.tools.change import GitChangeBackend
from sentinelops.tools.kubernetes import KubernetesBackend
from sentinelops.tools.observability import ObservabilityBackend
from sentinelops.tools.simulator import SimulatedKubernetesBackend

KUBERNETES_NAME_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 253,
    "pattern": (
        r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$"
    ),
}

KUBERNETES_TOOL_SPECS = [
    ToolSpec(
        name="list_pods",
        description="List pod health and restart counts",
        risk=RiskLevel.READ_ONLY,
    ),
    ToolSpec(
        name="list_events",
        description="List recent Kubernetes events bound to a target workload",
        risk=RiskLevel.READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"name": KUBERNETES_NAME_SCHEMA},
            "required": ["name"],
            "additionalProperties": False,
        },
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
        input_schema={
            "type": "object",
            "properties": {"name": KUBERNETES_NAME_SCHEMA},
            "required": ["name"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="rollback_deployment",
        description="Rollback a deployment to a known revision",
        risk=RiskLevel.HIGH,
        input_schema={
            "type": "object",
            "properties": {
                "name": KUBERNETES_NAME_SCHEMA,
                "revision": {"type": "integer", "minimum": 1},
            },
            "required": ["name", "revision"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="scale_deployment",
        description="Change desired deployment replicas",
        risk=RiskLevel.HIGH,
        input_schema={
            "type": "object",
            "properties": {
                "name": KUBERNETES_NAME_SCHEMA,
                "replicas": {"type": "integer", "minimum": 0, "maximum": 100},
            },
            "required": ["name", "replicas"],
            "additionalProperties": False,
        },
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
    def __init__(
        self,
        backend: ToolBackend,
        specs: list[ToolSpec] | None = None,
        *,
        allow_guarded_writes: bool = True,
    ) -> None:
        self.backend = backend
        self.specs = {spec.name: spec for spec in (specs or KUBERNETES_TOOL_SPECS)}
        self.allow_guarded_writes = allow_guarded_writes

    def list_specs(self) -> list[ToolSpec]:
        return list(self.specs.values())

    def has_tool(self, name: str) -> bool:
        return name in self.specs

    def validation_error(self, name: str, arguments: dict[str, Any]) -> str | None:
        spec = self.specs.get(name)
        if spec is None:
            return "Tool is not allowlisted"
        return self._validate_arguments(arguments, spec.input_schema)

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        validation_error = self.validation_error(name, arguments)
        if validation_error:
            return ToolResult(
                tool_name=name,
                success=False,
                error=validation_error,
            )
        if self.specs[name].risk != RiskLevel.READ_ONLY:
            return ToolResult(
                tool_name=name,
                success=False,
                error=(
                    "Write tools require a host-generated execution precondition; "
                    "run remediation through IncidentAgent"
                ),
            )
        return await self.backend.call(name, arguments)

    async def call_guarded(
        self,
        name: str,
        arguments: dict[str, Any],
        precondition: dict[str, Any],
    ) -> ToolResult:
        """Attach a host-generated write guard after validating only public arguments."""
        if not self.allow_guarded_writes:
            return ToolResult(
                tool_name=name,
                success=False,
                error="This process does not hold the cluster-write capability",
            )
        validation_error = self.validation_error(name, arguments)
        if validation_error:
            return ToolResult(tool_name=name, success=False, error=validation_error)
        execution_guard = {
            **precondition,
            "guarded_tool_name": name,
            "public_arguments_fingerprint": tool_call_fingerprint(name, arguments),
        }
        guarded_arguments = {**arguments, "_precondition": execution_guard}
        return await self.backend.call(name, guarded_arguments)

    @staticmethod
    def _validate_arguments(arguments: dict[str, Any], schema: dict[str, Any]) -> str | None:
        missing = [key for key in schema.get("required", []) if key not in arguments]
        if missing:
            return f"Missing required arguments: {', '.join(missing)}"

        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unexpected = sorted(set(arguments) - set(properties))
            if unexpected:
                return f"Unexpected arguments: {', '.join(unexpected)}"

        for key, value in arguments.items():
            property_schema = properties.get(key)
            if not property_schema:
                continue
            expected_type = property_schema.get("type")
            if expected_type == "string" and type(value) is not str:
                return f"Argument {key} must be a string"
            if expected_type == "integer" and type(value) is not int:
                return f"Argument {key} must be an integer"
            if expected_type == "string":
                minimum_length = property_schema.get("minLength")
                maximum_length = property_schema.get("maxLength")
                if minimum_length is not None and len(value) < minimum_length:
                    return f"Argument {key} is shorter than {minimum_length} characters"
                if maximum_length is not None and len(value) > maximum_length:
                    return f"Argument {key} exceeds {maximum_length} characters"
                pattern = property_schema.get("pattern")
                if pattern and re.fullmatch(pattern, value) is None:
                    return f"Argument {key} does not match the required pattern"
            if expected_type == "integer":
                minimum = property_schema.get("minimum")
                maximum = property_schema.get("maximum")
                if minimum is not None and value < minimum:
                    return f"Argument {key} must be at least {minimum}"
                if maximum is not None and value > maximum:
                    return f"Argument {key} must be at most {maximum}"
        return None


def build_tool_registry(
    settings: Settings,
    *,
    allow_guarded_writes: bool = True,
) -> ToolRegistry:
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
    return ToolRegistry(
        CompositeBackend(routes),
        specs,
        allow_guarded_writes=allow_guarded_writes,
    )
