from __future__ import annotations

import time
from typing import Any

from sentinelops.domain import ToolResult


class SimulatedKubernetesBackend:
    """Repeatable fault lab used by local development and CI."""

    def __init__(self, scenario: str = "bad_rollout") -> None:
        self.scenario = scenario
        self.resolved = False
        self.current_revision = 2 if scenario == "bad_rollout" else 1

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        started = time.perf_counter()
        handler = getattr(self, f"_tool_{name}", None)
        if handler is None:
            return ToolResult(tool_name=name, success=False, error=f"Unknown tool: {name}")
        try:
            content = handler(arguments)
            return ToolResult(
                tool_name=name,
                success=True,
                content=content,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # pragma: no cover - defensive tool boundary
            return ToolResult(
                tool_name=name,
                success=False,
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )

    def _tool_list_pods(self, arguments: dict[str, Any]) -> dict[str, Any]:
        healthy = self.resolved or self.scenario != "bad_rollout"
        return {
            "scenario": self.scenario,
            "items": [
                {
                    "name": "order-service-7b9d8",
                    "phase": "Running" if healthy else "CrashLoopBackOff",
                    "ready": healthy,
                    "restarts": 0 if healthy else 7,
                    "revision": self.current_revision,
                }
            ],
        }

    def _tool_list_events(self, arguments: dict[str, Any]) -> dict[str, Any]:
        message = (
            "Back-off restarting failed container after deployment revision 2"
            if self.scenario == "bad_rollout" and not self.resolved
            else "No warning events"
        )
        return {"scenario": self.scenario, "items": [{"type": "Warning", "message": message}]}

    def _tool_get_pod_logs(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.scenario == "bad_rollout" and not self.resolved:
            lines = ["FATAL: required environment variable DATABASE_URL is missing"]
        elif self.scenario == "db_pool_exhaustion" and not self.resolved:
            lines = ["ERROR: timeout acquiring database connection from pool"] * 3
        else:
            lines = ["INFO: service healthy"]
        return {"scenario": self.scenario, "lines": lines}

    def _tool_get_rollout_history(self, arguments: dict[str, Any]) -> dict[str, Any]:
        deployment_name = arguments.get("name", "order-service")
        if self.scenario != "bad_rollout":
            revisions = [
                {
                    "uid": "sim-rs-1",
                    "template_hash": "sim-template-1",
                    "revision": 1,
                    "image": "order-service:1.0.0",
                    "replicas": 1,
                    "ready_replicas": 1,
                    "status": "stable",
                    "health_status": "healthy",
                    "health_proof": {
                        "valid": True,
                        "status": "healthy",
                        "subject": "sha256:simulated-revision-1",
                    },
                }
            ]
        else:
            revisions = [
                {
                    "uid": "sim-rs-1",
                    "template_hash": "sim-template-1",
                    "revision": 1,
                    "image": "order-service:1.0.0",
                    "replicas": 0,
                    "ready_replicas": 0,
                    "status": "stable",
                    "health_status": "healthy",
                    "health_proof": {
                        "valid": True,
                        "status": "healthy",
                        "subject": "sha256:simulated-revision-1",
                    },
                },
                {
                    "uid": "sim-rs-2",
                    "template_hash": "sim-template-2",
                    "revision": 2,
                    "image": "order-service:1.1.0",
                    "replicas": 1,
                    "ready_replicas": 0,
                    "status": "failed",
                    "health_status": "unknown",
                    "health_proof": {"valid": False, "status": "unknown"},
                },
            ]
        return {
            "scenario": self.scenario,
            "namespace": "sentinelops-demo",
            "deployment_uid": f"sim-deployment-{deployment_name}",
            "generation": self.current_revision,
            "observed_generation": self.current_revision,
            "resource_version": f"sim-rv-{self.current_revision}",
            "desired_replicas": 1,
            "paused": False,
            "current_revision": self.current_revision,
            "revisions": revisions,
        }

    def _tool_get_service_metrics(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.resolved:
            error_rate, p95_ms, pool = 0.002, 180, 0.42
        elif self.scenario == "db_pool_exhaustion":
            error_rate, p95_ms, pool = 0.18, 4800, 1.0
        else:
            error_rate, p95_ms, pool = 0.31, 2100, 0.35
        return {
            "scenario": self.scenario,
            "error_rate": error_rate,
            "p95_ms": p95_ms,
            "db_pool_utilization": pool,
        }

    def _tool_restart_deployment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self.resolved = True
        return {"deployment": arguments["name"], "restarted": True}

    def _tool_rollback_deployment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self.current_revision = int(arguments.get("revision", 1))
        self.resolved = True
        return {
            "deployment": arguments["name"],
            "rolled_back": True,
            "revision": self.current_revision,
        }

    def _tool_scale_deployment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"deployment": arguments["name"], "replicas": arguments["replicas"]}
