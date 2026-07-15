from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException

from sentinelops.domain import ToolResult


class KubernetesBackend:
    """Kubernetes API backend using kubeconfig locally and ServiceAccount in-cluster."""

    def __init__(self, namespace: str) -> None:
        self.namespace = namespace
        try:
            config.load_incluster_config()
        except ConfigException:
            config.load_kube_config()
        self.core = client.CoreV1Api()
        self.apps = client.AppsV1Api()

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        started = time.perf_counter()
        handler: Callable[[dict[str, Any]], dict[str, Any]] | None = getattr(
            self, f"_tool_{name}", None
        )
        if handler is None:
            return ToolResult(tool_name=name, success=False, error=f"Unknown tool: {name}")
        try:
            content = await asyncio.to_thread(handler, arguments)
            return ToolResult(
                tool_name=name,
                success=True,
                content=content,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=name,
                success=False,
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )

    def _tool_list_pods(self, arguments: dict[str, Any]) -> dict[str, Any]:
        label_selector = arguments.get("label_selector", "")
        pods = self.core.list_namespaced_pod(self.namespace, label_selector=label_selector)
        return {
            "items": [
                {
                    "name": pod.metadata.name,
                    "phase": pod.status.phase,
                    "ready": all(c.ready for c in (pod.status.container_statuses or [])),
                    "restarts": sum(c.restart_count for c in (pod.status.container_statuses or [])),
                }
                for pod in pods.items
            ]
        }

    def _tool_list_events(self, arguments: dict[str, Any]) -> dict[str, Any]:
        events = self.core.list_namespaced_event(self.namespace)
        return {
            "items": [
                {
                    "type": event.type,
                    "reason": event.reason,
                    "message": event.message,
                    "object": event.involved_object.name,
                }
                for event in events.items[-50:]
            ]
        }

    def _tool_get_pod_logs(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = arguments.get("pod_name")
        if not name:
            pods = self.core.list_namespaced_pod(
                self.namespace, label_selector=arguments.get("label_selector", "app=order-service")
            )
            if not pods.items:
                raise RuntimeError("No matching pod found")
            name = pods.items[0].metadata.name
        logs = self.core.read_namespaced_pod_log(
            name=name,
            namespace=self.namespace,
            tail_lines=int(arguments.get("tail_lines", 200)),
        )
        return {"pod": name, "lines": logs.splitlines()}

    def _tool_get_rollout_history(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = arguments.get("name", "order-service")
        deployment = self.apps.read_namespaced_deployment(name, self.namespace)
        replica_sets = self.apps.list_namespaced_replica_set(
            self.namespace, label_selector=f"app={name}"
        )
        return {
            "deployment": name,
            "generation": deployment.metadata.generation,
            "observed_generation": deployment.status.observed_generation,
            "replica_sets": [rs.metadata.name for rs in replica_sets.items],
        }

    def _tool_get_service_metrics(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = arguments.get("name", "order-service")
        deployment = self.apps.read_namespaced_deployment_status(name, self.namespace)
        desired = deployment.spec.replicas or 0
        available = deployment.status.available_replicas or 0
        return {
            "source": "kubernetes_deployment_status",
            "desired_replicas": desired,
            "available_replicas": available,
            "availability": available / desired if desired else 0,
            "note": "Connect Prometheus MCP for request-level SLI metrics",
        }

    def _tool_restart_deployment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = arguments["name"]
        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {"sentinelops.io/restartedAt": datetime.now(UTC).isoformat()}
                    }
                }
            }
        }
        self.apps.patch_namespaced_deployment(name, self.namespace, body)
        return {"deployment": name, "restarted": True}

    def _tool_rollback_deployment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError(
            "Rollback requires an external deployment controller adapter; "
            "use Argo Rollouts/GitOps MCP in production"
        )

    def _tool_scale_deployment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = arguments["name"]
        replicas = int(arguments["replicas"])
        self.apps.patch_namespaced_deployment_scale(
            name, self.namespace, {"spec": {"replicas": replicas}}
        )
        return {"deployment": name, "replicas": replicas}
