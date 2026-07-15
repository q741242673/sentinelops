from __future__ import annotations

import asyncio
import copy
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
        return {"items": [self._pod_summary(pod) for pod in pods.items]}

    @staticmethod
    def _pod_summary(pod: Any) -> dict[str, Any]:
        statuses = pod.status.container_statuses or []
        waiting_reasons = [
            status.state.waiting.reason
            for status in statuses
            if status.state and status.state.waiting
        ]
        return {
            "name": pod.metadata.name,
            "phase": pod.status.phase,
            "ready": bool(statuses) and all(status.ready for status in statuses),
            "restarts": sum(status.restart_count for status in statuses),
            "waiting_reasons": waiting_reasons,
            "created_at": (
                pod.metadata.creation_timestamp.isoformat()
                if pod.metadata.creation_timestamp
                else None
            ),
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
            ranked = sorted(
                pods.items,
                key=lambda pod: (
                    self._pod_summary(pod)["ready"],
                    -self._pod_summary(pod)["restarts"],
                ),
            )
            name = ranked[0].metadata.name
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
        owned = self._owned_replica_sets(deployment, replica_sets.items)
        return {
            "deployment": name,
            "generation": deployment.metadata.generation,
            "observed_generation": deployment.status.observed_generation,
            "revisions": [self._replica_set_summary(rs) for rs in owned],
        }

    @staticmethod
    def _owned_replica_sets(deployment: Any, replica_sets: list[Any]) -> list[Any]:
        deployment_uid = deployment.metadata.uid
        owned = [
            replica_set
            for replica_set in replica_sets
            if any(
                owner.uid == deployment_uid and owner.kind == "Deployment"
                for owner in (replica_set.metadata.owner_references or [])
            )
        ]
        return sorted(
            owned,
            key=lambda replica_set: int(
                (replica_set.metadata.annotations or {}).get(
                    "deployment.kubernetes.io/revision", "0"
                )
            ),
        )

    @staticmethod
    def _replica_set_summary(replica_set: Any) -> dict[str, Any]:
        annotations = replica_set.metadata.annotations or {}
        containers = replica_set.spec.template.spec.containers or []
        return {
            "name": replica_set.metadata.name,
            "revision": int(annotations.get("deployment.kubernetes.io/revision", "0")),
            "images": [container.image for container in containers],
            "change_cause": (replica_set.spec.template.metadata.annotations or {}).get(
                "sentinelops.io/change-cause"
            ),
            "replicas": replica_set.status.replicas or 0,
            "ready_replicas": replica_set.status.ready_replicas or 0,
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
        name = arguments["name"]
        target_revision = int(arguments["revision"])
        deployment = self.apps.read_namespaced_deployment(name, self.namespace)
        if deployment.spec.paused:
            raise RuntimeError("Cannot rollback a paused deployment")

        replica_sets = self.apps.list_namespaced_replica_set(
            self.namespace,
            label_selector=f"app={name}",
        )
        owned = self._owned_replica_sets(deployment, replica_sets.items)
        target = next(
            (
                replica_set
                for replica_set in owned
                if int(
                    (replica_set.metadata.annotations or {}).get(
                        "deployment.kubernetes.io/revision", "0"
                    )
                )
                == target_revision
            ),
            None,
        )
        if target is None:
            available = [self._replica_set_summary(item)["revision"] for item in owned]
            raise RuntimeError(
                f"Revision {target_revision} was not found for {name}; available={available}"
            )

        deployment.spec.template = copy.deepcopy(target.spec.template)
        annotations = deployment.spec.template.metadata.annotations or {}
        annotations["sentinelops.io/rolledBackAt"] = datetime.now(UTC).isoformat()
        deployment.spec.template.metadata.annotations = annotations
        self.apps.replace_namespaced_deployment(
            name,
            self.namespace,
            deployment,
        )
        return {
            "deployment": name,
            "rolled_back": True,
            "source_revision": target_revision,
            "source_replica_set": target.metadata.name,
        }

    def _tool_scale_deployment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = arguments["name"]
        replicas = int(arguments["replicas"])
        self.apps.patch_namespaced_deployment_scale(
            name, self.namespace, {"spec": {"replicas": replicas}}
        )
        return {"deployment": name, "replicas": replicas}
