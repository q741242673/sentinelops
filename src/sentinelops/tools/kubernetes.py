from __future__ import annotations

import asyncio
import copy
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

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
        configuration = client.Configuration.get_default_copy()
        hostname = urlsplit(configuration.host).hostname
        if hostname in {"127.0.0.1", "localhost", "::1"}:
            # The Kubernetes client automatically inherits HTTP(S)_PROXY. A kind
            # API server is always local and must not be sent through that proxy.
            configuration.proxy = None
        api_client = client.ApiClient(configuration)
        self.core = client.CoreV1Api(api_client)
        self.apps = client.AppsV1Api(api_client)

    def _api_timeout(self) -> float:
        """Bound individual API calls so a stalled local cluster cannot hang the console."""
        return 5.0

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
            tail_lines=min(max(int(arguments.get("tail_lines", 200)), 1), 500),
        )
        return {"pod": name, "lines": logs.splitlines()}

    def _tool_get_rollout_history(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = arguments.get("name", "order-service")
        deployment = self.apps.read_namespaced_deployment(
            name,
            self.namespace,
            _request_timeout=self._api_timeout(),
        )
        replica_sets = self.apps.list_namespaced_replica_set(
            self.namespace,
            label_selector=f"app={name}",
            _request_timeout=self._api_timeout(),
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
        template_annotations = replica_set.spec.template.metadata.annotations or {}
        containers = replica_set.spec.template.spec.containers or []
        health_status = template_annotations.get("sentinelops.io/health-status")
        if health_status not in {"healthy", "unhealthy"}:
            health_status = "unknown"
        return {
            "name": replica_set.metadata.name,
            "revision": int(annotations.get("deployment.kubernetes.io/revision", "0")),
            "images": [container.image for container in containers],
            "change_cause": template_annotations.get("sentinelops.io/change-cause"),
            "health_status": health_status,
            "git_commit": template_annotations.get("sentinelops.io/git-commit"),
            "repository": template_annotations.get("sentinelops.io/repository"),
            "source_path": template_annotations.get("sentinelops.io/source-path"),
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

    def _tool_inject_demo_fault(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Inject the portfolio demo fault without exposing it as an Agent tool."""
        name = arguments.get("name", "inventory-service")
        timeout_seconds = float(arguments.get("timeout_seconds", 45))
        deployment = self.apps.read_namespaced_deployment(
            name,
            self.namespace,
            _request_timeout=self._api_timeout(),
        )
        containers = deployment.spec.template.spec.containers or []
        container = next((item for item in containers if item.name == name), containers[0])
        env = {item.name: item.value for item in (container.env or [])}
        if env.get("FAIL_EVERY") not in {None, "0"}:
            history = self._tool_get_rollout_history({"name": name})
            active = [item for item in history["revisions"] if item["replicas"] > 0]
            return {
                "deployment": name,
                "fault_active": True,
                "already_active": True,
                "revision": active[-1]["revision"] if active else None,
                "failure_every": env.get("FAIL_EVERY"),
            }

        injected_at = datetime.now(UTC).isoformat()
        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "sentinelops.io/change-cause": (
                                "enable-every-third-inventory-failure"
                            ),
                            "sentinelops.io/health-status": "unhealthy",
                            "sentinelops.io/fault-injected-at": injected_at,
                        }
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": name,
                                "env": [{"name": "FAIL_EVERY", "value": "3"}],
                            }
                        ]
                    },
                }
            }
        }
        updated = self.apps.patch_namespaced_deployment(
            name,
            self.namespace,
            body,
            _request_timeout=self._api_timeout(),
        )
        target_generation = updated.metadata.generation
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            current = self.apps.read_namespaced_deployment_status(
                name,
                self.namespace,
                _request_timeout=self._api_timeout(),
            )
            desired = current.spec.replicas or 0
            if (
                (current.status.observed_generation or 0) >= target_generation
                and (current.status.updated_replicas or 0) == desired
                and (current.status.replicas or 0) == desired
                and (current.status.ready_replicas or 0) == desired
                and (current.status.available_replicas or 0) == desired
            ):
                history = self._tool_get_rollout_history({"name": name})
                active = [item for item in history["revisions"] if item["replicas"] > 0]
                return {
                    "deployment": name,
                    "fault_active": True,
                    "already_active": False,
                    "revision": active[-1]["revision"] if active else None,
                    "failure_every": "3",
                }
            time.sleep(0.5)
        raise RuntimeError(f"Timed out waiting for the injected fault rollout on {name}")

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

    def _tool_reset_demo_baseline(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Set a known healthy demo configuration; never exposed through the Agent registry."""
        name = arguments.get("name", "inventory-service")
        timeout_seconds = float(arguments.get("timeout_seconds", 45))
        restored_at = datetime.now(UTC).isoformat()
        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "sentinelops.io/change-cause": "healthy-baseline",
                            "sentinelops.io/health-status": "healthy",
                            "sentinelops.io/baseline-restored-at": restored_at,
                        }
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": name,
                                "env": [{"name": "FAIL_EVERY", "value": "0"}],
                            }
                        ]
                    },
                }
            }
        }
        updated = self.apps.patch_namespaced_deployment(
            name,
            self.namespace,
            body,
            _request_timeout=self._api_timeout(),
        )
        target_generation = updated.metadata.generation
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            current = self.apps.read_namespaced_deployment_status(
                name,
                self.namespace,
                _request_timeout=self._api_timeout(),
            )
            desired = current.spec.replicas or 0
            if (
                (current.status.observed_generation or 0) >= target_generation
                and (current.status.updated_replicas or 0) == desired
                and (current.status.replicas or 0) == desired
                and (current.status.ready_replicas or 0) == desired
                and (current.status.available_replicas or 0) == desired
            ):
                history = self._tool_get_rollout_history({"name": name})
                active = [item for item in history["revisions"] if item["replicas"] > 0]
                return {
                    "deployment": name,
                    "baseline_restored": True,
                    "revision": active[-1]["revision"] if active else None,
                }
            time.sleep(0.5)
        raise RuntimeError(f"Timed out waiting for the healthy baseline rollout on {name}")

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
