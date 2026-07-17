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
from sentinelops.revision_health import (
    build_health_proof_annotations,
    revision_subject,
    runtime_image_fingerprint,
    verify_health_proof,
)
from sentinelops.tools.base import tool_call_fingerprint


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
        name = str(arguments.get("name") or "")
        if not name:
            raise RuntimeError("list_events requires a target workload name")
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
        owned_replica_sets = self._owned_replica_sets(deployment, replica_sets.items)
        replica_set_uids = {str(item.metadata.uid) for item in owned_replica_sets}
        pods = self.core.list_namespaced_pod(
            self.namespace,
            label_selector=f"app={name}",
            _request_timeout=self._api_timeout(),
        )
        owned_pod_uids = {
            str(pod.metadata.uid)
            for pod in pods.items
            if any(
                str(owner.uid) in replica_set_uids and owner.kind == "ReplicaSet"
                for owner in (pod.metadata.owner_references or [])
            )
        }
        allowed_uids = {
            str(deployment.metadata.uid),
            *replica_set_uids,
            *owned_pod_uids,
        }
        events = self.core.list_namespaced_event(
            self.namespace,
            _request_timeout=self._api_timeout(),
        )
        matching = [
            event
            for event in events.items
            if str(getattr(event.involved_object, "uid", "")) in allowed_uids
        ]
        return {
            "target_service": name,
            "items": [
                {
                    "type": event.type,
                    "reason": event.reason,
                    "message": event.message,
                    "object": event.involved_object.name,
                    "object_kind": event.involved_object.kind,
                    "object_uid": str(event.involved_object.uid),
                    "target_bound": True,
                }
                for event in matching[-50:]
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
        deployment_annotations = getattr(deployment.metadata, "annotations", None) or {}
        return {
            "deployment": name,
            "namespace": self.namespace,
            "deployment_uid": str(deployment.metadata.uid),
            "generation": deployment.metadata.generation,
            "resource_version": str(deployment.metadata.resource_version),
            "desired_replicas": deployment.spec.replicas or 0,
            "paused": bool(deployment.spec.paused),
            "current_revision": int(
                deployment_annotations.get("deployment.kubernetes.io/revision", "0")
            ),
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
                owner.uid == deployment_uid
                and owner.kind == "Deployment"
                and getattr(owner, "controller", False) is True
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
        labels = replica_set.metadata.labels or {}
        owners = replica_set.metadata.owner_references or []
        deployment_owner = next(
            (
                owner
                for owner in owners
                if owner.kind == "Deployment" and getattr(owner, "controller", False) is True
            ),
            None,
        )
        revision = annotations.get("deployment.kubernetes.io/revision", "0")
        proof = verify_health_proof(
            annotations,
            deployment_uid=str(getattr(deployment_owner, "uid", "")),
            replica_set_uid=str(replica_set.metadata.uid or ""),
            revision=revision,
            template_hash=labels.get("pod-template-hash", ""),
            containers=[(container.name, container.image) for container in containers],
            git_commit=template_annotations.get("sentinelops.io/git-commit", ""),
        )
        return {
            "name": replica_set.metadata.name,
            "uid": str(replica_set.metadata.uid),
            "template_hash": labels.get("pod-template-hash", ""),
            "revision": int(revision),
            "images": [container.image for container in containers],
            "change_cause": template_annotations.get("sentinelops.io/change-cause"),
            "health_status": proof["status"],
            "health_proof": proof,
            "git_commit": template_annotations.get("sentinelops.io/git-commit"),
            "repository": template_annotations.get("sentinelops.io/repository"),
            "source_path": template_annotations.get("sentinelops.io/source-path"),
            "replicas": replica_set.status.replicas or 0,
            "ready_replicas": replica_set.status.ready_replicas or 0,
        }

    def _attest_current_revision_healthy(
        self,
        name: str,
        *,
        verifier: str = "sentinelops-demo-controller",
    ) -> dict[str, Any]:
        """Write a health proof to the exact ready ReplicaSet, never its Pod template."""
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
        if not owned:
            raise RuntimeError(f"No owned ReplicaSet found for {name}")
        target = owned[-1]
        desired = target.spec.replicas or 0
        if desired <= 0 or (target.status.ready_replicas or 0) != desired:
            raise RuntimeError(f"Current ReplicaSet for {name} is not fully ready")

        labels = target.metadata.labels or {}
        template_hash = labels.get("pod-template-hash", "")
        if not template_hash:
            raise RuntimeError(f"Current ReplicaSet for {name} has no pod-template-hash")
        pods = self.core.list_namespaced_pod(
            self.namespace,
            label_selector=f"app={name},pod-template-hash={template_hash}",
            _request_timeout=self._api_timeout(),
        )
        ready_image_ids: dict[str, set[str]] = {}
        ready_pods = 0
        for pod in pods.items:
            if not any(
                owner.uid == target.metadata.uid
                and owner.kind == "ReplicaSet"
                and getattr(owner, "controller", False) is True
                for owner in (pod.metadata.owner_references or [])
            ):
                continue
            statuses = pod.status.container_statuses or []
            if not statuses or not all(status.ready and status.image_id for status in statuses):
                continue
            ready_pods += 1
            for status in statuses:
                ready_image_ids.setdefault(status.name, set()).add(status.image_id)
        if ready_pods < desired:
            raise RuntimeError(f"Ready Pods for {name} do not provide complete runtime image IDs")

        containers = target.spec.template.spec.containers or []
        expected_names = {container.name for container in containers}
        if set(ready_image_ids) != expected_names or any(
            len(image_ids) != 1 for image_ids in ready_image_ids.values()
        ):
            raise RuntimeError(f"Runtime images for {name} are incomplete or inconsistent")
        runtime_images = runtime_image_fingerprint(
            [
                (container_name, next(iter(image_ids)))
                for container_name, image_ids in ready_image_ids.items()
            ]
        )
        annotations = target.metadata.annotations or {}
        revision = annotations.get("deployment.kubernetes.io/revision", "0")
        template_annotations = target.spec.template.metadata.annotations or {}
        subject = revision_subject(
            deployment_uid=str(deployment.metadata.uid),
            replica_set_uid=str(target.metadata.uid),
            revision=revision,
            template_hash=template_hash,
            containers=[(container.name, container.image) for container in containers],
            runtime_images=runtime_images,
            git_commit=template_annotations.get("sentinelops.io/git-commit", ""),
        )
        proof_annotations = build_health_proof_annotations(
            subject,
            verified_at=datetime.now(UTC),
            verifier=verifier,
        )
        self.apps.patch_namespaced_replica_set(
            target.metadata.name,
            self.namespace,
            {"metadata": {"annotations": proof_annotations}},
            _request_timeout=self._api_timeout(),
        )
        return {
            "replica_set": target.metadata.name,
            "revision": int(revision),
            "health_proof": {"valid": True, "status": "healthy"},
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

    def _validated_write_context(
        self,
        name: str,
        arguments: dict[str, Any],
        expected_tool_name: str,
    ) -> tuple[Any, list[Any]]:
        precondition = arguments.get("_precondition")
        if not isinstance(precondition, dict):
            raise RuntimeError("Missing host-generated execution precondition")
        public_arguments = {
            key: value for key, value in arguments.items() if key != "_precondition"
        }
        if (
            precondition.get("guarded_tool_name") != expected_tool_name
            or precondition.get("public_arguments_fingerprint")
            != tool_call_fingerprint(expected_tool_name, public_arguments)
        ):
            raise RuntimeError(
                "Execution precondition failed: guarded tool or arguments changed"
            )
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
        summaries = [self._replica_set_summary(item) for item in owned]
        deployment_annotations = getattr(deployment.metadata, "annotations", None) or {}
        declared_revision = int(
            deployment_annotations.get("deployment.kubernetes.io/revision", "0")
        )
        current = next(
            (item for item in summaries if int(item["revision"]) == declared_revision),
            None,
        )
        if current is None:
            active = [
                item
                for item in summaries
                if (item.get("replicas") or 0) > 0
                or (item.get("ready_replicas") or 0) > 0
            ]
            current = (
                max(active, key=lambda item: int(item["revision"])) if active else None
            )
        if current is None:
            raise RuntimeError("Execution precondition failed: current revision is unknown")
        actual = {
            "namespace": self.namespace,
            "target": name,
            "deployment_uid": str(deployment.metadata.uid),
            "generation": int(deployment.metadata.generation),
            "resource_version": str(deployment.metadata.resource_version),
            "desired_replicas": int(deployment.spec.replicas or 0),
            "paused": bool(deployment.spec.paused),
            "current_revision": int(current["revision"]),
            "current_replica_set_uid": current["uid"],
            "current_template_hash": current["template_hash"],
            "current_replicas": int(current["replicas"]),
            "current_ready_replicas": int(current["ready_replicas"]),
        }
        changed = [
            key
            for key, value in actual.items()
            if precondition.get(key) != value
        ]
        if changed:
            raise RuntimeError(
                "Execution precondition failed: " + ", ".join(changed)
            )

        rollback_target = precondition.get("rollback_target")
        if expected_tool_name == "rollback_deployment" and not isinstance(
            rollback_target, dict
        ):
            raise RuntimeError(
                "Execution precondition failed: rollback health proof is missing"
            )
        if rollback_target is not None:
            if (
                expected_tool_name != "rollback_deployment"
                or int(rollback_target.get("revision", -1))
                != int(public_arguments.get("revision", -2))
            ):
                raise RuntimeError(
                    "Execution precondition failed: rollback target changed"
                )
            target = next(
                (
                    item
                    for item in summaries
                    if int(item["revision"]) == int(rollback_target["revision"])
                ),
                None,
            )
            expected_proof = rollback_target.get("health_proof")
            actual_proof = target.get("health_proof") if target else None
            proof_identity = (
                {
                    "subject": actual_proof.get("subject"),
                    "version": actual_proof.get("version"),
                    "verified_at": actual_proof.get("verified_at"),
                    "verifier": actual_proof.get("verifier"),
                }
                if isinstance(actual_proof, dict)
                else None
            )
            if (
                target is None
                or target["uid"] != rollback_target.get("replica_set_uid")
                or not isinstance(actual_proof, dict)
                or actual_proof.get("valid") is not True
                or actual_proof.get("status") != "healthy"
                or proof_identity != expected_proof
            ):
                raise RuntimeError(
                    "Execution precondition failed: rollback health proof changed"
                )
        return deployment, owned

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
                            "sentinelops.io/health-status": None,
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
        deployment, _ = self._validated_write_context(
            name, arguments, "restart_deployment"
        )
        body = {
            "metadata": {"resourceVersion": deployment.metadata.resource_version},
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
                            "sentinelops.io/health-status": None,
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
                proof = self._attest_current_revision_healthy(name)
                return {
                    "deployment": name,
                    "baseline_restored": True,
                    "revision": proof["revision"] if active else None,
                    "health_proof": proof["health_proof"],
                }
            time.sleep(0.5)
        raise RuntimeError(f"Timed out waiting for the healthy baseline rollout on {name}")

    def _tool_rollback_deployment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = arguments["name"]
        target_revision = int(arguments["revision"])
        deployment, owned = self._validated_write_context(
            name, arguments, "rollback_deployment"
        )
        if deployment.spec.paused:
            raise RuntimeError("Cannot rollback a paused deployment")
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
        annotations.pop("sentinelops.io/health-status", None)
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
        deployment, _ = self._validated_write_context(
            name, arguments, "scale_deployment"
        )
        self.apps.patch_namespaced_deployment_scale(
            name,
            self.namespace,
            {
                "metadata": {"resourceVersion": deployment.metadata.resource_version},
                "spec": {"replicas": replicas},
            },
        )
        return {"deployment": name, "replicas": replicas}
