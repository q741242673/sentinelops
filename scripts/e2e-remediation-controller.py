from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from kubernetes import client, config

from sentinelops.domain import RemediationAction, RiskLevel
from sentinelops.remediation_controller import (
    KubernetesRemediationGateway,
    canonical_digest,
)
from sentinelops.storage.base import StoredActionIntent
from sentinelops.tools.kubernetes import KubernetesBackend

NAMESPACE = "sentinelops-demo"
DEPLOYMENT = "order-service"


def executor_custom_objects_api() -> client.CustomObjectsApi:
    token = os.environ.get("SENTINELOPS_E2E_EXECUTOR_TOKEN", "")
    if not token:
        raise RuntimeError("E2E Executor ServiceAccount token is missing")
    config.load_kube_config()
    configuration = client.Configuration.get_default_copy()
    configuration.cert_file = None
    configuration.key_file = None
    configuration.username = None
    configuration.password = None
    configuration.api_key = {"authorization": token}
    configuration.api_key_prefix = {"authorization": "Bearer"}
    if urlsplit(configuration.host).hostname in {"127.0.0.1", "localhost", "::1"}:
        configuration.proxy = None
    return client.CustomObjectsApi(client.ApiClient(configuration))


async def main() -> None:
    backend = KubernetesBackend(NAMESPACE)
    rollout_result = await backend.call(
        "get_rollout_history",
        {"name": DEPLOYMENT},
    )
    if not rollout_result.success:
        raise RuntimeError(rollout_result.error or "rollout snapshot failed")
    rollout = rollout_result.content
    current_revision = int(rollout["current_revision"])
    current = next(
        item
        for item in rollout["revisions"]
        if int(item["revision"]) == current_revision
    )
    captured_at = datetime.now(UTC)
    precondition: dict[str, object] = {
        "action_fingerprint": "kind-controller-restart",
        "tool_name": "restart_deployment",
        "target": DEPLOYMENT,
        "namespace": NAMESPACE,
        "deployment_uid": str(rollout["deployment_uid"]),
        "generation": int(rollout["generation"]),
        "resource_version": str(rollout["resource_version"]),
        "desired_replicas": int(rollout["desired_replicas"]),
        "paused": bool(rollout["paused"]),
        "current_revision": current_revision,
        "current_replica_set_uid": str(current["uid"]),
        "current_template_hash": str(current["template_hash"]),
        "current_replicas": int(current["replicas"]),
        "current_ready_replicas": int(current["ready_replicas"]),
        "captured_at": captured_at.isoformat(),
        "expires_at": (captured_at + timedelta(minutes=5)).isoformat(),
    }
    action = RemediationAction(
        tool_name="restart_deployment",
        arguments={"name": DEPLOYMENT},
        rationale="exercise the real SentinelRemediation execution boundary",
        expected_outcome="Deployment receives one deterministic restart marker",
        risk=RiskLevel.MEDIUM,
    )
    action_id = canonical_digest(
        {
            "incident_id": "kind-controller-e2e",
            "action": action.model_dump(mode="json"),
            "precondition": precondition,
        }
    )
    intent = StoredActionIntent(
        idempotency_key=action_id,
        incident_id="kind-controller-e2e",
        lease_generation=1,
        approval_id=None,
        approval_version=None,
        action=action,
        precondition=precondition,
        status="dispatched",
        result=None,
        error=None,
        executor_id="kind-controller-e2e",
        executor_generation=1,
        executor_lease_until=captured_at + timedelta(minutes=5),
        attempt_id="kind-controller-attempt",
    )
    gateway = KubernetesRemediationGateway(
        NAMESPACE,
        custom_objects_api=executor_custom_objects_api(),
        poll_interval_seconds=0.2,
        result_timeout_seconds=30,
    )
    result = await gateway.execute(intent)
    if not result.success:
        raise RuntimeError(result.error or "Controller rejected the E2E action")
    deployment = backend.apps.read_namespaced_deployment(
        DEPLOYMENT,
        NAMESPACE,
        _request_timeout=5,
    )
    annotations = deployment.metadata.annotations or {}
    template_annotations = deployment.spec.template.metadata.annotations or {}
    if annotations.get("ops.sentinelops.io/action-id") != action_id:
        raise RuntimeError("Deployment action marker does not bind the Action Intent")
    if annotations.get("ops.sentinelops.io/action-plugin") != "restart_deployment":
        raise RuntimeError("Deployment action marker does not bind the plugin")
    if template_annotations.get("ops.sentinelops.io/action-id") != action_id:
        raise RuntimeError("restart template marker is missing")
    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
