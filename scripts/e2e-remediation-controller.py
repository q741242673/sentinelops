from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from kubernetes import client, config

from sentinelops.domain import (
    Alert,
    IncidentRecord,
    IncidentStatus,
    RemediationAction,
    RiskLevel,
)
from sentinelops.executor import ExecutorWorker
from sentinelops.remediation_controller import (
    KubernetesRemediationGateway,
    build_sentinel_remediation,
    canonical_digest,
)
from sentinelops.storage import SqlIncidentStore
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


class ReadOnlyRecoveryApi:
    def __init__(self, delegate: client.CustomObjectsApi) -> None:
        self.delegate = delegate

    def get_namespaced_custom_object(self, *args, **kwargs):
        return self.delegate.get_namespaced_custom_object(*args, **kwargs)

    def create_namespaced_custom_object(self, *args, **kwargs):
        del args, kwargs
        raise RuntimeError(
            "replacement Executor attempted to recreate a remediation contract"
        )


async def wait_for_rollout(
    backend: KubernetesBackend,
    *,
    timeout_seconds: float = 60,
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while True:
        deployment = await asyncio.to_thread(
            backend.apps.read_namespaced_deployment_status,
            DEPLOYMENT,
            NAMESPACE,
            _request_timeout=5,
        )
        desired = deployment.spec.replicas or 0
        if (
            (deployment.status.observed_generation or 0)
            >= deployment.metadata.generation
            and (deployment.status.updated_replicas or 0) == desired
            and (deployment.status.replicas or 0) == desired
            and (deployment.status.ready_replicas or 0) == desired
            and (deployment.status.available_replicas or 0) == desired
        ):
            return
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError("order-service rollout did not become ready")
        await asyncio.sleep(0.5)


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

    await wait_for_rollout(backend)
    recovery_rollout_result = await backend.call(
        "get_rollout_history",
        {"name": DEPLOYMENT},
    )
    if not recovery_rollout_result.success:
        raise RuntimeError(
            recovery_rollout_result.error or "recovery snapshot failed"
        )
    recovery_rollout = recovery_rollout_result.content
    recovery_revision = int(recovery_rollout["current_revision"])
    recovery_current = next(
        item
        for item in recovery_rollout["revisions"]
        if int(item["revision"]) == recovery_revision
    )
    recovery_captured_at = datetime.now(UTC)
    recovery_precondition: dict[str, object] = {
        "action_fingerprint": "kind-controller-crash-recovery",
        "tool_name": "restart_deployment",
        "target": DEPLOYMENT,
        "namespace": NAMESPACE,
        "deployment_uid": str(recovery_rollout["deployment_uid"]),
        "generation": int(recovery_rollout["generation"]),
        "resource_version": str(recovery_rollout["resource_version"]),
        "desired_replicas": int(recovery_rollout["desired_replicas"]),
        "paused": bool(recovery_rollout["paused"]),
        "current_revision": recovery_revision,
        "current_replica_set_uid": str(recovery_current["uid"]),
        "current_template_hash": str(recovery_current["template_hash"]),
        "current_replicas": int(recovery_current["replicas"]),
        "current_ready_replicas": int(recovery_current["ready_replicas"]),
        "captured_at": recovery_captured_at.isoformat(),
        "expires_at": (
            recovery_captured_at + timedelta(minutes=5)
        ).isoformat(),
    }
    recovery_action_id = canonical_digest(
        {
            "incident_id": "kind-controller-crash-recovery",
            "action": action.model_dump(mode="json"),
            "precondition": recovery_precondition,
        }
    )
    with tempfile.TemporaryDirectory(prefix="sentinelops-controller-e2e-") as tmp:
        store = SqlIncidentStore(
            f"sqlite+aiosqlite:///{Path(tmp) / 'sentinelops.db'}"
        )
        await store.setup()
        recovery_incident = IncidentRecord(
            id="kind-controller-crash-recovery",
            alert=Alert(
                name="ExecutorCrashRecovery",
                namespace=NAMESPACE,
                service=DEPLOYMENT,
                severity="critical",
                summary="prove Controller outcome reconciliation",
            ),
            status=IncidentStatus.REMEDIATING,
        )
        await store.save(
            recovery_incident,
            expected_version=None,
            graph_state=None,
        )
        lease = await store.acquire_lease(
            recovery_incident.id,
            owner_id="kind-agent-worker",
            ttl_seconds=60,
        )
        await store.prepare_action(
            lease,
            idempotency_key=recovery_action_id,
            action=action,
            precondition=recovery_precondition,
        )
        await store.enqueue_action(
            lease,
            idempotency_key=recovery_action_id,
        )
        original_claim = await store.claim_action_execution(
            owner_id="kind-executor-before-crash",
            attempt_id="kind-controller-crash-attempt",
            ttl_seconds=0.2,
        )
        if original_claim is None:
            raise RuntimeError("failed to claim crash-recovery Action Intent")
        dispatched = await store.mark_action_dispatched(original_claim)
        executor_api = executor_custom_objects_api()
        body = build_sentinel_remediation(dispatched)
        await asyncio.to_thread(
            executor_api.create_namespaced_custom_object,
            "ops.sentinelops.io",
            "v1alpha1",
            NAMESPACE,
            "sentinelremediations",
            body,
            _request_timeout=5,
        )

        # The original Executor is now treated as SIGKILLed: it never records
        # the Controller result. A replacement may only observe the existing CR.
        await asyncio.sleep(1.2)
        replacement = ExecutorWorker(
            store,
            None,
            owner_id="kind-executor-replacement",
            remediation_gateway=KubernetesRemediationGateway(
                NAMESPACE,
                custom_objects_api=ReadOnlyRecoveryApi(executor_api),
                poll_interval_seconds=0.2,
                result_timeout_seconds=30,
            ),
            claim_ttl_seconds=10,
            poll_interval_seconds=0.2,
        )
        deadline = asyncio.get_running_loop().time() + 30
        while True:
            await replacement.run_once()
            recovered = await store.latest_action_intent(
                recovery_incident.id
            )
            if recovered is not None and recovered.status in {
                "succeeded",
                "failed",
            }:
                break
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError(
                    "replacement Executor did not reconcile Controller outcome"
                )
            await asyncio.sleep(1.2)
        if recovered is None or recovered.status != "succeeded":
            raise RuntimeError(
                "replacement Executor did not persist the trusted success"
            )
        if recovered.result is None:
            raise RuntimeError("reconciled Action Intent is missing ToolResult")
        if (
            recovered.result.content.get("sentinel_remediation")
            != recovery_action_id
        ):
            raise RuntimeError("reconciled result is not bound to Action Intent")
        reconciliation_events = [
            event
            for event in await store.list_audit_events(recovery_incident.id)
            if event.source_component == "executor-reconciler"
        ]
        if len(reconciliation_events) != 1:
            raise RuntimeError(
                "Controller outcome reconciliation audit is not exactly once"
            )
        await store.close()

    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
    print(
        json.dumps(
            {
                "crash_recovery_action_id": recovery_action_id,
                "database_status": "succeeded",
                "replayed_contract": False,
                "reconciliation_audit_events": 1,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
