from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sentinelops.revision_health import (
    build_health_proof_annotations,
    revision_subject,
    runtime_image_fingerprint,
)
from sentinelops.tools.base import tool_call_fingerprint
from sentinelops.tools.kubernetes import KubernetesBackend


def ns(**values):
    return SimpleNamespace(**values)


def replica_set(
    revision: int,
    *,
    owner_uid: str = "deployment-uid",
    healthy_proof: bool = False,
    template_health_status: str | None = None,
    controller: bool = True,
):
    template_annotations = {"sentinelops.io/version": f"1.{revision}.0"}
    if template_health_status is not None:
        template_annotations["sentinelops.io/health-status"] = template_health_status
    template = ns(
        metadata=ns(annotations=template_annotations),
        spec=ns(containers=[ns(name="order-service", image=f"order:{revision}")]),
    )
    annotations = {"deployment.kubernetes.io/revision": str(revision)}
    if healthy_proof:
        subject = revision_subject(
            deployment_uid=owner_uid,
            replica_set_uid=f"replica-set-uid-{revision}",
            revision=str(revision),
            template_hash=f"hash-{revision}",
            containers=[("order-service", f"order:{revision}")],
            runtime_images=runtime_image_fingerprint(
                [("order-service", f"docker-pullable://order@sha256:{revision}")]
            ),
        )
        annotations.update(
            build_health_proof_annotations(
                subject,
                verified_at=datetime.now(UTC),
                verifier="test-release-pipeline",
            )
        )
    return ns(
        metadata=ns(
            name=f"order-service-{revision}",
            uid=f"replica-set-uid-{revision}",
            annotations=annotations,
            labels={"pod-template-hash": f"hash-{revision}"},
            owner_references=[
                ns(uid=owner_uid, kind="Deployment", controller=controller)
            ],
        ),
        spec=ns(template=template, replicas=1),
        status=ns(replicas=1, ready_replicas=1),
    )


def rollback_precondition(
    target,
    *,
    tool_name: str = "rollback_deployment",
    arguments: dict | None = None,
) -> dict:
    target_summary = KubernetesBackend._replica_set_summary(target)
    public_arguments = arguments or {"name": "order-service", "revision": 1}
    return {
        "guarded_tool_name": tool_name,
        "public_arguments_fingerprint": tool_call_fingerprint(
            tool_name, public_arguments
        ),
        "namespace": "sentinelops-demo",
        "target": "order-service",
        "deployment_uid": "deployment-uid",
        "generation": 2,
        "resource_version": "42",
        "desired_replicas": 1,
        "paused": False,
        "current_revision": 2,
        "current_replica_set_uid": "replica-set-uid-2",
        "current_template_hash": "hash-2",
        "current_replicas": 1,
        "current_ready_replicas": 1,
        "rollback_target": {
            "revision": 1,
            "replica_set_uid": "replica-set-uid-1",
            "health_proof": {
                key: target_summary["health_proof"].get(key)
                for key in ("subject", "version", "verified_at", "verifier")
            },
        },
    }


def test_owned_replica_sets_are_filtered_and_sorted() -> None:
    deployment = ns(metadata=ns(uid="deployment-uid"))
    unrelated = replica_set(9, owner_uid="another-deployment")
    non_controller = replica_set(8, controller=False)

    result = KubernetesBackend._owned_replica_sets(
        deployment,
        [replica_set(2), unrelated, non_controller, replica_set(1)],
    )

    assert [item.metadata.name for item in result] == [
        "order-service-1",
        "order-service-2",
    ]
    assert KubernetesBackend._replica_set_summary(result[0])["change_cause"] is None
    assert KubernetesBackend._replica_set_summary(result[0])["health_status"] == "unknown"


def test_replica_set_health_requires_a_valid_revision_bound_proof() -> None:
    healthy = KubernetesBackend._replica_set_summary(replica_set(1, healthy_proof=True))
    inherited = KubernetesBackend._replica_set_summary(
        replica_set(2, template_health_status="healthy")
    )
    copied = replica_set(3)
    copied.metadata.annotations.update(replica_set(1, healthy_proof=True).metadata.annotations)
    copied.metadata.annotations["deployment.kubernetes.io/revision"] = "3"
    invalid = KubernetesBackend._replica_set_summary(copied)

    assert healthy["health_status"] == "healthy"
    assert healthy["health_proof"]["valid"] is True
    assert inherited["health_status"] == "unknown"
    assert invalid["health_status"] == "unknown"
    assert invalid["health_proof"]["valid"] is False


def test_attestation_writes_proof_to_exact_ready_replica_set_metadata() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()
    backend.core = Mock()
    deployment = ns(metadata=ns(uid="deployment-uid"))
    target = replica_set(4)
    backend.apps.read_namespaced_deployment.return_value = deployment
    backend.apps.list_namespaced_replica_set.return_value = ns(items=[target])
    backend.core.list_namespaced_pod.return_value = ns(
        items=[
            ns(
                metadata=ns(
                    owner_references=[
                        ns(
                            uid="replica-set-uid-4",
                            kind="ReplicaSet",
                            controller=True,
                        )
                    ]
                ),
                status=ns(
                    container_statuses=[
                        ns(
                            name="order-service",
                            ready=True,
                            image_id="docker-pullable://order@sha256:4",
                        )
                    ]
                )
            )
        ]
    )

    result = backend._attest_current_revision_healthy("order-service")

    assert result["revision"] == 4
    call = backend.apps.patch_namespaced_replica_set.call_args
    assert call.args[:2] == ("order-service-4", "sentinelops-demo")
    proof_annotations = call.args[2]["metadata"]["annotations"]
    assert proof_annotations["sentinelops.io/health-proof-revision"] == "4"
    assert proof_annotations["sentinelops.io/health-proof-replicaset-uid"] == (
        "replica-set-uid-4"
    )
    assert "sentinelops.io/health-status" not in proof_annotations
    assert backend.core.list_namespaced_pod.call_args.kwargs["label_selector"] == (
        "app=order-service,pod-template-hash=hash-4"
    )


def test_rollback_restores_target_template_with_resource_version_guard() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()
    current_template = ns(
        metadata=ns(annotations={"sentinelops.io/version": "broken"}),
        spec=ns(containers=[ns(name="order-service", image="order:broken")]),
    )
    deployment = ns(
        metadata=ns(uid="deployment-uid", resource_version="42", generation=2),
        spec=ns(paused=False, replicas=1, template=current_template),
    )
    target = replica_set(1, healthy_proof=True)
    target.spec.template.metadata.annotations["sentinelops.io/health-status"] = "healthy"
    current = replica_set(2)
    backend.apps.read_namespaced_deployment.return_value = deployment
    backend.apps.list_namespaced_replica_set.return_value = ns(items=[target, current])

    result = backend._tool_rollback_deployment(
        {
            "name": "order-service",
            "revision": 1,
            "_precondition": rollback_precondition(target),
        }
    )

    assert result["rolled_back"] is True
    assert deployment.spec.template is not target.spec.template
    assert deployment.spec.template.spec.containers[0].image == "order:1"
    assert "sentinelops.io/rolledBackAt" in deployment.spec.template.metadata.annotations
    assert "sentinelops.io/health-status" not in deployment.spec.template.metadata.annotations
    backend.apps.replace_namespaced_deployment.assert_called_once_with(
        "order-service",
        "sentinelops-demo",
        deployment,
    )


def test_backend_rejects_rollback_if_proof_changes_after_preflight() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()
    deployment = ns(
        metadata=ns(uid="deployment-uid", resource_version="42", generation=2),
        spec=ns(paused=False, replicas=1),
    )
    target = replica_set(1, healthy_proof=True)
    precondition = rollback_precondition(target)
    target.metadata.annotations.pop("sentinelops.io/health-proof-status")
    backend.apps.read_namespaced_deployment.return_value = deployment
    backend.apps.list_namespaced_replica_set.return_value = ns(
        items=[target, replica_set(2)]
    )

    with pytest.raises(RuntimeError, match="health proof changed"):
        backend._tool_rollback_deployment(
            {
                "name": "order-service",
                "revision": 1,
                "_precondition": precondition,
            }
        )

    backend.apps.replace_namespaced_deployment.assert_not_called()


def test_backend_rejects_rollback_when_public_revision_differs_from_guard() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()
    deployment = ns(
        metadata=ns(uid="deployment-uid", resource_version="42", generation=2),
        spec=ns(paused=False, replicas=1),
    )
    target = replica_set(1, healthy_proof=True)
    backend.apps.read_namespaced_deployment.return_value = deployment
    backend.apps.list_namespaced_replica_set.return_value = ns(
        items=[target, replica_set(2)]
    )

    with pytest.raises(RuntimeError, match="tool or arguments changed"):
        backend._tool_rollback_deployment(
            {
                "name": "order-service",
                "revision": 2,
                "_precondition": rollback_precondition(target),
            }
        )

    backend.apps.replace_namespaced_deployment.assert_not_called()


def test_backend_rejects_rollback_when_current_revision_self_recovers() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()
    deployment = ns(
        metadata=ns(uid="deployment-uid", resource_version="42", generation=2),
        spec=ns(paused=False, replicas=1),
    )
    target = replica_set(1, healthy_proof=True)
    precondition = rollback_precondition(target)
    precondition["current_ready_replicas"] = 0
    backend.apps.read_namespaced_deployment.return_value = deployment
    backend.apps.list_namespaced_replica_set.return_value = ns(
        items=[target, replica_set(2)]
    )

    with pytest.raises(RuntimeError, match="current_ready_replicas"):
        backend._tool_rollback_deployment(
            {
                "name": "order-service",
                "revision": 1,
                "_precondition": precondition,
            }
        )

    backend.apps.replace_namespaced_deployment.assert_not_called()


def test_backend_rejects_guard_replayed_to_another_write_tool() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()

    with pytest.raises(RuntimeError, match="tool or arguments changed"):
        backend._tool_restart_deployment(
            {
                "name": "order-service",
                "_precondition": rollback_precondition(
                    replica_set(1, healthy_proof=True)
                ),
            }
        )

    backend.apps.patch_namespaced_deployment.assert_not_called()


def test_restart_uses_fresh_resource_version_as_a_cas_guard() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()
    deployment = ns(
        metadata=ns(uid="deployment-uid", resource_version="42", generation=2),
        spec=ns(paused=False, replicas=1),
    )
    backend.apps.read_namespaced_deployment.return_value = deployment
    backend.apps.list_namespaced_replica_set.return_value = ns(
        items=[replica_set(1), replica_set(2)]
    )
    restart_arguments = {"name": "order-service"}
    precondition = rollback_precondition(
        replica_set(1, healthy_proof=True),
        tool_name="restart_deployment",
        arguments=restart_arguments,
    )
    precondition.pop("rollback_target")

    result = backend._tool_restart_deployment(
        {**restart_arguments, "_precondition": precondition}
    )

    assert result["restarted"] is True
    body = backend.apps.patch_namespaced_deployment.call_args.args[2]
    assert body["metadata"]["resourceVersion"] == "42"


def test_demo_fault_injection_patches_failure_rate_and_waits_for_rollout() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()
    container = ns(name="inventory-service", env=[ns(name="FAIL_EVERY", value="0")])
    deployment = ns(
        metadata=ns(generation=4),
        spec=ns(template=ns(spec=ns(containers=[container]))),
    )
    updated = ns(metadata=ns(generation=5))
    status = ns(
        spec=ns(replicas=1),
        status=ns(
            observed_generation=5,
            replicas=1,
            updated_replicas=1,
            ready_replicas=1,
            available_replicas=1,
        ),
    )
    backend.apps.read_namespaced_deployment.return_value = deployment
    backend.apps.patch_namespaced_deployment.return_value = updated
    backend.apps.read_namespaced_deployment_status.return_value = status
    backend._tool_get_rollout_history = Mock(  # type: ignore[method-assign]
        return_value={"revisions": [{"revision": 5, "replicas": 1}]}
    )

    result = backend._tool_inject_demo_fault(
        {"name": "inventory-service", "timeout_seconds": 1}
    )

    assert result["fault_active"] is True
    assert result["revision"] == 5
    body = backend.apps.patch_namespaced_deployment.call_args.args[2]
    assert body["spec"]["template"]["metadata"]["annotations"][
        "sentinelops.io/health-status"
    ] is None
    assert body["spec"]["template"]["spec"]["containers"][0]["env"] == [
        {"name": "FAIL_EVERY", "value": "3"}
    ]


def test_reset_demo_baseline_sets_known_healthy_config() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()
    backend.apps.patch_namespaced_deployment.return_value = ns(metadata=ns(generation=8))
    backend.apps.read_namespaced_deployment_status.return_value = ns(
        spec=ns(replicas=1),
        status=ns(
            observed_generation=8,
            replicas=1,
            updated_replicas=1,
            ready_replicas=1,
            available_replicas=1,
        ),
    )
    backend._tool_get_rollout_history = Mock(  # type: ignore[method-assign]
        return_value={"revisions": [{"revision": 8, "replicas": 1}]}
    )
    backend._attest_current_revision_healthy = Mock(  # type: ignore[method-assign]
        return_value={
            "revision": 8,
            "health_proof": {"valid": True, "status": "healthy"},
        }
    )

    result = backend._tool_reset_demo_baseline(
        {"name": "inventory-service", "timeout_seconds": 1}
    )

    assert result["baseline_restored"] is True
    assert result["revision"] == 8
    body = backend.apps.patch_namespaced_deployment.call_args.args[2]
    template = body["spec"]["template"]
    assert template["metadata"]["annotations"]["sentinelops.io/change-cause"] == (
        "healthy-baseline"
    )
    assert template["metadata"]["annotations"]["sentinelops.io/health-status"] is None
    assert template["spec"]["containers"][0]["env"] == [
        {"name": "FAIL_EVERY", "value": "0"}
    ]
    backend._attest_current_revision_healthy.assert_called_once_with("inventory-service")
