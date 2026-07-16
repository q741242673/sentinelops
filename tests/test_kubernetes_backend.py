from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from sentinelops.tools.kubernetes import KubernetesBackend


def ns(**values):
    return SimpleNamespace(**values)


def replica_set(revision: int, *, owner_uid: str = "deployment-uid"):
    template = ns(
        metadata=ns(annotations={"sentinelops.io/version": f"1.{revision}.0"}),
        spec=ns(containers=[ns(name="order-service", image=f"order:{revision}")]),
    )
    return ns(
        metadata=ns(
            name=f"order-service-{revision}",
            annotations={"deployment.kubernetes.io/revision": str(revision)},
            owner_references=[ns(uid=owner_uid, kind="Deployment")],
        ),
        spec=ns(template=template),
        status=ns(replicas=1, ready_replicas=1),
    )


def test_owned_replica_sets_are_filtered_and_sorted() -> None:
    deployment = ns(metadata=ns(uid="deployment-uid"))
    unrelated = replica_set(9, owner_uid="another-deployment")

    result = KubernetesBackend._owned_replica_sets(
        deployment,
        [replica_set(2), unrelated, replica_set(1)],
    )

    assert [item.metadata.name for item in result] == [
        "order-service-1",
        "order-service-2",
    ]
    assert KubernetesBackend._replica_set_summary(result[0])["change_cause"] is None


def test_rollback_restores_target_template_with_resource_version_guard() -> None:
    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.namespace = "sentinelops-demo"
    backend.apps = Mock()
    current_template = ns(
        metadata=ns(annotations={"sentinelops.io/version": "broken"}),
        spec=ns(containers=[ns(name="order-service", image="order:broken")]),
    )
    deployment = ns(
        metadata=ns(uid="deployment-uid", resource_version="42"),
        spec=ns(paused=False, template=current_template),
    )
    target = replica_set(1)
    backend.apps.read_namespaced_deployment.return_value = deployment
    backend.apps.list_namespaced_replica_set.return_value = ns(items=[target, replica_set(2)])

    result = backend._tool_rollback_deployment({"name": "order-service", "revision": 1})

    assert result["rolled_back"] is True
    assert deployment.spec.template is not target.spec.template
    assert deployment.spec.template.spec.containers[0].image == "order:1"
    assert "sentinelops.io/rolledBackAt" in deployment.spec.template.metadata.annotations
    backend.apps.replace_namespaced_deployment.assert_called_once_with(
        "order-service",
        "sentinelops-demo",
        deployment,
    )


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
    assert template["spec"]["containers"][0]["env"] == [
        {"name": "FAIL_EVERY", "value": "0"}
    ]
