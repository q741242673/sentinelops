from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from sentinelops.actions import STANDARD_ACTION_CATALOG

ROOT = Path(__file__).resolve().parents[1]
CRD_PATH = (
    ROOT
    / "deploy"
    / "production"
    / "crds"
    / "sentinelremediations.yaml"
)
RBAC_PATH = (
    ROOT
    / "deploy"
    / "production"
    / "access"
    / "workload-rbac.yaml"
)


def _crd() -> dict[str, Any]:
    resource = yaml.safe_load(CRD_PATH.read_text(encoding="utf-8"))
    assert isinstance(resource, dict)
    return resource


def _schema() -> dict[str, Any]:
    versions = _crd()["spec"]["versions"]
    assert len(versions) == 1
    return versions[0]["schema"]["openAPIV3Schema"]


def _validations(schema: dict[str, Any]) -> list[str]:
    return [item["rule"] for item in schema.get("x-kubernetes-validations", [])]


def _rbac_resources() -> list[dict[str, Any]]:
    resources = list(yaml.safe_load_all(RBAC_PATH.read_text(encoding="utf-8")))
    assert all(isinstance(resource, dict) for resource in resources)
    return resources


def test_remediation_crd_is_namespaced_versioned_and_uses_status_subresource() -> None:
    crd = _crd()

    assert crd["apiVersion"] == "apiextensions.k8s.io/v1"
    assert crd["kind"] == "CustomResourceDefinition"
    assert crd["metadata"]["name"] == "sentinelremediations.ops.sentinelops.io"
    assert crd["spec"]["group"] == "ops.sentinelops.io"
    assert crd["spec"]["scope"] == "Namespaced"
    assert crd["spec"]["names"] == {
        "kind": "SentinelRemediation",
        "listKind": "SentinelRemediationList",
        "plural": "sentinelremediations",
        "singular": "sentinelremediation",
    }

    version = crd["spec"]["versions"][0]
    assert version["name"] == "v1alpha1"
    assert version["served"] is True
    assert version["storage"] is True
    assert version["subresources"] == {"status": {}}


def test_remediation_identity_target_and_spec_are_immutable() -> None:
    schema = _schema()
    spec = schema["properties"]["spec"]
    root_rules = _validations(schema)
    spec_rules = _validations(spec)

    assert "self.metadata.name == self.spec.actionId" in root_rules
    assert "self == oldSelf" in spec_rules
    assert spec["x-kubernetes-map-type"] == "atomic"
    assert spec.get("x-kubernetes-preserve-unknown-fields") is not True
    assert set(spec["required"]) == {
        "actionId",
        "incidentId",
        "action",
        "target",
        "precondition",
        "authorization",
        "fence",
    }
    assert spec["properties"]["actionId"]["pattern"] == "^[a-f0-9]{64}$"


def test_crd_action_contract_matches_the_server_owned_plugin_catalog() -> None:
    spec = _schema()["properties"]["spec"]
    action = spec["properties"]["action"]
    parameters = action["properties"]["parameters"]
    registered = {
        plugin.name for plugin in STANDARD_ACTION_CATALOG.list(enabled_only=False)
    }

    assert set(action["properties"]["plugin"]["enum"]) == registered
    assert action.get("x-kubernetes-preserve-unknown-fields") is not True
    assert parameters.get("x-kubernetes-preserve-unknown-fields") is not True
    assert parameters["properties"]["replicas"]["maximum"] == 100
    rules = " ".join(_validations(action))
    assert "restart_deployment" in rules
    assert "rollback_deployment" in rules
    assert "scale_deployment" in rules

    cross_field_rules = " ".join(_validations(spec))
    assert "self.action.parameters.name == self.target.name" in cross_field_rules
    assert "self.precondition.rollbackTarget.revision" in cross_field_rules
    assert "self.action.parameters.revision" in cross_field_rules


def test_crd_binds_authorization_snapshot_and_monotonic_fence() -> None:
    spec = _schema()["properties"]["spec"]
    authorization = spec["properties"]["authorization"]
    precondition = spec["properties"]["precondition"]
    fence = spec["properties"]["fence"]

    assert authorization.get("x-kubernetes-preserve-unknown-fields") is not True
    authorization_rules = " ".join(_validations(authorization))
    assert "human_approval" in authorization_rules
    assert "approvalDigest" in authorization_rules
    assert "risk_policy" in authorization_rules
    assert authorization["properties"]["policyDigest"]["pattern"] == "^[a-f0-9]{64}$"

    assert precondition.get("x-kubernetes-preserve-unknown-fields") is not True
    assert {
        "snapshotDigest",
        "resourceVersion",
        "generation",
        "desiredReplicas",
        "paused",
        "currentRevision",
        "currentReplicaSetUid",
        "currentTemplateHash",
        "capturedAt",
    } <= set(precondition["required"])
    assert precondition["properties"]["snapshotDigest"]["pattern"] == "^[a-f0-9]{64}$"

    assert fence.get("x-kubernetes-preserve-unknown-fields") is not True
    assert fence["properties"]["generation"]["minimum"] == 1
    assert fence["properties"]["expiresAt"]["format"] == "date-time"


def test_status_preserves_terminal_results_and_never_rewinds_generation() -> None:
    status = _schema()["properties"]["status"]
    rules = " ".join(_validations(status))

    assert status.get("x-kubernetes-preserve-unknown-fields") is not True
    assert {"Succeeded", "Failed", "Rejected", "Stale", "Cancelled"} <= set(
        status["properties"]["phase"]["enum"]
    )
    assert "oldSelf.phase" in rules
    assert "self.phase == oldSelf.phase" in rules
    assert "self.observedGeneration >= oldSelf.observedGeneration" in rules
    assert (
        status["properties"]["conditions"]["x-kubernetes-list-map-keys"]
        == ["type"]
    )


def test_executor_can_submit_and_observe_but_not_mutate_remediation_specs() -> None:
    resources = _rbac_resources()
    role = next(
        resource
        for resource in resources
        if resource["kind"] == "Role"
        and resource["metadata"]["name"] == "sentinelops-remediation-submit"
    )
    binding = next(
        resource
        for resource in resources
        if resource["kind"] == "RoleBinding"
        and resource["metadata"]["name"] == "sentinelops-remediation-submit"
    )

    assert role["rules"] == [
        {
            "apiGroups": ["ops.sentinelops.io"],
            "resources": ["sentinelremediations"],
            "verbs": ["create", "get", "list", "watch"],
        }
    ]
    assert binding["subjects"] == [
        {
            "kind": "ServiceAccount",
            "name": "sentinelops-executor",
            "namespace": "sentinelops-system",
        }
    ]
    assert binding["roleRef"]["name"] == "sentinelops-remediation-submit"
