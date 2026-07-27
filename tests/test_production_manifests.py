from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_DIR = ROOT / "deploy" / "production"


def _resources() -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for path in sorted(PRODUCTION_DIR.rglob("*.yaml")):
        for document in yaml.safe_load_all(path.read_text()):
            assert isinstance(document, dict), f"{path} contains an empty YAML document"
            resources.append(document)
    return resources


def _resource(
    kind: str,
    name: str,
    namespace: str | None,
) -> dict[str, Any]:
    matches = [
        item
        for item in _resources()
        if item["kind"] == kind
        and item["metadata"]["name"] == name
        and item["metadata"].get("namespace") == namespace
    ]
    assert len(matches) == 1
    return matches[0]


def _container(resource: dict[str, Any]) -> dict[str, Any]:
    pod_spec = (
        resource["spec"]["template"]["spec"]
        if resource["kind"] == "Deployment"
        else resource["spec"]["template"]["spec"]
    )
    assert len(pod_spec["containers"]) == 1
    return pod_spec["containers"][0]


def test_production_yaml_resources_are_unique_and_do_not_commit_secrets() -> None:
    resources = _resources()
    identities = [
        (
            item["apiVersion"],
            item["kind"],
            item["metadata"].get("namespace"),
            item["metadata"]["name"],
        )
        for item in resources
    ]

    assert len(identities) == len(set(identities))
    assert all(item["kind"] != "Secret" for item in resources)
    cluster_resources = {
        (item["kind"], item["metadata"]["name"])
        for item in resources
        if item["kind"] in {"ClusterRole", "ClusterRoleBinding"}
    }
    assert cluster_resources == {
        (
            "ClusterRole",
            "sentinelops-api-token-review",
        ),
        (
            "ClusterRoleBinding",
            "sentinelops-api-token-review",
        ),
        (
            "ClusterRole",
            "sentinelops-remediation-controller-admission-integrity",
        ),
        (
            "ClusterRoleBinding",
            "sentinelops-remediation-controller-admission-integrity",
        ),
    }
    token_review_role = _resource(
        "ClusterRole",
        "sentinelops-api-token-review",
        None,
    )
    assert token_review_role["rules"] == [
        {
            "apiGroups": ["authentication.k8s.io"],
            "resources": ["tokenreviews"],
            "verbs": ["create"],
        }
    ]
    token_review_binding = _resource(
        "ClusterRoleBinding",
        "sentinelops-api-token-review",
        None,
    )
    assert token_review_binding["subjects"] == [
        {
            "kind": "ServiceAccount",
            "name": "sentinelops-api",
            "namespace": "sentinelops-system",
        }
    ]


def test_runtime_configuration_fails_closed_for_production() -> None:
    runtime = _resource("ConfigMap", "sentinelops-runtime", "sentinelops-system")["data"]
    executor_runtime = _resource(
        "ConfigMap",
        "sentinelops-executor-runtime",
        "sentinelops-system",
    )["data"]
    api = _resource("ConfigMap", "sentinelops-api", "sentinelops-system")["data"]
    anchor = _resource(
        "ConfigMap",
        "sentinelops-anchor",
        "sentinelops-system",
    )["data"]
    gitops = _resource(
        "ConfigMap",
        "sentinelops-gitops",
        "sentinelops-system",
    )["data"]

    assert runtime["SENTINELOPS_ENVIRONMENT"] == "production"
    assert runtime["SENTINELOPS_TOOL_BACKEND"] == "kubernetes"
    assert runtime["SENTINELOPS_CLUSTER_ID"] == "prod-cluster-a"
    assert runtime["SENTINELOPS_CLUSTER_DISPLAY_NAME"] == "生产集群 A"
    assert runtime["SENTINELOPS_DATABASE_AUTO_CREATE"] == "false"
    assert 1 <= int(
        runtime["SENTINELOPS_DATABASE_OPERATION_TIMEOUT_SECONDS"]
    ) <= 120
    assert executor_runtime == {
        "SENTINELOPS_ENVIRONMENT": "production",
        "SENTINELOPS_TOOL_BACKEND": "kubernetes",
        "SENTINELOPS_CLUSTER_ID": "prod-cluster-a",
        "SENTINELOPS_CLUSTER_DISPLAY_NAME": "生产集群 A",
        "SENTINELOPS_KUBERNETES_NAMESPACE": "sentinelops-workloads",
        "SENTINELOPS_EXECUTOR_MODE": "external",
        "SENTINELOPS_EXECUTOR_BACKEND": "controller",
        "SENTINELOPS_EXECUTOR_CLAIM_TTL_SECONDS": "60",
        "SENTINELOPS_EXECUTOR_REGISTRY_TTL_SECONDS": "60",
        "SENTINELOPS_EXECUTOR_REGISTRY_HEARTBEAT_SECONDS": "15",
        "SENTINELOPS_CONTROL_GATEWAY_URL": (
            "https://replace-with-company-control-gateway.example"
        ),
        "SENTINELOPS_CONTROL_GATEWAY_TOKEN_FILE": (
            "/var/run/secrets/sentinelops-control-gateway/gateway-token"
        ),
    }
    registry_ttl = float(
        executor_runtime["SENTINELOPS_EXECUTOR_REGISTRY_TTL_SECONDS"]
    )
    registry_heartbeat = float(
        executor_runtime["SENTINELOPS_EXECUTOR_REGISTRY_HEARTBEAT_SECONDS"]
    )
    assert 10 <= registry_ttl <= 600
    assert 1 <= registry_heartbeat <= registry_ttl / 3
    assert runtime["SENTINELOPS_DATABASE_URL_FILE"].startswith("/var/run/secrets/")
    assert runtime["SENTINELOPS_AUDIT_HMAC_KEY_FILE"].startswith(
        "/var/run/secrets/"
    )
    assert runtime["SENTINELOPS_AUDIT_KEY_ID"] != "development-unkeyed"
    assert runtime["SENTINELOPS_AUDIT_ANCHOR_ENFORCEMENT_REQUIRED"] == "true"
    assert api["SENTINELOPS_DEMO_ENABLED"] == "false"
    assert api["SENTINELOPS_ALERTMANAGER_WEBHOOK_AUTH_MODE"] != "disabled"
    assert api["SENTINELOPS_MODEL_API_KEY_FILE"].startswith("/var/run/secrets/")
    assert 256 <= int(api["SENTINELOPS_MODEL_MAX_TOKENS"]) <= 32_768
    assert api["SENTINELOPS_ALERTMANAGER_WEBHOOK_BEARER_TOKEN_FILE"].startswith(
        "/var/run/secrets/"
    )
    assert api["SENTINELOPS_OPERATOR_AUTH_MODE"] == "oidc"
    assert api["SENTINELOPS_OIDC_ISSUER"].startswith("https://")
    assert api["SENTINELOPS_OIDC_AUDIENCE"] == "sentinelops-api"
    assert api["SENTINELOPS_OIDC_JWKS_URL"].startswith("https://")
    assert api["SENTINELOPS_OIDC_HUMAN_VALUE"] == "human"
    assert api["SENTINELOPS_CONTROL_GATEWAY_AUTH_MODE"] == "workload_oidc"
    assert api["SENTINELOPS_CONTROL_GATEWAY_TRUST_BUNDLE_FILE"].startswith(
        "/etc/"
    )
    workload_trust = json.loads(
        _resource(
            "ConfigMap",
            "sentinelops-control-gateway-trust",
            "sentinelops-system",
        )["data"]["trust.json"]
    )
    trusted_cluster = workload_trust["clusters"][0]
    assert trusted_cluster["cluster_id"] == "prod-cluster-a"
    assert trusted_cluster["audience"] == "sentinelops-control-gateway"
    assert trusted_cluster["issuer"].startswith("https://")
    assert trusted_cluster["jwks_url"].startswith("https://")
    assert trusted_cluster["token_review_url"] == (
        "https://kubernetes.default.svc/"
        "apis/authentication.k8s.io/v1/tokenreviews"
    )
    assert trusted_cluster["reviewer_token_file"] == (
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )
    assert trusted_cluster["token_review_ca_file"] == (
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    )
    assert "action.execute" in trusted_cluster["allowed_capabilities"]
    assert anchor["SENTINELOPS_AUDIT_ANCHOR_URL"].startswith("https://")
    assert anchor["SENTINELOPS_AUDIT_ANCHOR_INVENTORY_URL"].startswith(
        "https://"
    )
    assert anchor["SENTINELOPS_AUDIT_ANCHOR_SOURCE_ID"] != "default"
    assert anchor["SENTINELOPS_AUDIT_ANCHOR_BEARER_TOKEN_FILE"].startswith(
        "/var/run/secrets/"
    )
    assert anchor["SENTINELOPS_AUDIT_ANCHOR_TRUSTED_RECEIVER_ID"].startswith(
        "replace-"
    )
    assert anchor[
        "SENTINELOPS_AUDIT_ANCHOR_RECEIPT_PUBLIC_KEYS_FILE"
    ].startswith("/etc/")
    keyring = _resource(
        "ConfigMap",
        "sentinelops-anchor-public-keys",
        "sentinelops-system",
    )["data"]["receipt-public-keys.json"]
    assert "replace-key-id" in keyring
    assert gitops["SENTINELOPS_GITOPS_GATEWAY_URL"].startswith("https://")
    assert gitops["SENTINELOPS_GITOPS_BEARER_TOKEN_FILE"].startswith(
        "/var/run/secrets/"
    )


def test_runtime_components_are_separate_hardened_deployments() -> None:
    api = _resource("Deployment", "sentinelops-api", "sentinelops-system")
    executor = _resource("Deployment", "sentinelops-executor", "sentinelops-system")
    controller = _resource(
        "Deployment",
        "sentinelops-remediation-controller",
        "sentinelops-system",
    )
    publisher = _resource(
        "Deployment",
        "sentinelops-anchor-publisher",
        "sentinelops-system",
    )
    gitops_publisher = _resource(
        "Deployment",
        "sentinelops-gitops-publisher",
        "sentinelops-system",
    )

    assert api["spec"]["replicas"] >= 2
    assert executor["spec"]["replicas"] >= 2
    assert controller["spec"]["replicas"] >= 2
    assert publisher["spec"]["replicas"] >= 2
    assert gitops_publisher["spec"]["replicas"] >= 2
    assert api["spec"]["template"]["spec"]["serviceAccountName"] == "sentinelops-api"
    assert (
        executor["spec"]["template"]["spec"]["serviceAccountName"]
        == "sentinelops-executor"
    )
    executor_env = {
        item["name"]: item
        for item in _container(executor)["env"]
    }
    assert executor_env["SENTINELOPS_EXECUTOR_INSTANCE_ID"]["valueFrom"][
        "fieldRef"
    ] == {
        "apiVersion": "v1",
        "fieldPath": "metadata.uid",
    }
    executor_container = _container(executor)
    for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
        command = executor_container[probe_name]["exec"]["command"]
        max_age = float(command[command.index("--max-age-seconds") + 1])
        assert max_age <= float(
            _resource(
                "ConfigMap",
                "sentinelops-executor-runtime",
                "sentinelops-system",
            )["data"]["SENTINELOPS_EXECUTOR_REGISTRY_TTL_SECONDS"]
        )
    assert (
        controller["spec"]["template"]["spec"]["serviceAccountName"]
        == "sentinelops-remediation-controller"
    )
    assert (
        controller["spec"]["template"]["spec"]["automountServiceAccountToken"]
        is True
    )
    assert (
        publisher["spec"]["template"]["spec"]["serviceAccountName"]
        == "sentinelops-anchor-publisher"
    )
    assert publisher["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    assert (
        gitops_publisher["spec"]["template"]["spec"]["serviceAccountName"]
        == "sentinelops-gitops-publisher"
    )
    assert (
        gitops_publisher["spec"]["template"]["spec"][
            "automountServiceAccountToken"
        ]
        is False
    )

    api_container = _container(api)
    executor_container = _container(executor)
    controller_container = _container(controller)
    publisher_container = _container(publisher)
    gitops_container = _container(gitops_publisher)
    for container in (api_container, controller_container):
        assert {
            item["configMapRef"]["name"]
            for item in container["envFrom"]
        } >= {"sentinelops-runtime"}
    assert {
        item["configMapRef"]["name"]
        for item in executor_container["envFrom"]
    } == {"sentinelops-executor-runtime"}
    assert api_container["livenessProbe"]["httpGet"]["path"] == "/health"
    assert api_container["readinessProbe"]["httpGet"]["path"] == "/ready"
    assert api_container["startupProbe"]["httpGet"]["path"] == "/health"
    assert (
        executor_container["livenessProbe"]["exec"]["command"][0]
        == "sentinelops-executor-health"
    )
    assert (
        executor_container["readinessProbe"]["exec"]["command"][0]
        == "sentinelops-executor-health"
    )
    assert controller_container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert controller_container["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert controller_container["image"].endswith(
        "/sentinelops-remediation-controller:0.1.0-rc.1"
    )
    assert "--leader-elect=true" in controller_container["args"]
    assert (
        publisher_container["livenessProbe"]["exec"]["command"][0]
        == "sentinelops-anchor-health"
    )
    assert (
        publisher_container["readinessProbe"]["exec"]["command"][0]
        == "sentinelops-anchor-health"
    )
    assert (
        gitops_container["readinessProbe"]["exec"]["command"][0]
        == "sentinelops-gitops-health"
    )
    assert executor_container["startupProbe"]["timeoutSeconds"] >= 5
    assert publisher_container["startupProbe"]["timeoutSeconds"] >= 5
    assert (
        api_container["image"]
        == executor_container["image"]
        == publisher_container["image"]
        == gitops_container["image"]
    )

    for deployment in (api, executor, controller, publisher, gitops_publisher):
        pod_spec = deployment["spec"]["template"]["spec"]
        container = _container(deployment)
        assert pod_spec["securityContext"]["runAsNonRoot"] is True
        assert pod_spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
        assert container["resources"]["requests"]
        assert container["resources"]["limits"]

    executor_pod_spec = executor["spec"]["template"]["spec"]
    assert executor_pod_spec["automountServiceAccountToken"] is True
    assert executor_pod_spec["volumes"][0] == {
        "name": "control-gateway-identity",
        "projected": {
            "defaultMode": 288,
            "sources": [
                {
                    "serviceAccountToken": {
                        "audience": "sentinelops-control-gateway",
                        "expirationSeconds": 600,
                        "path": "gateway-token",
                    }
                }
            ],
        },
    }
    assert executor_container["volumeMounts"][0] == {
        "name": "control-gateway-identity",
        "mountPath": "/var/run/secrets/sentinelops-control-gateway",
        "readOnly": True,
    }
    forbidden_executor_configuration = (
        "database",
        "postgres",
        "audit_hmac",
        "database-url",
        "audit-hmac-key",
    )
    executor_configuration = json.dumps(
        {
            "config": _resource(
                "ConfigMap",
                "sentinelops-executor-runtime",
                "sentinelops-system",
            ),
            "deployment": executor,
        },
        sort_keys=True,
    ).casefold()
    assert all(
        forbidden not in executor_configuration
        for forbidden in forbidden_executor_configuration
    )

    api_secret_items = api["spec"]["template"]["spec"]["volumes"][0][
        "projected"
    ]["sources"][0]["secret"]["items"]
    assert {"key": "database-url", "path": "database-url"} in api_secret_items
    api_volumes = {
        volume["name"]: volume
        for volume in api["spec"]["template"]["spec"]["volumes"]
    }
    assert api_volumes["control-gateway-trust"]["configMap"]["name"] == (
        "sentinelops-control-gateway-trust"
    )
    publisher_secret_items = publisher["spec"]["template"]["spec"]["volumes"][0][
        "projected"
    ]["sources"][0]["secret"]["items"]
    assert publisher_secret_items == [
        {"key": "database-url", "path": "database-url"},
        {"key": "audit-hmac-key", "path": "audit-hmac-key"},
        {"key": "audit-anchor-token", "path": "audit-anchor-token"},
        {
            "key": "audit-anchor-reconcile-token",
            "path": "audit-anchor-reconcile-token",
        },
    ]
    gitops_secret_items = gitops_publisher["spec"]["template"]["spec"][
        "volumes"
    ][0]["projected"]["sources"][0]["secret"]["items"]
    assert gitops_secret_items == [
        {"key": "database-url", "path": "database-url"},
        {"key": "audit-hmac-key", "path": "audit-hmac-key"},
        {"key": "gitops-token", "path": "gitops-token"},
    ]


def test_migration_job_is_bounded_and_has_no_cluster_credentials() -> None:
    migration = _resource("Job", "sentinelops-db-migrate", "sentinelops-system")
    pod_spec = migration["spec"]["template"]["spec"]
    container = _container(migration)

    assert migration["spec"]["activeDeadlineSeconds"] <= 600
    assert migration["spec"]["backoffLimit"] <= 1
    assert pod_spec["restartPolicy"] == "Never"
    assert pod_spec["automountServiceAccountToken"] is False
    assert pod_spec["serviceAccountName"] == "sentinelops-migrator"
    assert container["args"] == ["db-init"]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["env"] == [
        {
            "name": "SENTINELOPS_DATABASE_URL_FILE",
            "value": "/var/run/secrets/sentinelops/database-url",
        }
    ]
    assert pod_spec["volumes"][0]["projected"]["sources"][0]["secret"]["items"] == [
        {"key": "database-url", "path": "database-url"}
    ]


def test_rbac_keeps_api_readonly_and_controller_as_only_workload_writer() -> None:
    api_role = _resource("Role", "sentinelops-api-readonly", "sentinelops-workloads")
    submit_role = _resource(
        "Role",
        "sentinelops-remediation-submit",
        "sentinelops-workloads",
    )
    controller_role = _resource(
        "Role",
        "sentinelops-remediation-controller",
        "sentinelops-workloads",
    )

    api_verbs = {verb for rule in api_role["rules"] for verb in rule["verbs"]}
    api_resources = {
        resource for rule in api_role["rules"] for resource in rule["resources"]
    }
    assert api_verbs <= {"get", "list", "watch"}
    assert "secrets" not in api_resources

    submit_resources = {
        resource
        for rule in submit_role["rules"]
        for resource in rule["resources"]
    }
    assert submit_resources == {"sentinelremediations"}
    assert all(
        set(rule["verbs"]) <= {"create", "get", "list", "watch"}
        for rule in submit_role["rules"]
    )
    controller_resources = {
        resource
        for rule in controller_role["rules"]
        for resource in rule["resources"]
    }
    assert controller_resources == {
        "sentinelremediations",
        "sentinelremediations/status",
        "deployments",
        "replicasets",
        "sentineladmissionguards",
    }
    assert any(
        set(rule["verbs"]) == {"get", "list", "watch", "update"}
        for rule in controller_role["rules"]
        if rule["resources"] == ["deployments"]
    )
    assert any(
        {"update", "patch"} <= set(rule["verbs"])
        for rule in controller_role["rules"]
        if rule["resources"] == ["sentinelremediations/status"]
    )
    assert all(
        "delete" not in rule["verbs"] and "create" not in rule["verbs"]
        for rule in controller_role["rules"]
    )

    api_binding = _resource(
        "RoleBinding",
        "sentinelops-api-readonly",
        "sentinelops-workloads",
    )
    submit_binding = _resource(
        "RoleBinding",
        "sentinelops-remediation-submit",
        "sentinelops-workloads",
    )
    controller_binding = _resource(
        "RoleBinding",
        "sentinelops-remediation-controller",
        "sentinelops-workloads",
    )
    assert api_binding["subjects"][0] == {
        "kind": "ServiceAccount",
        "name": "sentinelops-api",
        "namespace": "sentinelops-system",
    }
    assert submit_binding["subjects"][0] == {
        "kind": "ServiceAccount",
        "name": "sentinelops-executor",
        "namespace": "sentinelops-system",
    }
    assert controller_binding["subjects"][0] == {
        "kind": "ServiceAccount",
        "name": "sentinelops-remediation-controller",
        "namespace": "sentinelops-system",
    }
    leader_role = _resource(
        "Role",
        "sentinelops-remediation-controller-leader-election",
        "sentinelops-system",
    )
    assert leader_role["rules"] == [
        {
            "apiGroups": ["coordination.k8s.io"],
            "resources": ["leases"],
            "verbs": ["get", "list", "watch", "create", "update", "patch"],
        },
        {
            "apiGroups": [""],
            "resources": ["events"],
            "verbs": ["create", "patch"],
        },
    ]
    bound_service_accounts = {
        subject["name"]
        for item in _resources()
        if item["kind"] in {"RoleBinding", "ClusterRoleBinding"}
        for subject in item.get("subjects", [])
        if subject.get("kind") == "ServiceAccount"
    }
    assert "sentinelops-anchor-publisher" not in bound_service_accounts
    assert "sentinelops-gitops-publisher" not in bound_service_accounts


def test_admission_fence_denies_unlisted_workload_and_contract_writers() -> None:
    guard_crd = _resource(
        "CustomResourceDefinition",
        "sentineladmissionguards.ops.sentinelops.io",
        None,
    )
    guard_schema = guard_crd["spec"]["versions"][0]["schema"][
        "openAPIV3Schema"
    ]["properties"]["spec"]
    assert set(guard_schema["required"]) == {
        "allowedPolicyManagers",
        "allowedDeploymentWriters",
        "allowedRemediationCreators",
        "allowedRemediationStatusWriters",
        "allowedRemediationDeleters",
    }
    for field in guard_schema["properties"].values():
        assert field["type"] == "array"
        assert field["x-kubernetes-list-type"] == "set"
        assert field["maxItems"] <= 32

    guard = _resource(
        "SentinelAdmissionGuard",
        "sentinelops-workload-write-fence",
        "sentinelops-workloads",
    )["spec"]
    controller = (
        "system:serviceaccount:sentinelops-system:"
        "sentinelops-remediation-controller"
    )
    executor = (
        "system:serviceaccount:sentinelops-system:sentinelops-executor"
    )
    admission_admin = (
        "system:serviceaccount:sentinelops-system:"
        "sentinelops-admission-admin"
    )
    assert guard == {
        "allowedPolicyManagers": [admission_admin],
        "allowedDeploymentWriters": [controller],
        "allowedRemediationCreators": [executor],
        "allowedRemediationStatusWriters": [controller],
        "allowedRemediationDeleters": [],
    }
    runtime = _resource(
        "ConfigMap",
        "sentinelops-runtime",
        "sentinelops-system",
    )["data"]
    assert runtime["SENTINELOPS_ADMISSION_INTEGRITY_REQUIRED"] == "true"
    assert runtime["SENTINELOPS_ADMISSION_POLICY_NAME"] == (
        "sentinelops-workload-write-fence"
    )
    assert runtime["SENTINELOPS_ADMISSION_GOVERNANCE_POLICY_NAME"] == (
        "sentinelops-admission-governance"
    )
    assert json.loads(
        runtime["SENTINELOPS_ADMISSION_EXPECTED_GUARD_SPEC"]
    ) == guard

    policy = _resource(
        "ValidatingAdmissionPolicy",
        "sentinelops-workload-write-fence",
        None,
    )["spec"]
    assert policy["failurePolicy"] == "Fail"
    assert policy["paramKind"] == {
        "apiVersion": "ops.sentinelops.io/v1alpha1",
        "kind": "SentinelAdmissionGuard",
    }
    matched_resources = {
        resource
        for rule in policy["matchConstraints"]["resourceRules"]
        for resource in rule["resources"]
    }
    assert matched_resources == {
        "deployments",
        "sentinelremediations",
        "sentinelremediations/status",
    }
    validation_text = " ".join(
        validation["expression"] for validation in policy["validations"]
    )
    assert "allowedDeploymentWriters" in validation_text
    assert "allowedRemediationCreators" in validation_text
    assert "allowedRemediationStatusWriters" in validation_text
    assert "allowedRemediationDeleters" in validation_text
    assert "request.subResource == 'status'" in validation_text
    assert "request.userInfo.username" in validation_text
    assert all(
        validation["reason"] == "Forbidden"
        for validation in policy["validations"]
    )
    assert policy["auditAnnotations"][0]["key"] == "admission-guard"

    binding = _resource(
        "ValidatingAdmissionPolicyBinding",
        "sentinelops-workload-write-fence",
        None,
    )["spec"]
    assert set(binding["validationActions"]) == {"Deny", "Audit"}
    assert binding["paramRef"] == {
        "name": "sentinelops-workload-write-fence",
        "namespace": "sentinelops-workloads",
        "parameterNotFoundAction": "Deny",
    }
    assert binding["matchResources"]["namespaceSelector"][
        "matchLabels"
    ] == {"sentinelops.io/admission-protected": "true"}

    audit_binding = _resource(
        "ValidatingAdmissionPolicyBinding",
        "sentinelops-workload-write-fence-audit",
        None,
    )["spec"]
    assert set(audit_binding["validationActions"]) == {"Warn", "Audit"}
    assert audit_binding["paramRef"] == binding["paramRef"]
    assert audit_binding["matchResources"]["namespaceSelector"][
        "matchLabels"
    ] == {"sentinelops.io/admission-audit": "true"}

    governance = _resource(
        "ValidatingAdmissionPolicy",
        "sentinelops-admission-governance",
        None,
    )["spec"]
    assert governance["failurePolicy"] == "Fail"
    governance_resources = {
        resource
        for rule in governance["matchConstraints"]["resourceRules"]
        for resource in rule["resources"]
    }
    assert governance_resources == {"sentineladmissionguards", "namespaces"}
    governance_validation_text = " ".join(
        validation["expression"]
        for validation in governance["validations"]
    )
    assert "allowedPolicyManagers" in governance_validation_text
    assert "variables.oldProtection == variables.newProtection" in (
        governance_validation_text
    )
    assert all(
        validation["reason"] == "Forbidden"
        for validation in governance["validations"]
    )

    governance_binding = _resource(
        "ValidatingAdmissionPolicyBinding",
        "sentinelops-admission-governance",
        None,
    )["spec"]
    assert set(governance_binding["validationActions"]) == {"Deny", "Audit"}
    assert governance_binding["paramRef"] == binding["paramRef"]

    manager_account = _resource(
        "ServiceAccount",
        "sentinelops-admission-admin",
        "sentinelops-system",
    )
    assert manager_account["automountServiceAccountToken"] is False
    integrity_role = _resource(
        "ClusterRole",
        "sentinelops-remediation-controller-admission-integrity",
        None,
    )
    assert all(rule["verbs"] == ["get"] for rule in integrity_role["rules"])
    assert all(rule["resourceNames"] for rule in integrity_role["rules"])
    assert {
        resource
        for rule in integrity_role["rules"]
        for resource in rule["resources"]
    } == {
        "customresourcedefinitions",
        "namespaces",
        "validatingadmissionpolicies",
        "validatingadmissionpolicybindings",
    }
    integrity_binding = _resource(
        "ClusterRoleBinding",
        "sentinelops-remediation-controller-admission-integrity",
        None,
    )
    assert integrity_binding["subjects"] == [
        {
            "kind": "ServiceAccount",
            "name": "sentinelops-remediation-controller",
            "namespace": "sentinelops-system",
        }
    ]
    workload_role = _resource(
        "Role",
        "sentinelops-remediation-controller",
        "sentinelops-workloads",
    )
    guard_rules = [
        rule
        for rule in workload_role["rules"]
        if "sentineladmissionguards" in rule["resources"]
    ]
    assert guard_rules == [
        {
            "apiGroups": ["ops.sentinelops.io"],
            "resources": ["sentineladmissionguards"],
            "resourceNames": ["sentinelops-workload-write-fence"],
            "verbs": ["get"],
        }
    ]
    assert all(
        "sentineladmissionguards" not in rule.get("resources", [])
        for resource in _resources()
        if resource["kind"] == "Role"
        and resource["metadata"]["name"]
        != "sentinelops-remediation-controller"
        for rule in resource["rules"]
    )
    assert all(
        "namespaces" not in rule.get("resources", [])
        for resource in _resources()
        if resource["kind"] in {"Role", "ClusterRole"}
        and resource["metadata"]["name"]
        != "sentinelops-remediation-controller-admission-integrity"
        for rule in resource["rules"]
    )

    service = _resource(
        "Service",
        "sentinelops-remediation-controller",
        "sentinelops-system",
    )
    assert service["spec"]["ports"][0]["name"] == "metrics"
    service_monitor = _resource(
        "ServiceMonitor",
        "sentinelops-admission-integrity",
        "sentinelops-system",
    )
    assert service_monitor["spec"]["endpoints"][0]["path"] == "/metrics"
    prometheus_rule = _resource(
        "PrometheusRule",
        "sentinelops-admission-integrity",
        "sentinelops-system",
    )
    expressions = [
        rule["expr"]
        for group in prometheus_rule["spec"]["groups"]
        for rule in group["rules"]
    ]
    assert any(
        "min(sentinelops_admission_integrity_healthy)" in item
        for item in expressions
    )
    assert any(
        "min(sentinelops_admission_integrity_last_check_timestamp_seconds)"
        in item
        for item in expressions
    )
    assert any("absent(" in item for item in expressions)


def test_pdb_service_and_ingress_policy_match_deployments() -> None:
    for name in (
        "sentinelops-api",
        "sentinelops-executor",
        "sentinelops-remediation-controller",
        "sentinelops-anchor-publisher",
        "sentinelops-gitops-publisher",
    ):
        pdb = _resource("PodDisruptionBudget", name, "sentinelops-system")
        deployment = _resource("Deployment", name, "sentinelops-system")
        assert pdb["spec"]["minAvailable"] == 1
        assert (
            pdb["spec"]["selector"]["matchLabels"]
            == deployment["spec"]["selector"]["matchLabels"]
        )

    service = _resource("Service", "sentinelops-api", "sentinelops-system")
    assert service["spec"]["ports"] == [
        {
            "name": "http",
            "port": 8000,
            "targetPort": "http",
            "protocol": "TCP",
        }
    ]
    api_policy = _resource(
        "NetworkPolicy",
        "sentinelops-api-ingress",
        "sentinelops-system",
    )
    executor_policy = _resource(
        "NetworkPolicy",
        "sentinelops-executor-deny-ingress",
        "sentinelops-system",
    )
    executor_egress_policy = _resource(
        "NetworkPolicy",
        "sentinelops-executor-egress",
        "sentinelops-system",
    )
    controller_policy = _resource(
        "NetworkPolicy",
        "sentinelops-remediation-controller-ingress",
        "sentinelops-system",
    )
    publisher_policy = _resource(
        "NetworkPolicy",
        "sentinelops-anchor-publisher-deny-ingress",
        "sentinelops-system",
    )
    gitops_policy = _resource(
        "NetworkPolicy",
        "sentinelops-gitops-publisher-deny-ingress",
        "sentinelops-system",
    )
    assert api_policy["spec"]["policyTypes"] == ["Ingress"]
    assert api_policy["spec"]["ingress"][0]["ports"][0]["port"] == 8000
    assert api_policy["spec"]["ingress"][1]["from"][0][
        "namespaceSelector"
    ]["matchLabels"] == {"sentinelops.io/metrics-access": "true"}
    assert executor_policy["spec"]["ingress"] == []
    assert executor_egress_policy["spec"]["policyTypes"] == ["Egress"]
    assert executor_egress_policy["spec"]["podSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": "sentinelops-executor"
    }
    egress = executor_egress_policy["spec"]["egress"]
    assert egress[0]["to"] == [
        {
            "namespaceSelector": {
                "matchLabels": {
                    "kubernetes.io/metadata.name": "kube-system",
                }
            },
            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
        }
    ]
    assert egress[0]["ports"] == [
        {"protocol": "UDP", "port": 53},
        {"protocol": "TCP", "port": 53},
    ]
    assert {
        (
            rule["to"][0]["ipBlock"]["cidr"],
            rule["ports"][0]["protocol"],
            rule["ports"][0]["port"],
        )
        for rule in egress[1:]
    } == {
        ("192.0.2.10/32", "TCP", 443),
        ("198.51.100.10/32", "TCP", 443),
    }
    assert all(
        port["port"] != 5432
        for rule in egress
        for port in rule["ports"]
    )
    assert controller_policy["spec"]["ingress"][0]["ports"] == [
        {"protocol": "TCP", "port": 8080}
    ]
    assert controller_policy["spec"]["ingress"][0]["from"][0][
        "namespaceSelector"
    ]["matchLabels"] == {"sentinelops.io/metrics-access": "true"}
    assert publisher_policy["spec"]["ingress"] == []
    assert gitops_policy["spec"]["ingress"] == []


def test_audit_anchor_monitoring_uses_replica_safe_queries() -> None:
    service_monitor = _resource(
        "ServiceMonitor",
        "sentinelops-audit-anchor",
        "sentinelops-system",
    )
    prometheus_rule = _resource(
        "PrometheusRule",
        "sentinelops-audit-anchor",
        "sentinelops-system",
    )

    endpoint = service_monitor["spec"]["endpoints"][0]
    assert endpoint["port"] == "http"
    assert endpoint["path"] == "/metrics"
    expressions = [
        rule["expr"]
        for group in prometheus_rule["spec"]["groups"]
        for rule in group["rules"]
    ]
    assert any("dead_letter_items" in expression for expression in expressions)
    assert any("integrity_blocked" in expression for expression in expressions)
    assert any("absent(" in expression for expression in expressions)
    replicated_gauges = [
        expression
        for expression in expressions
        if "absent(" not in expression
    ]
    assert all("sum(" not in expression for expression in replicated_gauges)
    assert all("max(" in expression for expression in replicated_gauges)
