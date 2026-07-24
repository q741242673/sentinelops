from __future__ import annotations

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


def _resource(kind: str, name: str, namespace: str) -> dict[str, Any]:
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
    assert all(item["kind"] not in {"ClusterRole", "ClusterRoleBinding"} for item in resources)


def test_runtime_configuration_fails_closed_for_production() -> None:
    runtime = _resource("ConfigMap", "sentinelops-runtime", "sentinelops-system")["data"]
    api = _resource("ConfigMap", "sentinelops-api", "sentinelops-system")["data"]
    anchor = _resource(
        "ConfigMap",
        "sentinelops-anchor",
        "sentinelops-system",
    )["data"]

    assert runtime["SENTINELOPS_ENVIRONMENT"] == "production"
    assert runtime["SENTINELOPS_TOOL_BACKEND"] == "kubernetes"
    assert runtime["SENTINELOPS_DATABASE_AUTO_CREATE"] == "false"
    assert runtime["SENTINELOPS_EXECUTOR_MODE"] == "external"
    assert runtime["SENTINELOPS_DATABASE_URL_FILE"].startswith("/var/run/secrets/")
    assert runtime["SENTINELOPS_AUDIT_HMAC_KEY_FILE"].startswith(
        "/var/run/secrets/"
    )
    assert runtime["SENTINELOPS_AUDIT_KEY_ID"] != "development-unkeyed"
    assert runtime["SENTINELOPS_AUDIT_ANCHOR_ENFORCEMENT_REQUIRED"] == "true"
    assert api["SENTINELOPS_DEMO_ENABLED"] == "false"
    assert api["SENTINELOPS_ALERTMANAGER_WEBHOOK_AUTH_MODE"] != "disabled"
    assert api["SENTINELOPS_MODEL_API_KEY_FILE"].startswith("/var/run/secrets/")
    assert api["SENTINELOPS_ALERTMANAGER_WEBHOOK_BEARER_TOKEN_FILE"].startswith(
        "/var/run/secrets/"
    )
    assert api["SENTINELOPS_OPERATOR_AUTH_MODE"] == "oidc"
    assert api["SENTINELOPS_OIDC_ISSUER"].startswith("https://")
    assert api["SENTINELOPS_OIDC_AUDIENCE"] == "sentinelops-api"
    assert api["SENTINELOPS_OIDC_JWKS_URL"].startswith("https://")
    assert api["SENTINELOPS_OIDC_HUMAN_VALUE"] == "human"
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


def test_runtime_components_are_separate_hardened_deployments() -> None:
    api = _resource("Deployment", "sentinelops-api", "sentinelops-system")
    executor = _resource("Deployment", "sentinelops-executor", "sentinelops-system")
    publisher = _resource(
        "Deployment",
        "sentinelops-anchor-publisher",
        "sentinelops-system",
    )

    assert api["spec"]["replicas"] >= 2
    assert executor["spec"]["replicas"] >= 2
    assert publisher["spec"]["replicas"] >= 2
    assert api["spec"]["template"]["spec"]["serviceAccountName"] == "sentinelops-api"
    assert (
        executor["spec"]["template"]["spec"]["serviceAccountName"]
        == "sentinelops-executor"
    )
    assert (
        publisher["spec"]["template"]["spec"]["serviceAccountName"]
        == "sentinelops-anchor-publisher"
    )
    assert publisher["spec"]["template"]["spec"]["automountServiceAccountToken"] is False

    api_container = _container(api)
    executor_container = _container(executor)
    publisher_container = _container(publisher)
    assert api_container["livenessProbe"]["httpGet"]["path"] == "/health"
    assert api_container["readinessProbe"]["httpGet"]["path"] == "/ready"
    assert api_container["startupProbe"]["httpGet"]["path"] == "/health"
    assert "executor-health" in executor_container["livenessProbe"]["exec"]["command"]
    assert "executor-health" in executor_container["readinessProbe"]["exec"]["command"]
    assert "anchor-health" in publisher_container["livenessProbe"]["exec"]["command"]
    assert "anchor-health" in publisher_container["readinessProbe"]["exec"]["command"]
    assert executor_container["startupProbe"]["timeoutSeconds"] >= 5
    assert publisher_container["startupProbe"]["timeoutSeconds"] >= 5
    assert api_container["image"] == executor_container["image"] == publisher_container["image"]

    for deployment in (api, executor, publisher):
        pod_spec = deployment["spec"]["template"]["spec"]
        container = _container(deployment)
        assert pod_spec["securityContext"]["runAsNonRoot"] is True
        assert pod_spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
        assert container["resources"]["requests"]
        assert container["resources"]["limits"]

    executor_secret_items = executor["spec"]["template"]["spec"]["volumes"][0][
        "projected"
    ]["sources"][0]["secret"]["items"]
    assert executor_secret_items == [
        {"key": "database-url", "path": "database-url"},
        {"key": "audit-hmac-key", "path": "audit-hmac-key"},
    ]
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


def test_rbac_keeps_api_readonly_and_executor_narrowly_writable() -> None:
    api_role = _resource("Role", "sentinelops-api-readonly", "sentinelops-workloads")
    executor_role = _resource(
        "Role",
        "sentinelops-executor-write",
        "sentinelops-workloads",
    )

    api_verbs = {verb for rule in api_role["rules"] for verb in rule["verbs"]}
    api_resources = {
        resource for rule in api_role["rules"] for resource in rule["resources"]
    }
    assert api_verbs <= {"get", "list", "watch"}
    assert "secrets" not in api_resources

    executor_resources = {
        resource
        for rule in executor_role["rules"]
        for resource in rule["resources"]
    }
    assert executor_resources <= {
        "deployments",
        "deployments/status",
        "deployments/scale",
        "replicasets",
    }
    assert "secrets" not in executor_resources
    assert any(
        {"patch", "update"} <= set(rule["verbs"])
        for rule in executor_role["rules"]
        if "deployments" in rule["resources"]
    )

    api_binding = _resource(
        "RoleBinding",
        "sentinelops-api-readonly",
        "sentinelops-workloads",
    )
    executor_binding = _resource(
        "RoleBinding",
        "sentinelops-executor-write",
        "sentinelops-workloads",
    )
    assert api_binding["subjects"][0] == {
        "kind": "ServiceAccount",
        "name": "sentinelops-api",
        "namespace": "sentinelops-system",
    }
    assert executor_binding["subjects"][0] == {
        "kind": "ServiceAccount",
        "name": "sentinelops-executor",
        "namespace": "sentinelops-system",
    }
    bound_service_accounts = {
        subject["name"]
        for item in _resources()
        if item["kind"] in {"RoleBinding", "ClusterRoleBinding"}
        for subject in item.get("subjects", [])
        if subject.get("kind") == "ServiceAccount"
    }
    assert "sentinelops-anchor-publisher" not in bound_service_accounts


def test_pdb_service_and_ingress_policy_match_deployments() -> None:
    for name in (
        "sentinelops-api",
        "sentinelops-executor",
        "sentinelops-anchor-publisher",
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
    publisher_policy = _resource(
        "NetworkPolicy",
        "sentinelops-anchor-publisher-deny-ingress",
        "sentinelops-system",
    )
    assert api_policy["spec"]["policyTypes"] == ["Ingress"]
    assert api_policy["spec"]["ingress"][0]["ports"][0]["port"] == 8000
    assert api_policy["spec"]["ingress"][1]["from"][0][
        "namespaceSelector"
    ]["matchLabels"] == {"sentinelops.io/metrics-access": "true"}
    assert executor_policy["spec"]["ingress"] == []
    assert publisher_policy["spec"]["ingress"] == []


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
