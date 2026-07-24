from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import jwt
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SCRIPT_PATH = SCRIPTS / "topology_readiness.py"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "sentinelops_topology_readiness_script",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
TopologyTrial = MODULE.TopologyTrial
_report = MODULE._report

TOPOLOGY_DIR = ROOT / "deploy" / "topology-e2e"
SECURITY_DIR = ROOT / "deploy" / "security-e2e"


def _trial(**overrides: Any) -> object:
    values: dict[str, Any] = {
        "passed": True,
        "incident_id": "incident-1",
        "incident_status": "resolved",
        "injected_revision": 8,
        "expected_revision": 7,
        "root_cause": "库存服务 revision 8 启用了合成故障",
        "evidence_sources": [
            "kubernetes_logs",
            "loki",
            "prometheus",
        ],
        "failed_trace_id": "trace-1",
        "approving_api_url": "http://127.0.0.1:18100",
        "executor_id": "sentinelops-executor-a:1:attempt-1",
        "action_intents": 1,
        "audit_events": 20,
        "failed_requests_before_recovery": 5,
        "healthy_requests_after_recovery": 10,
        "wrong_remediation_plans": 0,
        "unsafe_writes": 0,
        "timings_ms": {"fault_to_verified_recovery": 1234.0},
        "checks": {
            "two_api_replicas_ready": True,
            "independent_executor_claimed_action": True,
            "strict_recovery_evidence_present": True,
        },
        "database_snapshot": {
            "schema_revision": "0008_anchor_unlock_workflow",
        },
    }
    values.update(overrides)
    return TopologyTrial(**values)


def _resources() -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for path in sorted(TOPOLOGY_DIR.glob("*.yaml")):
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            assert isinstance(document, dict), f"{path} has an empty document"
            if "kind" not in document:
                assert path.name == "alertmanager-patch.yaml"
                continue
            resources.append(document)
    return resources


def _security_resources() -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for path in sorted(SECURITY_DIR.glob("*.yaml")):
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            assert isinstance(document, dict), f"{path} has an empty document"
            if "kind" not in document:
                assert path.name == "runtime-patch.yaml"
                continue
            resources.append(document)
    return resources


def _security_resource(
    kind: str,
    name: str,
    namespace: str,
) -> dict[str, Any]:
    matches = [
        resource
        for resource in _security_resources()
        if resource["kind"] == kind
        and resource["metadata"]["name"] == name
        and resource["metadata"].get("namespace") == namespace
    ]
    assert len(matches) == 1
    return matches[0]


def _resource(kind: str, name: str, namespace: str) -> dict[str, Any]:
    matches = [
        resource
        for resource in _resources()
        if resource["kind"] == kind
        and resource["metadata"]["name"] == name
        and resource["metadata"].get("namespace") == namespace
    ]
    assert len(matches) == 1
    return matches[0]


def test_report_fails_closed_when_any_topology_threshold_is_violated() -> None:
    for trial in (
        _trial(wrong_remediation_plans=1),
        _trial(unsafe_writes=1),
        _trial(action_intents=2),
        _trial(checks={"strict_recovery_evidence_present": False}),
        _trial(passed=False),
    ):
        report = _report(trial, duration_ms=2000)
        assert report["summary"]["passed"] is False


def test_report_uses_separate_schema_for_control_plane_chaos() -> None:
    report = _report(
        _trial(
            chaos={
                "first_executor_generation": 1,
                "final_executor_generation": 2,
            }
        ),
        duration_ms=2000,
    )

    assert report["schema_version"] == ("sentinelops.control-plane-chaos.v1")
    assert report["summary"]["control_plane_chaos"] is True
    assert report["environment"]["control_plane_chaos"] is True


def test_report_uses_separate_schema_for_security_readiness() -> None:
    report = _report(
        _trial(
            security={
                "enabled": True,
                "operator_auth_mode": "oidc",
                "anchor_receiver_id": "kind-security-anchor",
            }
        ),
        duration_ms=2000,
    )

    assert report["schema_version"] == "sentinelops.security-readiness.v1"
    assert report["summary"]["security_e2e"] is True
    assert report["environment"]["security_e2e"] is True
    assert "independently persisted" in report["scope"]


def test_topology_manifests_keep_api_and_executor_separate() -> None:
    resources = _resources()
    assert all(resource["kind"] != "Secret" for resource in resources)

    runtime = _resource(
        "ConfigMap",
        "sentinelops-topology-runtime",
        "sentinelops-system",
    )["data"]
    api = _resource("Deployment", "sentinelops-api", "sentinelops-system")
    executor = _resource(
        "Deployment",
        "sentinelops-executor",
        "sentinelops-system",
    )
    migration = _resource(
        "Job",
        "sentinelops-topology-migrate",
        "sentinelops-system",
    )

    assert runtime["SENTINELOPS_ENVIRONMENT"] == "staging"
    assert runtime["SENTINELOPS_EXECUTOR_MODE"] == "external"
    assert runtime["SENTINELOPS_DATABASE_AUTO_CREATE"] == "false"
    assert runtime["SENTINELOPS_ALERTMANAGER_WEBHOOK_AUTH_MODE"] == "bearer"
    assert api["spec"]["replicas"] == 2
    assert executor["spec"]["replicas"] == 2
    assert api["spec"]["template"]["spec"]["serviceAccountName"] == "sentinelops-api"
    assert executor["spec"]["template"]["spec"]["serviceAccountName"] == "sentinelops-executor"
    assert migration["spec"]["template"]["spec"]["automountServiceAccountToken"] is False

    executor_container = executor["spec"]["template"]["spec"]["containers"][0]
    for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
        assert executor_container[probe_name]["timeoutSeconds"] >= 5


def test_topology_rbac_keeps_api_readonly_and_executor_narrowly_writable() -> None:
    api_role = _resource(
        "Role",
        "sentinelops-topology-api-readonly",
        "sentinelops-demo",
    )
    executor_role = _resource(
        "Role",
        "sentinelops-topology-executor-write",
        "sentinelops-demo",
    )

    api_verbs = {verb for rule in api_role["rules"] for verb in rule["verbs"]}
    executor_resources = {
        resource for rule in executor_role["rules"] for resource in rule["resources"]
    }
    assert api_verbs <= {"get", "list", "watch"}
    assert "secrets" not in executor_resources
    assert executor_resources <= {
        "deployments",
        "deployments/status",
        "deployments/scale",
        "replicasets",
    }


def test_alertmanager_uses_authenticated_in_cluster_webhook() -> None:
    config = _resource(
        "ConfigMap",
        "alertmanager-config",
        "sentinelops-demo",
    )["data"]["alertmanager.yml"]
    parsed = yaml.safe_load(config)
    webhook = parsed["receivers"][0]["webhook_configs"][0]

    assert webhook["url"].startswith("http://sentinelops-api.sentinelops-system.svc.cluster.local:")
    assert webhook["send_resolved"] is True
    assert (
        webhook["http_config"]["authorization"]["credentials_file"]
        == "/etc/sentinelops-webhook/token"
    )
    patch = yaml.safe_load((TOPOLOGY_DIR / "alertmanager-patch.yaml").read_text(encoding="utf-8"))
    secret = patch["spec"]["template"]["spec"]["volumes"][0]["secret"]
    assert secret["secretName"] == "sentinelops-topology-webhook"
    assert secret["defaultMode"] == 0o444


def test_observability_bootstrap_preloads_every_runtime_image() -> None:
    script = (SCRIPTS / "observability-up.sh").read_text(encoding="utf-8")

    for image in (
        "prom/prometheus:v3.13.1",
        "prom/alertmanager:v0.28.1",
        "grafana/loki:3.7.3",
        "grafana/tempo:3.0.2",
        "otel/opentelemetry-collector-contrib:0.156.0",
    ):
        assert image in script
    assert 'for observability_image in "${OBSERVABILITY_IMAGES[@]}"' in script
    assert "ctr --namespace=k8s.io images import" in script


def test_runtime_image_installs_dependencies_before_copying_source() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    dependency_install = dockerfile.index("config['project']['dependencies']")
    source_copy = dockerfile.index("COPY src ./src")
    package_install = dockerfile.index("pip install --no-deps .")
    assert dependency_install < source_copy < package_install


def test_security_manifests_separate_identity_and_anchor_trust_domains() -> None:
    resources = _security_resources()
    assert all(resource["kind"] != "Secret" for resource in resources)

    runtime_patch = yaml.safe_load(
        (SECURITY_DIR / "runtime-patch.yaml").read_text(encoding="utf-8")
    )["data"]
    anchor = _security_resource(
        "Deployment",
        "anchor-service",
        "sentinelops-security",
    )
    publisher = _security_resource(
        "Deployment",
        "sentinelops-anchor-publisher",
        "sentinelops-system",
    )
    jwks = _security_resource(
        "Deployment",
        "oidc-jwks",
        "sentinelops-security",
    )

    assert runtime_patch["SENTINELOPS_OPERATOR_AUTH_MODE"] == "oidc"
    assert runtime_patch["SENTINELOPS_AUDIT_ANCHOR_ENFORCEMENT_REQUIRED"] == "true"
    assert "sentinelops-security.svc.cluster.local" in (runtime_patch["SENTINELOPS_OIDC_JWKS_URL"])
    assert anchor["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    assert jwks["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    assert publisher["spec"]["replicas"] == 2
    assert publisher["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    publisher_container = publisher["spec"]["template"]["spec"]["containers"][0]
    for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
        assert (
            publisher_container[probe_name]["exec"]["command"][0]
            == "sentinelops-anchor-health"
        )

    publisher_env = {
        item["name"]: item for item in publisher_container["env"]
    }
    assert publisher_env["SENTINELOPS_AUDIT_ANCHOR_SOURCE_ID"]["value"] == ("kind-security-e2e")
    assert (
        publisher_env["SENTINELOPS_AUDIT_ANCHOR_TRUSTED_RECEIVER_ID"]["value"]
        == "kind-security-anchor"
    )
    assert "secretKeyRef" in publisher_env["SENTINELOPS_AUDIT_ANCHOR_BEARER_TOKEN"]["valueFrom"]


def test_security_material_generator_uses_ephemeral_asymmetric_keys(
    tmp_path: Path,
) -> None:
    output = tmp_path / "material"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "generate_security_e2e_material.py"),
            "--output-dir",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        check=True,
        text=True,
    )

    assert result.stdout == ""
    assert result.stderr == ""
    assert stat.S_IMODE((output / "viewer.jwt").stat().st_mode) == 0o600
    assert stat.S_IMODE((output / "anchor-private.pem").stat().st_mode) == 0o600
    assert (output / "anchor-delivery.token").read_text() != (
        output / "anchor-inventory.token"
    ).read_text()

    jwks = json.loads((output / "jwks.json").read_text())
    public_key = jwt.PyJWK.from_dict(jwks["keys"][0]).key
    viewer = jwt.decode(
        (output / "viewer.jwt").read_text().strip(),
        key=public_key,
        algorithms=["RS256"],
        audience="sentinelops-api",
        issuer="http://oidc-jwks.sentinelops-security.svc.cluster.local:8080",
    )
    approver = jwt.decode(
        (output / "approver.jwt").read_text().strip(),
        key=public_key,
        algorithms=["RS256"],
        audience="sentinelops-api",
        issuer="http://oidc-jwks.sentinelops-security.svc.cluster.local:8080",
    )
    invalid = jwt.decode(
        (output / "invalid.jwt").read_text().strip(),
        key=public_key,
        algorithms=["RS256"],
        options={"verify_aud": False},
        issuer="http://oidc-jwks.sentinelops-security.svc.cluster.local:8080",
    )

    assert viewer["roles"] == ["sentinelops.incident.view"]
    assert "sentinelops.incident.approve" in approver["roles"]
    assert invalid["aud"] == "wrong-audience"
    assert "PRIVATE" not in (output / "anchor-public-keys.json").read_text()


def test_committed_topology_report_is_machine_readable_and_secret_free() -> None:
    report_path = ROOT / "benchmarks" / "topology-readiness.json"
    raw = report_path.read_text(encoding="utf-8")
    report = json.loads(raw)

    assert report["schema_version"] == "sentinelops.topology-readiness.v1"
    assert report["summary"]["passed"] is True
    assert report["summary"]["wrong_remediation_plans"] == 0
    assert report["summary"]["unsafe_writes"] == 0
    assert report["summary"]["action_intents"] == 1
    assert report["trial"]["checks"]
    assert all(report["trial"]["checks"].values())
    assert report["trial"]["database_snapshot"]["approval_status"] == "approved"
    assert report["trial"]["database_snapshot"]["alert_binding_status"] == "resolved"
    assert "api_key" not in raw.casefold()
    assert "authorization" not in raw.casefold()
    assert "password" not in raw.casefold()
    assert "bearer" not in raw.casefold()


def test_committed_control_plane_chaos_report_proves_fenced_takeover() -> None:
    report_path = ROOT / "benchmarks" / "control-plane-chaos.json"
    raw = report_path.read_text(encoding="utf-8")
    report = json.loads(raw)
    trial = report["trial"]
    snapshot = trial["database_snapshot"]
    chaos = trial["chaos"]

    assert report["schema_version"] == ("sentinelops.control-plane-chaos.v1")
    assert report["summary"]["passed"] is True
    assert report["summary"]["wrong_remediation_plans"] == 0
    assert report["summary"]["unsafe_writes"] == 0
    assert len(trial["checks"]) >= 25
    assert all(trial["checks"].values())
    assert len(snapshot["action_intents"]) == 1
    assert snapshot["action_intents"][0]["status"] == "succeeded"
    assert snapshot["action_intents"][0]["executor_generation"] == 2
    assert len(snapshot["action_claim_events"]) == 2
    assert len(snapshot["action_requeue_events"]) == 1
    assert chaos["first_executor_generation"] == 1
    assert chaos["final_executor_generation"] == 2
    assert chaos["first_executor_id"] != chaos["final_executor_id"]
    assert "api_key" not in raw.casefold()
    assert "authorization" not in raw.casefold()
    assert "password" not in raw.casefold()
    assert "bearer" not in raw.casefold()


def test_committed_security_report_proves_identity_and_external_anchor() -> None:
    report_path = ROOT / "benchmarks" / "security-readiness.json"
    raw = report_path.read_text(encoding="utf-8")
    report = json.loads(raw)
    trial = report["trial"]
    snapshot = trial["database_snapshot"]

    assert report["schema_version"] == "sentinelops.security-readiness.v1"
    assert report["summary"]["passed"] is True
    assert report["summary"]["security_e2e"] is True
    assert all(trial["checks"].values())
    assert trial["checks"]["missing_operator_token_rejected"] is True
    assert trial["checks"]["invalid_oidc_token_rejected"] is True
    assert trial["checks"]["viewer_cannot_approve"] is True
    assert trial["checks"]["verified_oidc_approval_audited"] is True
    assert trial["checks"]["anchor_gate_started_blocked"] is True
    assert trial["checks"]["anchor_outage_failed_closed"] is True
    assert trial["checks"]["anchor_gate_remained_healthy"] is True
    assert (
        snapshot["anchor_outbox_total"]
        == snapshot["audit_events"]
        == snapshot["audit_head_sequence"]
    )
    assert snapshot["anchor_outbox_undelivered"] == 0
    assert trial["security"]["operator_auth_mode"] == "oidc"
    assert trial["security"]["anchor_receiver_id"] == "kind-security-anchor"
    assert "api_key" not in raw.casefold()
    assert "authorization" not in raw.casefold()
    assert "password" not in raw.casefold()
    assert "bearer" not in raw.casefold()
    assert ".jwt" not in raw.casefold()
