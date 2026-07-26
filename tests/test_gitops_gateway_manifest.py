from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "deploy" / "gitops-gateway" / "reference.yaml"


def _resources() -> list[dict[str, object]]:
    return [
        document
        for document in yaml.safe_load_all(MANIFEST.read_text())
        if isinstance(document, dict)
    ]


def _resource(kind: str, name: str) -> dict[str, object]:
    matches = [
        item
        for item in _resources()
        if item["kind"] == kind
        and item["metadata"]["name"] == name
    ]
    assert len(matches) == 1
    return matches[0]


def test_reference_gateway_has_no_committed_secret_or_cluster_token() -> None:
    resources = _resources()
    assert all(item["kind"] != "Secret" for item in resources)
    service_account = _resource(
        "ServiceAccount",
        "sentinelops-gitops-gateway",
    )
    deployment = _resource(
        "Deployment",
        "sentinelops-gitops-gateway",
    )
    pod_spec = deployment["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]

    assert service_account["automountServiceAccountToken"] is False
    assert pod_spec["automountServiceAccountToken"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    secret_items = pod_spec["volumes"][0]["projected"]["sources"][0][
        "secret"
    ]["items"]
    assert secret_items == [
        {"key": "gitops-token", "path": "gitops-token"},
        {"key": "gitops-github-token", "path": "gitops-github-token"},
    ]


def test_reference_gateway_only_accepts_publisher_ingress() -> None:
    policy = _resource(
        "NetworkPolicy",
        "sentinelops-gitops-gateway",
    )
    ingress = policy["spec"]["ingress"]

    assert ingress == [
        {
            "from": [
                {
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": (
                                "sentinelops-gitops-publisher"
                            )
                        }
                    }
                }
            ],
            "ports": [{"protocol": "TCP", "port": 8020}],
        }
    ]
