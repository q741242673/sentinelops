from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"
UPLOAD_ARTIFACT_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_ARTIFACT_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
ATTEST_SHA = "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"
BUILD_PUSH_SHA = "53b7df96c91f9c12dcc8a07bcb9ccacbed38856a"
COSIGN_INSTALLER_SHA = "faadad0cce49287aee09b3a48701e75088a2c6ad"
SBOM_SHA = "e22c389904149dbc22b58101806040fa8d37a610"


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_soak_workflow_is_bounded_fail_closed_and_keeps_evidence() -> None:
    workflow = _read(".github/workflows/soak.yml")

    assert "workflow_dispatch:" in workflow
    assert "schedule:" in workflow
    assert 'default: "20"' in workflow
    assert 'default: "100"' in workflow
    assert "cancel-in-progress: false" in workflow
    assert "python scripts/soak_gate.py" in workflow
    assert "topology-stability:" in workflow
    assert "--topology-report" in workflow
    assert "--chaos-report" in workflow
    assert "--max-p95-executor-takeover-ms 45000" in workflow
    assert '--expected-git-commit "$GITHUB_SHA"' in workflow
    assert '--expected-github-run-id "$GITHUB_RUN_ID"' in workflow
    assert "SENTINELOPS_REPORT_GIT_COMMIT" in workflow
    assert "SENTINELOPS_REPORT_GITHUB_RUN_ID" in workflow
    assert "continue-on-error: true" in workflow
    assert workflow.count("retention-days: 90") == 4
    assert "--retry 5" in workflow
    assert "--retry-all-errors" in workflow
    assert "--max-time 180" in workflow
    assert "sha256sum --check" in workflow
    assert (
        "50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54"
        in workflow
    )
    assert CHECKOUT_SHA in workflow
    assert SETUP_PYTHON_SHA in workflow
    assert UPLOAD_ARTIFACT_SHA in workflow
    assert DOWNLOAD_ARTIFACT_SHA in workflow
    assert "API_KEY" not in workflow
    assert "MODEL_PROVIDER" not in workflow


def test_kubernetes_report_entrypoints_bind_running_image_identity() -> None:
    for path in (
        "scripts/e2e-observability.sh",
        "scripts/run-kubernetes-readiness.sh",
    ):
        script = _read(path)
        report_call = script.index("scripts/kubernetes_readiness.py")
        for variable in (
            "SENTINELOPS_REPORT_IMAGE_REFERENCE",
            "SENTINELOPS_REPORT_IMAGE_BUILD_DIGEST",
            "SENTINELOPS_REPORT_RUNNING_IMAGE_IDS",
        ):
            assert script.index(f"export {variable}") < report_call
        assert ".status.containerStatuses[*]}{.imageID}" in script


def test_release_candidate_workflow_builds_without_publishing() -> None:
    workflow = _read(".github/workflows/release-candidate.yml")

    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "schedule:" not in workflow
    assert "python scripts/release_version.py" in workflow
    assert "python -m build" in workflow
    assert "sha256sum * > SHA256SUMS" in workflow
    assert '"git_commit": os.environ["GITHUB_SHA"]' in workflow
    assert "retention-days: 90" in workflow
    assert "docker push" not in workflow
    assert "gh release" not in workflow
    assert "contents: write" not in workflow


def test_tag_release_is_fail_closed_signed_and_attested() -> None:
    workflow = _read(".github/workflows/release.yml")

    assert 'tags:\n      - "v*"' in workflow
    assert "workflow_dispatch:" not in workflow
    assert "branches:" not in workflow
    assert "cancel-in-progress: false" in workflow
    assert "git merge-base --is-ancestor" in workflow
    assert "actions/workflows/soak.yml/runs?status=success" in workflow
    assert 'select(.head_sha == \\"${GITHUB_SHA}\\")' in workflow
    assert "--release-version \"$release_version\"" in workflow
    assert "Refuse to overwrite an existing RC image tag" in workflow
    assert "platforms: linux/amd64" in workflow
    assert "provenance: mode=max" in workflow
    assert "sbom: true" in workflow
    assert "push-to-registry: true" in workflow
    assert "cosign sign --yes" in workflow
    assert "cosign verify" in workflow
    assert "python scripts/release_manifest.py" in workflow
    assert "gh release create" in workflow
    assert "--prerelease" in workflow
    assert ":latest" not in workflow
    assert workflow.index("cosign verify") < workflow.index("gh release create")
    assert workflow.index("release_manifest.py") < workflow.index("gh release create")
    assert workflow.count(ATTEST_SHA) == 3
    assert BUILD_PUSH_SHA in workflow
    assert COSIGN_INSTALLER_SHA in workflow
    assert SBOM_SHA in workflow
    assert CHECKOUT_SHA in workflow
    assert SETUP_PYTHON_SHA in workflow
    assert UPLOAD_ARTIFACT_SHA in workflow


def test_release_repository_hygiene_is_present() -> None:
    dockerignore = _read(".dockerignore").splitlines()
    license_text = _read("LICENSE")

    assert {".git", ".venv", "artifacts", "web/node_modules"}.issubset(
        dockerignore
    )
    assert len(license_text.splitlines()) > 150
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text
