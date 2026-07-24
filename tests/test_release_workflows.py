from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"
UPLOAD_ARTIFACT_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_ARTIFACT_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"


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
    assert "continue-on-error: true" in workflow
    assert workflow.count("retention-days: 90") == 3
    assert CHECKOUT_SHA in workflow
    assert SETUP_PYTHON_SHA in workflow
    assert UPLOAD_ARTIFACT_SHA in workflow
    assert DOWNLOAD_ARTIFACT_SHA in workflow
    assert "API_KEY" not in workflow
    assert "MODEL_PROVIDER" not in workflow


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


def test_release_repository_hygiene_is_present() -> None:
    dockerignore = _read(".dockerignore").splitlines()
    license_text = _read("LICENSE")

    assert {".git", ".venv", "artifacts", "web/node_modules"}.issubset(
        dockerignore
    )
    assert len(license_text.splitlines()) > 150
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text
