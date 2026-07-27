from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sentinelops.report_provenance import build_report_provenance

COMMIT_A = "a" * 40
DIGEST_A = f"sha256:{'1' * 64}"
DIGEST_B = f"sha256:{'2' * 64}"


@pytest.fixture(autouse=True)
def _clear_report_environment(monkeypatch) -> None:
    for name in (
        "SENTINELOPS_REPORT_GIT_COMMIT",
        "SENTINELOPS_REPORT_GIT_REF",
        "SENTINELOPS_REPORT_REPOSITORY",
        "SENTINELOPS_REPORT_GITHUB_RUN_ID",
        "SENTINELOPS_REPORT_GITHUB_RUN_ATTEMPT",
        "SENTINELOPS_REPORT_GITHUB_SERVER_URL",
        "SENTINELOPS_REPORT_GITHUB_JOB",
        "SENTINELOPS_REPORT_IMAGE_REFERENCE",
        "SENTINELOPS_REPORT_IMAGE_BUILD_DIGEST",
        "SENTINELOPS_REPORT_RUNNING_IMAGE_IDS",
        "GITHUB_SHA",
        "GITHUB_REF",
        "GITHUB_REPOSITORY",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SERVER_URL",
        "GITHUB_JOB",
    ):
        monkeypatch.delenv(name, raising=False)


def _repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repository"
    root.mkdir()
    subprocess.run(("git", "init", str(root)), check=True, capture_output=True)
    subprocess.run(
        ("git", "-C", str(root), "config", "user.email", "test@example.test"),
        check=True,
    )
    subprocess.run(
        ("git", "-C", str(root), "config", "user.name", "SentinelOps Test"),
        check=True,
    )
    (root / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(
        ("git", "-C", str(root), "add", "tracked.txt"),
        check=True,
    )
    subprocess.run(
        ("git", "-C", str(root), "commit", "-m", "baseline"),
        check=True,
        capture_output=True,
    )
    commit = subprocess.run(
        ("git", "-C", str(root), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return root, commit


def _github_environment(monkeypatch, commit: str) -> None:
    values = {
        "SENTINELOPS_REPORT_GIT_COMMIT": commit,
        "SENTINELOPS_REPORT_GIT_REF": "refs/pull/42/merge",
        "SENTINELOPS_REPORT_REPOSITORY": "q741242673/sentinelops",
        "SENTINELOPS_REPORT_GITHUB_RUN_ID": "30244957352",
        "SENTINELOPS_REPORT_GITHUB_RUN_ATTEMPT": "2",
        "SENTINELOPS_REPORT_GITHUB_SERVER_URL": "https://github.com",
        "SENTINELOPS_REPORT_GITHUB_JOB": "observability-e2e",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_github_report_binds_checkout_run_and_running_image(
    tmp_path,
    monkeypatch,
) -> None:
    root, commit = _repository(tmp_path)
    _github_environment(monkeypatch, commit)
    monkeypatch.setenv(
        "SENTINELOPS_REPORT_IMAGE_REFERENCE",
        "sentinelops:topology-e2e",
    )
    monkeypatch.setenv(
        "SENTINELOPS_REPORT_IMAGE_BUILD_DIGEST",
        DIGEST_A,
    )
    monkeypatch.setenv(
        "SENTINELOPS_REPORT_RUNNING_IMAGE_IDS",
        f"docker.io/library/sentinelops@{DIGEST_B}",
    )

    report = build_report_provenance(
        root,
        require_ci=True,
        require_container=True,
    )

    assert report["source"] == {
        "repository": "q741242673/sentinelops",
        "commit": commit,
        "ref": "refs/pull/42/merge",
        "dirty": False,
    }
    assert report["execution"]["run_id"] == 30244957352
    assert report["execution"]["run_attempt"] == 2
    assert report["execution"]["run_url"].endswith(
        "/q741242673/sentinelops/actions/runs/30244957352"
    )
    container = report["subjects"][1]
    assert container["build_image_digest"] == DIGEST_A
    assert container["running_image_ids"] == [DIGEST_B]
    assert all(report["checks"].values())


def test_report_rejects_commit_that_does_not_match_checkout(
    tmp_path,
    monkeypatch,
) -> None:
    root, commit = _repository(tmp_path)
    _github_environment(monkeypatch, commit)
    monkeypatch.setenv("SENTINELOPS_REPORT_GIT_COMMIT", COMMIT_A)

    with pytest.raises(ValueError, match="does not match"):
        build_report_provenance(root, require_ci=True)


def test_report_rejects_incomplete_ci_or_container_identity(
    tmp_path,
    monkeypatch,
) -> None:
    root, commit = _repository(tmp_path)
    monkeypatch.setenv("SENTINELOPS_REPORT_GIT_COMMIT", commit)
    monkeypatch.setenv(
        "SENTINELOPS_REPORT_REPOSITORY",
        "q741242673/sentinelops",
    )
    with pytest.raises(ValueError, match="incomplete"):
        build_report_provenance(root, require_ci=True)

    _github_environment(monkeypatch, commit)
    monkeypatch.setenv(
        "SENTINELOPS_REPORT_IMAGE_REFERENCE",
        "sentinelops:topology-e2e",
    )
    with pytest.raises(ValueError, match="container.*incomplete"):
        build_report_provenance(root, require_container=True)


def test_report_rejects_replicas_with_different_running_images(
    tmp_path,
    monkeypatch,
) -> None:
    root, commit = _repository(tmp_path)
    _github_environment(monkeypatch, commit)
    monkeypatch.setenv(
        "SENTINELOPS_REPORT_IMAGE_REFERENCE",
        "sentinelops:topology-e2e",
    )
    monkeypatch.setenv(
        "SENTINELOPS_REPORT_IMAGE_BUILD_DIGEST",
        DIGEST_A,
    )
    monkeypatch.setenv(
        "SENTINELOPS_REPORT_RUNNING_IMAGE_IDS",
        f"{DIGEST_A},{DIGEST_B}",
    )

    with pytest.raises(ValueError, match="one immutable"):
        build_report_provenance(
            root,
            require_ci=True,
            require_container=True,
        )


def test_local_report_marks_tracked_checkout_changes(
    tmp_path,
) -> None:
    root, _commit = _repository(tmp_path)
    (root / "tracked.txt").write_text("changed\n", encoding="utf-8")

    report = build_report_provenance(root)

    assert report["execution"]["provider"] == "local"
    assert report["source"]["dirty"] is True
    assert report["checks"]["tracked_checkout_clean"] is False
