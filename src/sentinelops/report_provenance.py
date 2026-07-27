from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _environment(name: str, fallback: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None and fallback is not None:
        value = os.getenv(fallback)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return completed.stdout.strip()


def _normalise_sha256(value: str) -> str:
    candidate = value.strip().casefold()
    if "@sha256:" in candidate:
        candidate = f"sha256:{candidate.rsplit('@sha256:', 1)[1]}"
    elif candidate.startswith(("docker://sha256:", "containerd://sha256:")):
        candidate = candidate.split("://", 1)[1]
    if not _SHA256.fullmatch(candidate):
        raise ValueError("report container identity must be a sha256 digest")
    return candidate


def _positive_integer(value: str | None, *, name: str) -> int | None:
    if value is None:
        return None
    if not value.isdecimal() or int(value) <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return int(value)


def build_report_provenance(
    root: Path,
    *,
    require_ci: bool = False,
    require_container: bool = False,
) -> dict[str, Any]:
    """Bind a report to the exact checkout, CI execution and running image."""

    root = root.resolve()
    checkout_commit = _git(root, "rev-parse", "HEAD").casefold()
    if not _GIT_COMMIT.fullmatch(checkout_commit):
        raise ValueError("git checkout did not resolve to a full commit")
    declared_commit = (
        _environment("SENTINELOPS_REPORT_GIT_COMMIT", "GITHUB_SHA")
        or checkout_commit
    ).casefold()
    if not _GIT_COMMIT.fullmatch(declared_commit):
        raise ValueError("report git commit must be a full lowercase SHA")
    if declared_commit != checkout_commit:
        raise ValueError("report git commit does not match the tested checkout")

    repository = _environment(
        "SENTINELOPS_REPORT_REPOSITORY",
        "GITHUB_REPOSITORY",
    )
    if repository is not None and not _REPOSITORY.fullmatch(repository):
        raise ValueError("report repository must use owner/name form")
    ref = _environment("SENTINELOPS_REPORT_GIT_REF", "GITHUB_REF")
    dirty = bool(_git(root, "status", "--short", "--untracked-files=no"))

    run_id = _positive_integer(
        _environment("SENTINELOPS_REPORT_GITHUB_RUN_ID", "GITHUB_RUN_ID"),
        name="GitHub run ID",
    )
    run_attempt = _positive_integer(
        _environment(
            "SENTINELOPS_REPORT_GITHUB_RUN_ATTEMPT",
            "GITHUB_RUN_ATTEMPT",
        ),
        name="GitHub run attempt",
    )
    job = _environment("SENTINELOPS_REPORT_GITHUB_JOB", "GITHUB_JOB")
    server_url = _environment(
        "SENTINELOPS_REPORT_GITHUB_SERVER_URL",
        "GITHUB_SERVER_URL",
    )
    ci_values = (run_id, run_attempt, repository, server_url)
    ci_present = any(value is not None for value in ci_values)
    if ci_present and not all(value is not None for value in ci_values):
        raise ValueError("GitHub report provenance is incomplete")
    if require_ci and not all(value is not None for value in ci_values):
        raise ValueError("GitHub report provenance is required")
    if ci_present and server_url != "https://github.com":
        raise ValueError("GitHub report server URL is not trusted")
    if ci_present and dirty:
        raise ValueError("CI report checkout contains tracked modifications")

    image_reference = _environment("SENTINELOPS_REPORT_IMAGE_REFERENCE")
    build_digest_raw = _environment(
        "SENTINELOPS_REPORT_IMAGE_BUILD_DIGEST"
    )
    running_ids_raw = _environment(
        "SENTINELOPS_REPORT_RUNNING_IMAGE_IDS"
    )
    container_present = any(
        value is not None
        for value in (image_reference, build_digest_raw, running_ids_raw)
    )
    if container_present and not all(
        value is not None
        for value in (image_reference, build_digest_raw, running_ids_raw)
    ):
        raise ValueError("container report provenance is incomplete")
    if require_container and not container_present:
        raise ValueError("container report provenance is required")

    container_subject: dict[str, Any] | None = None
    if container_present:
        assert image_reference is not None
        assert build_digest_raw is not None
        assert running_ids_raw is not None
        build_digest = _normalise_sha256(build_digest_raw)
        running_ids = sorted(
            {
                _normalise_sha256(value)
                for value in running_ids_raw.split(",")
                if value.strip()
            }
        )
        if not running_ids:
            raise ValueError("running container image identities are empty")
        if len(running_ids) != 1:
            raise ValueError(
                "tested replicas did not run one immutable container image"
            )
        container_subject = {
            "kind": "container_image",
            "reference": image_reference,
            "build_image_digest": build_digest,
            "running_image_ids": running_ids,
            "digest_semantics": {
                "build_image_digest": "docker_local_image_id",
                "running_image_ids": "kubernetes_runtime_image_id",
            },
        }

    execution: dict[str, Any]
    if ci_present:
        assert server_url is not None
        assert repository is not None
        assert run_id is not None
        execution = {
            "provider": "github_actions",
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job": job,
            "run_url": f"{server_url}/{repository}/actions/runs/{run_id}",
        }
    else:
        execution = {
            "provider": "local",
            "run_id": None,
            "run_attempt": None,
            "job": None,
            "run_url": None,
        }

    subjects: list[dict[str, Any]] = [
        {
            "kind": "git_checkout",
            "digest": {
                "algorithm": "git-sha1",
                "value": checkout_commit,
            },
        }
    ]
    if container_subject is not None:
        subjects.append(container_subject)
    return {
        "schema_version": "sentinelops.report-provenance.v1",
        "source": {
            "repository": repository,
            "commit": checkout_commit,
            "ref": ref,
            "dirty": dirty,
        },
        "execution": execution,
        "subjects": subjects,
        "checks": {
            "commit_matches_checkout": declared_commit == checkout_commit,
            "tracked_checkout_clean": not dirty,
            "running_replicas_use_one_image": (
                container_subject is None
                or len(container_subject["running_image_ids"]) == 1
            ),
        },
    }
