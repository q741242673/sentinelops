from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sentinelops.domain import ToolResult
from sentinelops.tools.change import GitChangeBackend


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def commit(repository: Path, name: str, content: str) -> str:
    (repository / name).write_text(content, encoding="utf-8")
    git(repository, "add", name)
    git(repository, "commit", "-m", f"update {name}")
    return git(repository, "rev-parse", "HEAD")


class RolloutBackend:
    def __init__(self, previous_sha: str, current_sha: str) -> None:
        self.previous_sha = previous_sha
        self.current_sha = current_sha

    async def call(self, name: str, arguments: dict) -> ToolResult:
        assert name == "get_rollout_history"
        return ToolResult(
            tool_name=name,
            success=True,
            content={
                "deployment": arguments["name"],
                "revisions": [
                    {
                        "revision": 1,
                        "replicas": 0,
                        "ready_replicas": 0,
                        "git_commit": self.previous_sha,
                    },
                    {
                        "revision": 2,
                        "replicas": 1,
                        "ready_replicas": 1,
                        "git_commit": self.current_sha,
                    },
                ],
            },
        )


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str, str]:
    git(tmp_path, "init")
    git(tmp_path, "config", "user.email", "sentinelops@example.test")
    git(tmp_path, "config", "user.name", "SentinelOps Test")
    previous_sha = commit(tmp_path, "service.txt", "healthy\n")
    current_sha = commit(tmp_path, "service.txt", "faulty\n")
    return tmp_path.resolve(), previous_sha, current_sha


@pytest.mark.asyncio
async def test_change_backend_verifies_rollout_commits_and_diff(
    repository: tuple[Path, str, str],
) -> None:
    path, previous_sha, current_sha = repository
    backend = GitChangeBackend(
        str(path), RolloutBackend(previous_sha, current_sha), history_limit=5
    )

    result = await backend.call("get_change_evidence", {"service": "order-service"})

    assert result.success is True
    assert result.content["correlation_status"] == "verified"
    assert result.content["current_commit"]["sha"] == current_sha
    assert result.content["previous_commit"]["sha"] == previous_sha
    assert result.content["changed_files"] == ["service.txt"]
    assert result.content["safety"]["read_only"] is True


@pytest.mark.asyncio
async def test_change_backend_rejects_untrusted_service_name(
    repository: tuple[Path, str, str],
) -> None:
    path, previous_sha, current_sha = repository
    backend = GitChangeBackend(str(path), RolloutBackend(previous_sha, current_sha))

    result = await backend.call(
        "get_change_evidence", {"service": "order-service; rm -rf /"}
    )

    assert result.success is False
    assert "DNS label" in str(result.error)


@pytest.mark.asyncio
async def test_change_backend_rejects_model_supplied_repository_path(
    repository: tuple[Path, str, str],
) -> None:
    path, previous_sha, current_sha = repository
    backend = GitChangeBackend(str(path), RolloutBackend(previous_sha, current_sha))

    result = await backend.call(
        "get_change_evidence",
        {"service": "order-service", "repository_path": "/tmp/untrusted"},
    )

    assert result.success is False
    assert "Unexpected arguments" in str(result.error)


@pytest.mark.asyncio
async def test_change_backend_does_not_claim_causality_without_full_sha(
    repository: tuple[Path, str, str],
) -> None:
    path, previous_sha, current_sha = repository
    backend = GitChangeBackend(
        str(path), RolloutBackend(previous_sha[:8], current_sha[:8])
    )

    result = await backend.call("get_change_evidence", {"service": "order-service"})

    assert result.success is True
    assert result.content["correlation_status"] == "temporal_candidates"
    assert result.content["current_commit"] is None
    assert result.content["changed_files"] == []


@pytest.mark.asyncio
async def test_change_backend_rejects_non_git_directory(tmp_path: Path) -> None:
    backend = GitChangeBackend(str(tmp_path), RolloutBackend("0" * 40, "1" * 40))

    result = await backend.call("get_change_evidence", {"service": "order-service"})

    assert result.success is False
    assert "not a git repository" in str(result.error).lower()
