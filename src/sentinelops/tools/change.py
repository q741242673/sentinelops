from __future__ import annotations

import asyncio
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelops.domain import ToolResult
from sentinelops.tools.base import ToolBackend

SERVICE_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
FULL_GIT_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


class GitChangeBackend:
    """Correlate a deployment rollout with a fixed, local Git repository."""

    def __init__(
        self,
        repository_path: str,
        rollout_backend: ToolBackend,
        *,
        history_hours: int = 24,
        history_limit: int = 20,
        timeout_seconds: float = 5,
    ) -> None:
        self.repository = Path(repository_path).expanduser().resolve(strict=True)
        if not self.repository.is_dir():
            raise ValueError("Change repository path must be a directory")
        self.rollout_backend = rollout_backend
        self.history_hours = history_hours
        self.history_limit = history_limit
        self.timeout_seconds = timeout_seconds

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        started = time.perf_counter()
        if name != "get_change_evidence":
            return ToolResult(tool_name=name, success=False, error=f"Unknown tool: {name}")
        try:
            content = await self._get_change_evidence(arguments)
            return ToolResult(
                tool_name=name,
                success=True,
                content=content,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=name,
                success=False,
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )

    async def _get_change_evidence(self, arguments: dict[str, Any]) -> dict[str, Any]:
        unexpected = sorted(set(arguments) - {"service"})
        if unexpected:
            raise ValueError(f"Unexpected arguments: {', '.join(unexpected)}")
        service = str(arguments.get("service", ""))
        if not SERVICE_NAME.fullmatch(service):
            raise ValueError("service must be a valid Kubernetes DNS label")
        await self._validate_repository()

        rollout_result = await self.rollout_backend.call(
            "get_rollout_history", {"name": service}
        )
        if not rollout_result.success:
            raise RuntimeError(f"Could not read rollout history: {rollout_result.error}")

        current, previous = self._select_revisions(rollout_result.content)
        current_commit = await self._verified_commit(current.get("git_commit")) if current else None
        previous_commit = (
            await self._verified_commit(previous.get("git_commit")) if previous else None
        )

        changed_files: list[str] = []
        correlation_status = "temporal_candidates"
        correlation_summary = "Kubernetes revision 没有可验证的完整 Git SHA，仅提供时间候选提交"
        if current_commit and previous_commit:
            if current_commit["sha"] == previous_commit["sha"]:
                correlation_status = "no_code_change"
                correlation_summary = "当前与上一 revision 指向同一 Git 提交，未发现代码变更"
            else:
                correlation_status = "verified"
                correlation_summary = "已通过完整 SHA 验证当前与上一 revision 的 Git 提交差异"
                changed_files = await self._changed_files(
                    previous_commit["sha"], current_commit["sha"]
                )
        elif current_commit:
            correlation_status = "current_commit_verified"
            correlation_summary = "当前 revision 的 Git SHA 已验证，但上一 revision 缺少可验证 SHA"

        return {
            "repository": self.repository.name,
            "service": service,
            "correlation_status": correlation_status,
            "correlation_summary": correlation_summary,
            "current_rollout": current,
            "previous_rollout": previous,
            "current_commit": current_commit,
            "previous_commit": previous_commit,
            "changed_files": changed_files,
            "recent_commits": await self._recent_commits(),
            "safety": {
                "read_only": True,
                "repository_path_fixed_by_configuration": True,
                "verified_sha_required_for_causal_diff": True,
            },
        }

    async def _validate_repository(self) -> None:
        root = await self._run_git("rev-parse", "--show-toplevel")
        if root.strip() != str(self.repository):
            raise ValueError("Configured change repository must be the Git worktree root")

    @staticmethod
    def _select_revisions(
        rollout: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        revisions = [
            item
            for item in rollout.get("revisions", [])
            if str(item.get("revision", "")).isdigit()
        ]
        if not revisions:
            return None, None
        active = [
            item
            for item in revisions
            if (item.get("replicas") or 0) > 0 or (item.get("ready_replicas") or 0) > 0
        ]
        current = max(active or revisions, key=lambda item: int(item["revision"]))
        older = [
            item for item in revisions if int(item["revision"]) < int(current["revision"])
        ]
        previous = max(older, key=lambda item: int(item["revision"])) if older else None
        return current, previous

    async def _verified_commit(self, candidate: Any) -> dict[str, Any] | None:
        sha = str(candidate or "")
        if not FULL_GIT_SHA.fullmatch(sha):
            return None
        try:
            await self._run_git("cat-file", "-e", f"{sha}^{{commit}}")
            output = await self._run_git(
                "show", "-s", "--format=%H%x00%an%x00%aI%x00%s", sha
            )
        except RuntimeError:
            return None
        parts = output.rstrip("\n").split("\x00", 3)
        if len(parts) != 4:
            return None
        return {
            "sha": parts[0],
            "author": parts[1],
            "authored_at": parts[2],
            "subject": parts[3],
        }

    async def _changed_files(self, previous_sha: str, current_sha: str) -> list[str]:
        output = await self._run_git(
            "diff", "--name-only", previous_sha, current_sha, "--"
        )
        return [line for line in output.splitlines() if line][:100]

    async def _recent_commits(self) -> list[dict[str, str]]:
        since = (datetime.now(UTC) - timedelta(hours=self.history_hours)).isoformat()
        output = await self._run_git(
            "log",
            f"--since={since}",
            f"--max-count={self.history_limit}",
            "--format=%H%x00%an%x00%aI%x00%s",
        )
        commits: list[dict[str, str]] = []
        for line in output.splitlines():
            parts = line.split("\x00", 3)
            if len(parts) == 4:
                commits.append(
                    {
                        "sha": parts[0],
                        "author": parts[1],
                        "authored_at": parts[2],
                        "subject": parts[3],
                    }
                )
        return commits

    async def _run_git(self, *arguments: str) -> str:
        process = await asyncio.create_subprocess_exec(
            "git",
            "-C",
            str(self.repository),
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout_seconds
            )
        except TimeoutError:
            process.kill()
            await process.communicate()
            raise RuntimeError("Git command timed out") from None
        if len(stdout) > 262_144 or len(stderr) > 65_536:
            raise RuntimeError("Git command output exceeded the safety limit")
        if process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(message or "Git command failed")
        return stdout.decode("utf-8", errors="replace")
