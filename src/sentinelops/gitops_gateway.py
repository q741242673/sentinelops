from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sentinelops.change_proposals import ChangeDiff, ChangeField
from sentinelops.gitops import GITOPS_PROTOCOL, GitOpsReceipt

MAX_GATEWAY_BODY_BYTES = 262_144
MAX_GITHUB_RESPONSE_BYTES = 1_048_576
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_BRANCH = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,198}[A-Za-z0-9])?$")
_PATH_PREFIX = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,198}[A-Za-z0-9])?$"
)


class GitOpsTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=253)
    cluster_id: str = Field(
        min_length=1,
        max_length=63,
        pattern=r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$",
    )
    namespace: str = Field(min_length=1, max_length=253)
    uid: str = Field(min_length=1, max_length=256)
    resource_version: str = Field(min_length=1, max_length=128)
    generation: int = Field(ge=1)


class GitOpsProposalEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: str
    proposal_id: str
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    incident_id: str = Field(min_length=1, max_length=64)
    target: GitOpsTarget
    rationale: str = Field(min_length=10, max_length=2_000)
    diff: list[ChangeDiff] = Field(min_length=1, max_length=8)
    strategic_merge_patch: dict[str, Any]
    generated_at: datetime
    expires_at: datetime

    @field_validator("generated_at", "expires_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("时间必须包含时区")
        return value.astimezone(UTC)

    def verify(self, *, now: datetime) -> None:
        if self.protocol_version != GITOPS_PROTOCOL:
            raise ValueError("不支持的 GitOps 协议版本")
        if self.generated_at > now + timedelta(seconds=30):
            raise ValueError("提案生成时间来自未来")
        if self.expires_at <= now:
            raise ValueError("提案已经过期")
        if self.expires_at - self.generated_at > timedelta(minutes=15):
            raise ValueError("提案有效期超过 15 分钟")
        digest_payload = {
            "incident_id": self.incident_id,
            "target": self.target.model_dump(mode="json"),
            "rationale": self.rationale,
            "diff": [item.model_dump(mode="json") for item in self.diff],
            "strategic_merge_patch": self.strategic_merge_patch,
        }
        canonical = json.dumps(
            digest_payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        expected_digest = hashlib.sha256(canonical).hexdigest()
        expected_id = str(UUID(expected_digest[:32]))
        if not hmac.compare_digest(self.proposal_digest, expected_digest):
            raise ValueError("提案摘要与正文不一致")
        if not hmac.compare_digest(self.proposal_id, expected_id):
            raise ValueError("proposal_id 与摘要不一致")
        _verify_patch(self)


class GitHubGatewayError(RuntimeError):
    def __init__(self, category: str, *, retryable: bool) -> None:
        super().__init__(category)
        self.category = category
        self.retryable = retryable


class GitHubPullRequestClient:
    def __init__(
        self,
        *,
        api_url: str,
        repository: str,
        base_branch: str,
        proposal_path_prefix: str,
        token: str,
        timeout_seconds: float,
        deadline_seconds: float,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlsplit(api_url)
        if (
            parsed.scheme.casefold() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("GitHub API 必须使用固定 HTTPS URL")
        if _REPOSITORY.fullmatch(repository) is None:
            raise ValueError("GitHub repository 必须是固定的 owner/repo")
        repository_parts = repository.split("/", 1)
        if any(part in {".", ".."} for part in repository_parts):
            raise ValueError("GitHub repository 包含不安全路径")
        if (
            _BRANCH.fullmatch(base_branch) is None
            or ".." in base_branch
            or "//" in base_branch
            or base_branch.endswith(".lock")
        ):
            raise ValueError("GitHub base branch 不安全")
        prefix = proposal_path_prefix.strip("/")
        if (
            _PATH_PREFIX.fullmatch(prefix) is None
            or any(
                part in {".", ".."}
                for part in prefix.split("/")
            )
            or "//" in prefix
        ):
            raise ValueError("GitHub 提案目录不安全")
        if not token:
            raise ValueError("GitHub Gateway 需要独立仓库 Token")
        if deadline_seconds <= timeout_seconds:
            raise ValueError("GitHub 总 deadline 必须大于单次请求 timeout")
        self.api_url = api_url.rstrip("/")
        self.repository = repository
        self.owner, _ = repository_parts
        self.base_branch = base_branch
        self.proposal_path_prefix = prefix
        self.token = token
        self.deadline_seconds = deadline_seconds
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            headers={
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "sentinelops-gitops-gateway",
            },
        )

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def publish(
        self,
        proposal: GitOpsProposalEnvelope,
    ) -> GitOpsReceipt:
        try:
            async with asyncio.timeout(self.deadline_seconds):
                return await self._publish(proposal)
        except TimeoutError as exc:
            raise GitHubGatewayError(
                "github_deadline_exceeded",
                retryable=True,
            ) from exc

    async def _publish(
        self,
        proposal: GitOpsProposalEnvelope,
    ) -> GitOpsReceipt:
        branch = f"sentinelops/proposal-{proposal.proposal_id}"
        artifact_path = (
            f"{self.proposal_path_prefix}/{proposal.proposal_id}.json"
        )
        artifact = _proposal_artifact(proposal)
        await self._ensure_branch(branch)
        await self._ensure_artifact(
            branch=branch,
            path=artifact_path,
            content=artifact,
            proposal=proposal,
        )
        await self._verify_branch_scope(branch, artifact_path)
        pull_request = await self._find_pull_request(branch)
        if pull_request is None:
            response = await self._request(
                "POST",
                "pulls",
                expected={201, 422},
                json_body={
                    "title": (
                        "SentinelOps: review proposal "
                        f"{proposal.proposal_id}"
                    ),
                    "head": branch,
                    "base": self.base_branch,
                    "draft": True,
                    "body": _pull_request_body(proposal, artifact_path),
                },
            )
            if response.status_code == 422:
                pull_request = await self._find_pull_request(branch)
                if pull_request is None:
                    raise GitHubGatewayError(
                        "pull_request_conflict",
                        retryable=False,
                    )
            else:
                pull_request = _json_object(response)
        revision = await self._branch_revision(branch)
        html_url = pull_request.get("html_url")
        if not isinstance(html_url, str):
            raise GitHubGatewayError(
                "pull_request_url_missing",
                retryable=False,
            )
        return GitOpsReceipt(
            protocol_version=GITOPS_PROTOCOL,
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            change_request_url=html_url,
            revision=revision,
        )

    async def _ensure_branch(self, branch: str) -> None:
        if await self._ref(branch) is not None:
            return
        base_revision = await self._branch_revision(self.base_branch)
        response = await self._request(
            "POST",
            "git/refs",
            expected={201, 422},
            json_body={
                "ref": f"refs/heads/{branch}",
                "sha": base_revision,
            },
        )
        if response.status_code == 422 and await self._ref(branch) is None:
            raise GitHubGatewayError(
                "branch_conflict",
                retryable=False,
            )

    async def _ensure_artifact(
        self,
        *,
        branch: str,
        path: str,
        content: bytes,
        proposal: GitOpsProposalEnvelope,
    ) -> None:
        existing = await self._content(path, branch)
        if existing is not None:
            if not hmac.compare_digest(existing, content):
                raise GitHubGatewayError(
                    "proposal_branch_content_mismatch",
                    retryable=False,
                )
            return
        response = await self._request(
            "PUT",
            f"contents/{quote(path, safe='/')}",
            expected={201, 422},
            json_body={
                "message": (
                    "sentinelops: add proposal "
                    f"{proposal.proposal_id}"
                ),
                "content": base64.b64encode(content).decode(),
                "branch": branch,
            },
        )
        if response.status_code == 422:
            existing = await self._content(path, branch)
            if existing is None or not hmac.compare_digest(existing, content):
                raise GitHubGatewayError(
                    "proposal_file_conflict",
                    retryable=False,
                )

    async def _find_pull_request(
        self,
        branch: str,
    ) -> dict[str, Any] | None:
        response = await self._request(
            "GET",
            "pulls",
            expected={200},
            params={
                "head": f"{self.owner}:{branch}",
                "state": "all",
                "per_page": "10",
            },
        )
        payload = _json_value(response)
        if not isinstance(payload, list):
            raise GitHubGatewayError(
                "invalid_pull_request_list",
                retryable=False,
            )
        for item in payload:
            if not isinstance(item, dict):
                continue
            head = item.get("head")
            base = item.get("base")
            if (
                isinstance(head, dict)
                and head.get("ref") == branch
                and isinstance(base, dict)
                and base.get("ref") == self.base_branch
            ):
                return item
        return None

    async def _verify_branch_scope(
        self,
        branch: str,
        artifact_path: str,
    ) -> None:
        response = await self._request(
            "GET",
            (
                f"compare/{quote(self.base_branch, safe='')}"
                f"...{quote(branch, safe='')}"
            ),
            expected={200},
        )
        payload = _json_object(response)
        ahead_by = payload.get("ahead_by")
        total_commits = payload.get("total_commits")
        files = payload.get("files")
        if (
            ahead_by != 1
            or total_commits != 1
            or not isinstance(files, list)
            or len(files) != 1
            or not isinstance(files[0], dict)
            or files[0].get("filename") != artifact_path
            or files[0].get("status") not in {"added", "modified"}
        ):
            raise GitHubGatewayError(
                "proposal_branch_scope_violation",
                retryable=False,
            )

    async def _content(
        self,
        path: str,
        branch: str,
    ) -> bytes | None:
        response = await self._request(
            "GET",
            f"contents/{quote(path, safe='/')}",
            expected={200, 404},
            params={"ref": branch},
        )
        if response.status_code == 404:
            return None
        payload = _json_object(response)
        if payload.get("encoding") != "base64":
            raise GitHubGatewayError(
                "unsupported_content_encoding",
                retryable=False,
            )
        encoded = payload.get("content")
        if not isinstance(encoded, str):
            raise GitHubGatewayError(
                "repository_content_missing",
                retryable=False,
            )
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise GitHubGatewayError(
                "repository_content_invalid",
                retryable=False,
            ) from exc
        if len(decoded) > MAX_GATEWAY_BODY_BYTES:
            raise GitHubGatewayError(
                "repository_content_too_large",
                retryable=False,
            )
        return decoded

    async def _branch_revision(self, branch: str) -> str:
        reference = await self._ref(branch)
        if reference is None:
            raise GitHubGatewayError(
                "branch_missing",
                retryable=False,
            )
        object_value = reference.get("object")
        revision = (
            object_value.get("sha")
            if isinstance(object_value, dict)
            else None
        )
        if (
            not isinstance(revision, str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision)
            is None
        ):
            raise GitHubGatewayError(
                "branch_revision_invalid",
                retryable=False,
            )
        return revision

    async def _ref(self, branch: str) -> dict[str, Any] | None:
        response = await self._request(
            "GET",
            f"git/ref/heads/{quote(branch, safe='')}",
            expected={200, 404},
        )
        return (
            None
            if response.status_code == 404
            else _json_object(response)
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        expected: set[int],
        json_body: dict[str, object] | None = None,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        try:
            response = await self.client.request(
                method,
                f"{self.api_url}/repos/{self.repository}/{path}",
                json=json_body,
                params=params,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Accept-Encoding": "identity",
                    "Authorization": f"Bearer {self.token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "sentinelops-gitops-gateway",
                },
            )
        except httpx.HTTPError as exc:
            raise GitHubGatewayError(
                "github_transport_error",
                retryable=True,
            ) from exc
        if len(response.content) > MAX_GITHUB_RESPONSE_BYTES:
            raise GitHubGatewayError(
                "github_response_too_large",
                retryable=False,
            )
        if (
            response.headers.get("content-encoding", "identity").casefold()
            != "identity"
        ):
            raise GitHubGatewayError(
                "github_response_compressed",
                retryable=False,
            )
        if response.status_code not in expected:
            retryable = (
                response.status_code in {408, 425, 429}
                or response.status_code >= 500
                or (
                    response.status_code == 403
                    and response.headers.get("x-ratelimit-remaining") == "0"
                )
            )
            raise GitHubGatewayError(
                f"github_http_{response.status_code}",
                retryable=retryable,
            )
        return response


def create_gitops_gateway_app(
    github: GitHubPullRequestClient,
    *,
    inbound_token: str,
    production: bool,
) -> FastAPI:
    if not inbound_token:
        raise ValueError("GitOps Gateway 需要独立入站 Token")
    if production and len(inbound_token.encode()) < 32:
        raise ValueError("生产 GitOps Gateway 入站 Token 至少需要 32 字节")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await github.close()

    app = FastAPI(
        title="SentinelOps Reference GitOps Gateway",
        version="1",
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/proposals")
    async def publish(request: Request) -> JSONResponse:
        content_types = request.headers.getlist("content-type")
        content_type = content_types[0] if len(content_types) == 1 else ""
        if (
            content_type.split(";", 1)[0].strip().casefold()
            != "application/json"
        ):
            raise HTTPException(status_code=415, detail="只接受 JSON")
        content_encodings = request.headers.getlist("content-encoding")
        if len(content_encodings) > 1 or (
            content_encodings
            and content_encodings[0].strip().casefold()
            not in {"", "identity"}
        ):
            raise HTTPException(status_code=415, detail="不接受压缩请求体")
        content_lengths = request.headers.getlist("content-length")
        if len(content_lengths) > 1:
            raise HTTPException(status_code=413, detail="请求体长度无效")
        if content_lengths:
            try:
                length = int(content_lengths[0])
            except ValueError as exc:
                raise HTTPException(
                    status_code=413,
                    detail="请求体长度无效",
                ) from exc
            if length < 0 or length > MAX_GATEWAY_BODY_BYTES:
                raise HTTPException(status_code=413, detail="请求体过大")
        supplied_token = _bearer_token(request)
        if not hmac.compare_digest(supplied_token, inbound_token):
            raise HTTPException(
                status_code=401,
                detail="GitOps Gateway 认证失败",
                headers={"WWW-Authenticate": "Bearer"},
            )
        body = await request.body()
        if len(body) > MAX_GATEWAY_BODY_BYTES:
            raise HTTPException(status_code=413, detail="请求体过大")
        try:
            proposal = GitOpsProposalEnvelope.model_validate_json(body)
            proposal.verify(now=datetime.now(UTC))
        except (ValidationError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail=f"GitOps 提案无效：{exc}",
            ) from exc
        idempotency_key = request.headers.get("idempotency-key", "")
        if not hmac.compare_digest(
            idempotency_key,
            proposal.proposal_id,
        ):
            raise HTTPException(
                status_code=422,
                detail="Idempotency-Key 必须等于 proposal_id",
            )
        try:
            receipt = await github.publish(proposal)
        except GitHubGatewayError as exc:
            status = 503 if exc.retryable else 422
            raise HTTPException(status_code=status, detail=exc.category) from exc
        return JSONResponse(
            status_code=201,
            content=receipt.model_dump(mode="json"),
        )

    return app


def _bearer_token(request: Request) -> str:
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        return ""
    scheme, separator, token = values[0].partition(" ")
    if not separator or scheme.casefold() != "bearer":
        return ""
    return token


def _verify_patch(proposal: GitOpsProposalEnvelope) -> None:
    patch = proposal.strategic_merge_patch
    if set(patch) != {"apiVersion", "kind", "metadata", "spec"}:
        raise ValueError("patch 顶层字段超出允许范围")
    if patch["apiVersion"] != "apps/v1" or patch["kind"] != "Deployment":
        raise ValueError("patch 只允许 apps/v1 Deployment")
    metadata = patch["metadata"]
    if not isinstance(metadata, dict) or metadata != {
        "name": proposal.target.name,
        "namespace": proposal.target.namespace,
    }:
        raise ValueError("patch 目标与提案 target 不一致")
    spec = patch["spec"]
    if not isinstance(spec, dict) or set(spec) != {"template"}:
        raise ValueError("patch spec 字段超出允许范围")
    template = spec["template"]
    if not isinstance(template, dict) or set(template) != {"spec"}:
        raise ValueError("patch template 字段超出允许范围")
    pod_spec = template["spec"]
    if not isinstance(pod_spec, dict) or set(pod_spec) != {"containers"}:
        raise ValueError("patch Pod spec 字段超出允许范围")
    try:
        containers = pod_spec["containers"]
    except (KeyError, TypeError) as exc:
        raise ValueError("patch 缺少容器变更") from exc
    if (
        not isinstance(containers, list)
        or not containers
        or len(containers) > 8
    ):
        raise ValueError("patch 容器列表无效")
    leaves: dict[tuple[str, str], str | int] = {}
    for container in containers:
        if not isinstance(container, dict):
            raise ValueError("patch 容器必须是对象")
        if not set(container) <= {
            "name",
            "resources",
            "readinessProbe",
            "livenessProbe",
        }:
            raise ValueError("patch 容器字段超出允许范围")
        name = container.get("name")
        if not isinstance(name, str):
            raise ValueError("patch 容器缺少名称")
        _collect_resource_leaves(name, container, leaves)
        _collect_probe_leaves(name, container, leaves)
    expected = {
        (item.container, item.field.value): item.after
        for item in proposal.diff
    }
    if len(expected) != len(proposal.diff) or leaves != expected:
        raise ValueError("patch 与提案 diff 不一致")


def _collect_resource_leaves(
    container: str,
    patch: dict[str, Any],
    leaves: dict[tuple[str, str], str | int],
) -> None:
    resources = patch.get("resources")
    if resources is None:
        return
    if not isinstance(resources, dict) or not set(resources) <= {
        "requests",
        "limits",
    }:
        raise ValueError("resources 字段超出允许范围")
    for group, values in resources.items():
        if (
            not isinstance(values, dict)
            or not values
            or not set(values) <= {"cpu", "memory"}
        ):
            raise ValueError("resource 类型超出允许范围")
        for resource, value in values.items():
            field = f"container.resources.{group}.{resource}"
            _add_leaf(leaves, container, field, value)


def _collect_probe_leaves(
    container: str,
    patch: dict[str, Any],
    leaves: dict[tuple[str, str], str | int],
) -> None:
    attributes = {
        "initialDelaySeconds",
        "periodSeconds",
        "timeoutSeconds",
        "failureThreshold",
    }
    for probe in ("readinessProbe", "livenessProbe"):
        values = patch.get(probe)
        if values is None:
            continue
        if (
            not isinstance(values, dict)
            or not values
            or not set(values) <= attributes
        ):
            raise ValueError("probe 字段超出允许范围")
        for attribute, value in values.items():
            field = f"container.{probe}.{attribute}"
            _add_leaf(leaves, container, field, value)


def _add_leaf(
    leaves: dict[tuple[str, str], str | int],
    container: str,
    field: str,
    value: object,
) -> None:
    try:
        change_field = ChangeField(field)
    except ValueError as exc:
        raise ValueError("patch 包含未允许的字段") from exc
    if (
        isinstance(value, bool)
        or not isinstance(value, (str, int))
        or (isinstance(value, str) and not value)
    ):
        raise ValueError("patch 值类型无效")
    _validate_leaf_value(change_field, value)
    identity = (container, change_field.value)
    if identity in leaves:
        raise ValueError("patch 包含重复字段")
    leaves[identity] = value


def _validate_leaf_value(
    field: ChangeField,
    value: str | int,
) -> None:
    if field.value.startswith("container.resources."):
        if not isinstance(value, str):
            raise ValueError("resource 值必须是 quantity 字符串")
        match = re.fullmatch(
            r"(?P<number>[0-9]+(?:\.[0-9]+)?)(?P<unit>m|Ki|Mi|Gi|Ti)?",
            value,
        )
        if match is None:
            raise ValueError("resource quantity 格式无效")
        try:
            number = Decimal(match.group("number"))
        except InvalidOperation as exc:
            raise ValueError("resource quantity 无效") from exc
        unit = match.group("unit") or ""
        if number <= 0:
            raise ValueError("resource quantity 必须大于零")
        if field in {ChangeField.CPU_REQUEST, ChangeField.CPU_LIMIT}:
            cores = number / 1000 if unit == "m" else number
            if unit not in {"", "m"} or cores > 64:
                raise ValueError("CPU quantity 超过允许上限")
            return
        factors = {
            "": Decimal(1),
            "Ki": Decimal(1024),
            "Mi": Decimal(1024**2),
            "Gi": Decimal(1024**3),
            "Ti": Decimal(1024**4),
        }
        if (
            unit not in factors
            or number * factors[unit] > Decimal(256 * 1024**3)
        ):
            raise ValueError("内存 quantity 超过允许上限")
        return
    if not isinstance(value, int):
        raise ValueError("probe 值必须是整数")
    attribute = field.value.rsplit(".", 1)[-1]
    lower, upper = (
        (0, 3_600)
        if attribute == "initialDelaySeconds"
        else ((1, 20) if attribute == "failureThreshold" else (1, 300))
    )
    if value < lower or value > upper:
        raise ValueError("probe 值超过允许范围")


def _proposal_artifact(proposal: GitOpsProposalEnvelope) -> bytes:
    return (
        json.dumps(
            proposal.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _pull_request_body(
    proposal: GitOpsProposalEnvelope,
    artifact_path: str,
) -> str:
    return "\n".join(
        [
            "## SentinelOps 动态变更提案",
            "",
            f"- 事故：`{proposal.incident_id}`",
            (
                "- 目标："
                f"`{proposal.target.namespace}/{proposal.target.name}`"
            ),
            f"- 提案摘要：`{proposal.proposal_digest}`",
            f"- 不可变提案文件：`{artifact_path}`",
            "",
            proposal.rationale,
            "",
            (
                "此 PR 只保存经过边界检查的提案，"
                "不会自动合并或直接修改 Kubernetes。"
            ),
        ]
    )


def _json_value(response: httpx.Response) -> object:
    if (
        response.headers.get("content-type", "")
        .split(";", 1)[0]
        .strip()
        .casefold()
        != "application/json"
    ):
        raise GitHubGatewayError(
            "github_content_type_invalid",
            retryable=False,
        )
    try:
        return response.json()
    except ValueError as exc:
        raise GitHubGatewayError(
            "github_json_invalid",
            retryable=False,
        ) from exc


def _json_object(response: httpx.Response) -> dict[str, Any]:
    payload = _json_value(response)
    if not isinstance(payload, dict):
        raise GitHubGatewayError(
            "github_object_invalid",
            retryable=False,
        )
    return payload
