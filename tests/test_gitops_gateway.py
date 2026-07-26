from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter

import httpx
import pytest

from sentinelops.change_proposals import (
    ChangeField,
    ChangeOperation,
    ChangeProposalRequest,
    DeploymentSnapshot,
    build_change_proposal,
)
from sentinelops.domain import Alert
from sentinelops.gitops import (
    GitOpsDeliveryError,
    HttpGitOpsSink,
    gitops_request_payload,
)
from sentinelops.gitops_gateway import (
    GitHubPullRequestClient,
    create_gitops_gateway_app,
)


def _preview():
    alert = Alert(
        name="ManualInvestigationRequired",
        namespace="sentinelops-demo",
        service="order-service",
        severity="critical",
        summary="需要动态提案",
    )
    return build_change_proposal(
        incident_id="incident-1",
        alert=alert,
        request=ChangeProposalRequest(
            rationale="人工调查确认需要提高 CPU request 以消除资源争用",
            operations=[
                ChangeOperation(
                    field=ChangeField.CPU_REQUEST,
                    container="order-service",
                    value="250m",
                )
            ],
        ),
        snapshot=DeploymentSnapshot(
            name="order-service",
            namespace="sentinelops-demo",
            uid="deployment-uid",
            resource_version="42",
            generation=7,
            containers=[
                {
                    "name": "order-service",
                    "image": "order-service@sha256:abc",
                    "resources": {
                        "requests": {"cpu": "100m"},
                        "limits": {"cpu": "500m"},
                    },
                }
            ],
        ),
    )


class _FakeGitHub:
    def __init__(self) -> None:
        self.base_revision = "a" * 40
        self.branch_revision: str | None = None
        self.artifact: bytes | None = None
        self.artifact_path: str | None = None
        self.pull_request: dict[str, object] | None = None
        self.extra_branch_file = False
        self.calls: Counter[str] = Counter()
        self.authorization = ""

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.authorization = request.headers.get("authorization", "")
        method = request.method
        path = request.url.path
        key = f"{method} {path}"
        self.calls[key] += 1
        if method == "GET" and "/git/ref/heads/" in path:
            branch = path.split("/git/ref/heads/", 1)[1]
            if branch == "main":
                return self._json(
                    200,
                    {"object": {"sha": self.base_revision}},
                )
            if self.branch_revision is None:
                return self._json(404, {"message": "Not Found"})
            return self._json(
                200,
                {"object": {"sha": self.branch_revision}},
            )
        if method == "POST" and path.endswith("/git/refs"):
            self.branch_revision = self.base_revision
            return self._json(201, {"ref": "created"})
        if "/contents/" in path:
            artifact_path = path.split("/contents/", 1)[1]
            if method == "GET":
                if self.artifact is None:
                    return self._json(404, {"message": "Not Found"})
                return self._json(
                    200,
                    {
                        "encoding": "base64",
                        "content": base64.b64encode(self.artifact).decode(),
                    },
                )
            if method == "PUT":
                payload = json.loads(request.content)
                self.artifact = base64.b64decode(payload["content"])
                self.artifact_path = artifact_path
                self.branch_revision = "b" * 40
                return self._json(
                    201,
                    {"commit": {"sha": self.branch_revision}},
                )
        if method == "GET" and "/compare/" in path:
            files = [
                {
                    "filename": self.artifact_path,
                    "status": "added",
                }
            ]
            if self.extra_branch_file:
                files.append(
                    {
                        "filename": "deploy/production.yaml",
                        "status": "modified",
                    }
                )
            return self._json(
                200,
                {
                    "ahead_by": 1,
                    "behind_by": 0,
                    "total_commits": 1,
                    "files": files,
                },
            )
        if path.endswith("/pulls") and method == "GET":
            return self._json(
                200,
                [] if self.pull_request is None else [self.pull_request],
            )
        if path.endswith("/pulls") and method == "POST":
            payload = json.loads(request.content)
            self.pull_request = {
                "html_url": "https://github.example/acme/config/pull/17",
                "head": {"ref": payload["head"]},
                "base": {"ref": payload["base"]},
                "draft": payload["draft"],
            }
            return self._json(201, self.pull_request)
        raise AssertionError(f"unexpected GitHub request: {method} {path}")

    @staticmethod
    def _json(status: int, payload: object) -> httpx.Response:
        return httpx.Response(
            status,
            headers={"Content-Type": "application/json"},
            json=payload,
        )


def _gateway(fake: _FakeGitHub):
    github_http = httpx.AsyncClient(
        transport=httpx.MockTransport(fake),
    )
    github = GitHubPullRequestClient(
        api_url="https://api.github.example",
        repository="acme/config",
        base_branch="main",
        proposal_path_prefix="sentinelops/proposals",
        token="github-token",
        timeout_seconds=5,
        deadline_seconds=20,
        client=github_http,
    )
    return (
        create_gitops_gateway_app(
            github,
            inbound_token="publisher-token",
            production=False,
        ),
        github_http,
    )


@pytest.mark.parametrize(
    ("repository", "prefix"),
    [
        ("../config", "sentinelops/proposals"),
        ("acme/config", "sentinelops/../proposals"),
        ("acme/config", "sentinelops/./proposals"),
    ],
)
def test_github_client_rejects_path_traversal(
    repository: str,
    prefix: str,
) -> None:
    with pytest.raises(ValueError, match="不安全"):
        GitHubPullRequestClient(
            api_url="https://api.github.example",
            repository=repository,
            base_branch="main",
            proposal_path_prefix=prefix,
            token="github-token",
            timeout_seconds=5,
            deadline_seconds=20,
        )


@pytest.mark.asyncio
async def test_gateway_creates_one_draft_pr_and_reuses_it_on_retry() -> None:
    fake = _FakeGitHub()
    app, github_http = _gateway(fake)
    gateway_http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://gateway",
    )
    sink = HttpGitOpsSink(
        "http://gateway/v1/proposals",
        bearer_token="publisher-token",
        timeout_seconds=5,
        require_https=False,
        client=gateway_http,
    )
    preview = _preview()

    first = await sink.publish(preview)
    second = await sink.publish(preview)

    assert first == second
    assert first["change_request_url"].endswith("/pull/17")
    assert first["revision"] == "b" * 40
    assert fake.authorization == "Bearer github-token"
    assert fake.artifact is not None
    artifact = json.loads(fake.artifact)
    assert artifact["proposal_digest"] == preview.proposal_digest
    assert fake.artifact_path == (
        f"sentinelops/proposals/{preview.proposal_id}.json"
    )
    assert sum(
        count
        for key, count in fake.calls.items()
        if key.startswith("POST ") and key.endswith("/git/refs")
    ) == 1
    assert sum(
        count
        for key, count in fake.calls.items()
        if key.startswith("PUT ") and "/contents/" in key
    ) == 1
    assert sum(
        count
        for key, count in fake.calls.items()
        if key.startswith("POST ") and key.endswith("/pulls")
    ) == 1
    await gateway_http.aclose()
    await github_http.aclose()


@pytest.mark.asyncio
async def test_gateway_rejects_tampered_digest_before_github_call() -> None:
    fake = _FakeGitHub()
    app, github_http = _gateway(fake)
    payload = gitops_request_payload(_preview())
    payload["rationale"] = "攻击者替换了已经签名的提案正文内容"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://gateway",
    ) as client:
        response = await client.post(
            "/v1/proposals",
            headers={
                "Authorization": "Bearer publisher-token",
                "Idempotency-Key": str(payload["proposal_id"]),
            },
            json=payload,
        )

    assert response.status_code == 422
    assert not fake.calls
    await github_http.aclose()


@pytest.mark.asyncio
async def test_gateway_rejects_branch_with_unrelated_repository_change() -> None:
    fake = _FakeGitHub()
    fake.extra_branch_file = True
    app, github_http = _gateway(fake)
    gateway_http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://gateway",
    )
    sink = HttpGitOpsSink(
        "http://gateway/v1/proposals",
        bearer_token="publisher-token",
        timeout_seconds=5,
        require_https=False,
        client=gateway_http,
    )

    with pytest.raises(GitOpsDeliveryError) as raised:
        await sink.publish(_preview())

    assert raised.value.category == "http_422"
    assert raised.value.retryable is False
    assert fake.pull_request is None
    await gateway_http.aclose()
    await github_http.aclose()


@pytest.mark.asyncio
async def test_gateway_rejects_forged_patch_even_with_matching_digest() -> None:
    fake = _FakeGitHub()
    app, github_http = _gateway(fake)
    payload = gitops_request_payload(_preview())
    patch = payload["strategic_merge_patch"]
    patch["spec"]["template"]["spec"]["containers"][0][
        "image"
    ] = "attacker/image:latest"
    digest_document = {
        "incident_id": payload["incident_id"],
        "target": payload["target"],
        "rationale": payload["rationale"],
        "diff": payload["diff"],
        "strategic_merge_patch": patch,
    }
    digest = hashlib.sha256(
        json.dumps(
            digest_document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    payload["proposal_digest"] = digest
    from uuid import UUID

    payload["proposal_id"] = str(UUID(digest[:32]))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://gateway",
    ) as client:
        response = await client.post(
            "/v1/proposals",
            headers={
                "Authorization": "Bearer publisher-token",
                "Idempotency-Key": str(payload["proposal_id"]),
            },
            json=payload,
        )

    assert response.status_code == 422
    assert not fake.calls
    await github_http.aclose()


@pytest.mark.asyncio
async def test_publisher_treats_gateway_github_outage_as_retryable() -> None:
    def outage(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            headers={"Content-Type": "application/json"},
            json={"message": "unavailable"},
        )

    github_http = httpx.AsyncClient(
        transport=httpx.MockTransport(outage),
    )
    github = GitHubPullRequestClient(
        api_url="https://api.github.example",
        repository="acme/config",
        base_branch="main",
        proposal_path_prefix="sentinelops/proposals",
        token="github-token",
        timeout_seconds=5,
        deadline_seconds=20,
        client=github_http,
    )
    app = create_gitops_gateway_app(
        github,
        inbound_token="publisher-token",
        production=False,
    )
    gateway_http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://gateway",
    )
    sink = HttpGitOpsSink(
        "http://gateway/v1/proposals",
        bearer_token="publisher-token",
        timeout_seconds=5,
        require_https=False,
        client=gateway_http,
    )

    with pytest.raises(GitOpsDeliveryError) as raised:
        await sink.publish(_preview())

    assert raised.value.category == "http_503"
    assert raised.value.retryable is True
    await gateway_http.aclose()
    await github_http.aclose()
