from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit

import httpx
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationError,
    field_validator,
)

from sentinelops.change_proposals import ChangeProposalPreview
from sentinelops.storage import IncidentStore
from sentinelops.worker_health import run_with_health_pulse

logger = logging.getLogger(__name__)

GITOPS_PROTOCOL = "sentinelops.gitops-proposal.v1"
MAX_RECEIPT_BYTES = 65_536


class GitOpsDeliveryError(RuntimeError):
    def __init__(self, category: str, *, retryable: bool) -> None:
        super().__init__(category)
        self.category = category
        self.retryable = retryable


class GitOpsSink(Protocol):
    async def publish(
        self,
        proposal: ChangeProposalPreview,
    ) -> dict[str, object]: ...


class GitOpsReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: str
    proposal_id: str
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    change_request_url: HttpUrl
    revision: str = Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

    @field_validator("change_request_url")
    @classmethod
    def https_change_request(cls, value: HttpUrl) -> HttpUrl:
        if (
            value.scheme != "https"
            or value.username is not None
            or value.password is not None
            or value.query is not None
            or value.fragment is not None
        ):
            raise ValueError(
                "代码变更地址必须是无账号、query 和 fragment 的 HTTPS URL"
            )
        return value


def gitops_request_payload(
    proposal: ChangeProposalPreview,
) -> dict[str, object]:
    return {
        "protocol_version": GITOPS_PROTOCOL,
        "proposal_id": proposal.proposal_id,
        "proposal_digest": proposal.proposal_digest,
        "incident_id": proposal.incident_id,
        "target": proposal.target,
        "rationale": proposal.rationale,
        "diff": [item.model_dump(mode="json") for item in proposal.diff],
        "strategic_merge_patch": proposal.strategic_merge_patch,
        "generated_at": proposal.generated_at.isoformat(),
        "expires_at": proposal.expires_at.isoformat(),
    }


class HttpGitOpsSink:
    """Publishes to a separately trusted gateway that owns repository credentials."""

    def __init__(
        self,
        url: str,
        *,
        bearer_token: str,
        timeout_seconds: float,
        require_https: bool,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlsplit(url)
        schemes = {"https"} if require_https else {"http", "https"}
        if (
            parsed.scheme.casefold() not in schemes
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("GitOps Gateway 必须使用固定且安全的 HTTP(S) URL")
        if not bearer_token:
            raise ValueError("GitOps Publisher 必须使用独立 Bearer Token")
        self.url = url
        self.bearer_token = bearer_token
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            headers={"Accept-Encoding": "identity"},
        )

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def publish(
        self,
        proposal: ChangeProposalPreview,
    ) -> dict[str, object]:
        body = json.dumps(
            gitops_request_payload(proposal),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        try:
            response = await self.client.post(
                self.url,
                content=body,
                headers={
                    "Authorization": f"Bearer {self.bearer_token}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": proposal.proposal_id,
                },
            )
        except httpx.HTTPError as exc:
            raise GitOpsDeliveryError(
                "transport_error",
                retryable=True,
            ) from exc
        if response.status_code in {408, 409, 425, 429} or response.status_code >= 500:
            raise GitOpsDeliveryError(
                f"http_{response.status_code}",
                retryable=True,
            )
        if response.status_code not in {200, 201}:
            raise GitOpsDeliveryError(
                f"http_{response.status_code}",
                retryable=False,
            )
        if response.headers.get("content-encoding", "identity").casefold() != "identity":
            raise GitOpsDeliveryError(
                "compressed_receipt",
                retryable=False,
            )
        if len(response.content) > MAX_RECEIPT_BYTES:
            raise GitOpsDeliveryError("receipt_too_large", retryable=False)
        if (
            response.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
            != "application/json"
        ):
            raise GitOpsDeliveryError(
                "invalid_receipt_content_type",
                retryable=False,
            )
        try:
            receipt = GitOpsReceipt.model_validate_json(response.content)
        except ValidationError as exc:
            raise GitOpsDeliveryError(
                "invalid_receipt",
                retryable=False,
            ) from exc
        if (
            receipt.protocol_version != GITOPS_PROTOCOL
            or receipt.proposal_id != proposal.proposal_id
            or receipt.proposal_digest != proposal.proposal_digest
        ):
            raise GitOpsDeliveryError(
                "receipt_binding_mismatch",
                retryable=False,
            )
        return receipt.model_dump(mode="json")


class GitOpsPublisher:
    def __init__(
        self,
        store: IncidentStore,
        sink: GitOpsSink,
        *,
        owner_id: str,
        claim_ttl_seconds: float,
        poll_interval_seconds: float,
        retry_base_seconds: float,
        retry_max_seconds: float,
        health_callback: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.sink = sink
        self.owner_id = owner_id
        self.claim_ttl_seconds = claim_ttl_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self.retry_base_seconds = retry_base_seconds
        self.retry_max_seconds = retry_max_seconds
        self.health_callback = health_callback

    async def run_once(self) -> bool:
        claim = await self.store.claim_gitops_proposal(
            owner_id=self.owner_id,
            ttl_seconds=self.claim_ttl_seconds,
        )
        if claim is None:
            self._heartbeat()
            return False
        try:
            receipt = await self.sink.publish(claim.proposal.preview)
        except GitOpsDeliveryError as exc:
            if exc.retryable:
                await self.store.retry_gitops_proposal(
                    claim,
                    error=exc.category,
                    retry_after_seconds=self._retry_delay(claim.attempt_count),
                )
            else:
                await self.store.dead_letter_gitops_proposal(
                    claim,
                    error=exc.category,
                )
            self._heartbeat()
            return True
        await self.store.complete_gitops_proposal(claim, receipt=receipt)
        self._heartbeat()
        return True

    async def run_forever(self) -> None:
        await run_with_health_pulse(
            self._run_work_loop(),
            callback=self.health_callback,
            interval_seconds=5,
        )

    async def _run_work_loop(self) -> None:
        while True:
            try:
                processed = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "GitOps Publisher iteration failed safely: %s",
                    type(exc).__name__,
                )
                processed = False
            if not processed:
                await asyncio.sleep(self.poll_interval_seconds)

    def _retry_delay(self, attempt_count: int) -> float:
        exponent = min(max(attempt_count - 1, 0), 16)
        return min(
            self.retry_max_seconds,
            self.retry_base_seconds * (2**exponent),
        )

    def _heartbeat(self) -> None:
        if self.health_callback is not None:
            self.health_callback()
