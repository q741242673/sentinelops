from __future__ import annotations

import json

import httpx
import pytest

from sentinelops.change_proposals import (
    ChangeField,
    ChangeOperation,
    ChangeProposalRequest,
    DeploymentSnapshot,
    build_change_proposal,
)
from sentinelops.domain import Alert, IncidentRecord, IncidentStatus
from sentinelops.gitops import (
    GITOPS_PROTOCOL,
    GitOpsDeliveryError,
    GitOpsPublisher,
    HttpGitOpsSink,
)
from sentinelops.storage import ChangeProposalConflictError, SqlIncidentStore


def _database_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'gitops.db'}"


def _alert() -> Alert:
    return Alert(
        name="ManualInvestigationRequired",
        namespace="sentinelops-demo",
        service="order-service",
        severity="critical",
        summary="标准动作无法安全处理",
    )


def _preview(incident_id: str):
    return build_change_proposal(
        incident_id=incident_id,
        alert=_alert(),
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


@pytest.mark.asyncio
async def test_proposal_and_outbox_commit_atomically_and_publish_once(
    tmp_path,
) -> None:
    store = SqlIncidentStore(
        _database_url(tmp_path),
        audit_hmac_key="a" * 32,
        audit_key_id="test-key",
    )
    await store.setup()
    incident = IncidentRecord(
        alert=_alert(),
        status=IncidentStatus.ESCALATED,
    )
    await store.save(incident, expected_version=None, graph_state=None)
    preview = _preview(incident.id)

    first = await store.submit_change_proposal(
        preview,
        actor_id="operator-hash",
        actor_assurance="oidc-human",
    )
    repeated = await store.submit_change_proposal(
        preview,
        actor_id="operator-hash",
        actor_assurance="oidc-human",
    )
    claim = await store.claim_gitops_proposal(
        owner_id="publisher-a",
        ttl_seconds=30,
    )
    second_claim = await store.claim_gitops_proposal(
        owner_id="publisher-b",
        ttl_seconds=30,
    )

    assert first.status == "submitted"
    assert repeated == first
    assert claim is not None
    assert claim.proposal.status == "publishing"
    assert second_claim is None

    receipt = {
        "protocol_version": GITOPS_PROTOCOL,
        "proposal_id": preview.proposal_id,
        "proposal_digest": preview.proposal_digest,
        "change_request_url": "https://git.example/pulls/17",
        "revision": "a" * 40,
    }
    published = await store.complete_gitops_proposal(
        claim,
        receipt=receipt,
    )

    assert published.status == "published"
    assert published.receipt == receipt
    assert (
        await store.claim_gitops_proposal(
            owner_id="publisher-b",
            ttl_seconds=30,
        )
        is None
    )
    audit_types = {event.event_type for event in await store.list_audit_events(incident.id)}
    assert "change_proposal.submitted" in audit_types
    assert "change_proposal.published" in audit_types
    await store.close()


@pytest.mark.asyncio
async def test_stale_gitops_claim_cannot_overwrite_retry_state(tmp_path) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    incident = IncidentRecord(
        alert=_alert(),
        status=IncidentStatus.FAILED,
    )
    await store.save(incident, expected_version=None, graph_state=None)
    preview = _preview(incident.id)
    await store.submit_change_proposal(
        preview,
        actor_id="operator",
        actor_assurance="unverified",
    )
    claim = await store.claim_gitops_proposal(
        owner_id="publisher",
        ttl_seconds=30,
    )
    assert claim is not None
    await store.retry_gitops_proposal(
        claim,
        error="transport_error",
        retry_after_seconds=1,
    )

    with pytest.raises(ChangeProposalConflictError, match="领取已失效"):
        await store.complete_gitops_proposal(claim, receipt={"late": True})
    await store.close()


@pytest.mark.asyncio
async def test_publisher_invalidates_proposal_after_incident_resolves(
    tmp_path,
) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    incident = IncidentRecord(
        alert=_alert(),
        status=IncidentStatus.ESCALATED,
    )
    saved = await store.save(
        incident,
        expected_version=None,
        graph_state=None,
    )
    preview = _preview(incident.id)
    await store.submit_change_proposal(
        preview,
        actor_id="operator",
        actor_assurance="unverified",
    )
    resolved = incident.model_copy(
        update={"status": IncidentStatus.RESOLVED}
    )
    await store.save(
        resolved,
        expected_version=saved.version,
        graph_state=None,
    )

    claim = await store.claim_gitops_proposal(
        owner_id="publisher",
        ttl_seconds=30,
    )
    stored = await store.get_change_proposal(preview.proposal_id)

    assert claim is None
    assert stored is not None
    assert stored.status == "failed"
    assert "change_proposal.invalidated" in {
        event.event_type
        for event in await store.list_audit_events(incident.id)
    }
    await store.close()


@pytest.mark.asyncio
async def test_http_gitops_sink_binds_receipt_and_idempotency_key() -> None:
    preview = _preview("incident-1")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers["authorization"]
        captured["idempotency_key"] = request.headers["idempotency-key"]
        captured["payload"] = json.loads(request.content)
        return httpx.Response(
            201,
            headers={"Content-Type": "application/json"},
            json={
                "protocol_version": GITOPS_PROTOCOL,
                "proposal_id": preview.proposal_id,
                "proposal_digest": preview.proposal_digest,
                "change_request_url": "https://git.example/pulls/17",
                "revision": "a" * 40,
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sink = HttpGitOpsSink(
        "https://gitops.example/v1/proposals",
        bearer_token="gitops-token",
        timeout_seconds=5,
        require_https=True,
        client=client,
    )
    receipt = await sink.publish(preview)

    assert captured["authorization"] == "Bearer gitops-token"
    assert captured["idempotency_key"] == preview.proposal_id
    assert captured["payload"]["strategic_merge_patch"]
    assert receipt["proposal_digest"] == preview.proposal_digest
    await client.aclose()


@pytest.mark.asyncio
async def test_http_gitops_sink_rejects_unbound_receipt() -> None:
    preview = _preview("incident-1")

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={
                "protocol_version": GITOPS_PROTOCOL,
                "proposal_id": preview.proposal_id,
                "proposal_digest": "0" * 64,
                "change_request_url": "https://git.example/pulls/17",
                "revision": "a" * 40,
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sink = HttpGitOpsSink(
        "https://gitops.example/v1/proposals",
        bearer_token="gitops-token",
        timeout_seconds=5,
        require_https=True,
        client=client,
    )

    with pytest.raises(GitOpsDeliveryError, match="receipt_binding_mismatch"):
        await sink.publish(preview)
    await client.aclose()


class _RetryingSink:
    async def publish(self, _proposal):
        raise GitOpsDeliveryError("transport_error", retryable=True)


@pytest.mark.asyncio
async def test_publisher_retries_transient_gateway_failure(tmp_path) -> None:
    store = SqlIncidentStore(_database_url(tmp_path))
    await store.setup()
    incident = IncidentRecord(
        alert=_alert(),
        status=IncidentStatus.ESCALATED,
    )
    await store.save(incident, expected_version=None, graph_state=None)
    preview = _preview(incident.id)
    await store.submit_change_proposal(
        preview,
        actor_id="operator",
        actor_assurance="unverified",
    )
    publisher = GitOpsPublisher(
        store,
        _RetryingSink(),
        owner_id="publisher",
        claim_ttl_seconds=30,
        poll_interval_seconds=1,
        retry_base_seconds=1,
        retry_max_seconds=10,
    )

    assert await publisher.run_once() is True
    stored = await store.get_change_proposal(preview.proposal_id)
    assert stored is not None
    assert stored.status == "submitted"
    await store.close()
