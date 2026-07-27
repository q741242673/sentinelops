from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import TypeAdapter

from sentinelops.domain import RemediationAction, RiskLevel, ToolResult
from sentinelops.executor_control import (
    EXECUTOR_CONTROL_PREFIX,
    MAX_EXECUTOR_RESPONSE_BYTES,
    ExecutorControlAuthenticationError,
    ExecutorControlProtocolError,
    ExecutorControlUnavailableError,
    HttpExecutorControlPlane,
)
from sentinelops.storage.base import (
    ActionIntentConflictError,
    ActionReconciliationClaim,
    ClusterAgentLeaseToken,
    ClusterRegistration,
    ExecutorClaim,
    LeaseConflictError,
    StoredActionIntent,
)


class _ObservedAsyncStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.yielded = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def _registration(cluster_id: str = "cluster-a") -> ClusterRegistration:
    now = datetime.now(UTC)
    return ClusterRegistration(
        cluster_id=cluster_id,
        display_name="生产集群 A",
        default_namespace="sentinelops-system",
        routing_generation=3,
        lifecycle="active",
        metadata_state="configured",
        created_at=now,
        updated_at=now,
    )


def _lease(cluster_id: str = "cluster-a") -> ClusterAgentLeaseToken:
    now = datetime.now(UTC)
    return ClusterAgentLeaseToken(
        cluster_id=cluster_id,
        instance_id="pod-uid-a",
        session_id="session-a",
        generation=2,
        routing_generation=3,
        capabilities=(
            "action.execute",
            "action.reconcile",
            "backend.controller",
        ),
        version="0.1.0rc1",
        registered_at=now,
        last_seen_at=now,
        lease_until=now + timedelta(seconds=60),
    )


def _claim(cluster_id: str = "cluster-a") -> ExecutorClaim:
    return ExecutorClaim(
        idempotency_key="a" * 64,
        incident_id="incident-a",
        cluster_id=cluster_id,
        cluster_generation=3,
        owner_id="executor-a",
        generation=4,
        attempt_id="attempt-a",
        session_id="session-a",
        session_generation=2,
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
    )


def _action(cluster_id: str = "cluster-a") -> StoredActionIntent:
    return StoredActionIntent(
        idempotency_key="a" * 64,
        incident_id="incident-a",
        cluster_id=cluster_id,
        cluster_generation=3,
        lease_generation=5,
        approval_id="approval-a",
        approval_version=1,
        action=RemediationAction(
            tool_name="rollback_deployment",
            arguments={"name": "orders", "revision": 2},
            rationale="最近一次发布引发错误率升高",
            expected_outcome="恢复到健康版本",
            risk=RiskLevel.HIGH,
        ),
        precondition={
            "cluster_id": cluster_id,
            "namespace": "apps",
            "resource_version": "42",
        },
        status="dispatched",
        result=None,
        error=None,
        executor_id="executor-a",
        executor_generation=4,
        executor_lease_until=datetime.now(UTC) + timedelta(seconds=60),
        attempt_id="attempt-a",
        executor_session_id="session-a",
        executor_session_generation=2,
    )


def _reconciliation_claim(
    cluster_id: str = "cluster-a",
) -> ActionReconciliationClaim:
    return ActionReconciliationClaim(
        intent=_action(cluster_id),
        cluster_id=cluster_id,
        cluster_generation=3,
        owner_id="executor-a",
        generation=6,
        attempt_id="reconcile-a",
        attempt_count=1,
        session_id="session-a",
        session_generation=2,
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
    )


def _json_response(value: object) -> httpx.Response:
    return httpx.Response(
        200,
        content=TypeAdapter(type(value)).dump_json(value),
        headers={"Content-Type": "application/json"},
    )


def _client(tmp_path, handler):
    token_file = tmp_path / "executor-token"
    token_file.write_text("token-one\n", encoding="utf-8")
    return (
        HttpExecutorControlPlane(
            "https://control.example.test",
            cluster_id="cluster-a",
            token_file=token_file,
            deadline_seconds=1,
            transport=httpx.MockTransport(handler),
        ),
        token_file,
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "file:///tmp/gateway.sock",
        "https://user:password@control.example.test",
        "https://control.example.test/path",
        "https://control.example.test?cluster=other",
    ],
)
def test_rejects_ambiguous_or_credentialed_gateway_origins(
    tmp_path,
    base_url: str,
) -> None:
    token_file = tmp_path / "executor-token"
    token_file.write_text("token-one", encoding="utf-8")
    with pytest.raises(ValueError, match="fixed HTTP"):
        HttpExecutorControlPlane(
            base_url,
            cluster_id="cluster-a",
            token_file=token_file,
        )


@pytest.mark.asyncio
async def test_reads_rotated_token_and_sends_fixed_cluster_header(tmp_path) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _json_response(_registration())

    client, token_file = _client(tmp_path, handler)
    try:
        await client.ensure_cluster_registration(
            cluster_id="cluster-a",
            display_name="生产集群 A",
            default_namespace="sentinelops-system",
        )
        token_file.write_text("token-two\n", encoding="utf-8")
        await client.ensure_cluster_registration(
            cluster_id="cluster-a",
            display_name="生产集群 A",
            default_namespace="sentinelops-system",
        )
    finally:
        await client.aclose()

    assert [item.headers["authorization"] for item in requests] == [
        "Bearer token-one",
        "Bearer token-two",
    ]
    assert {item.headers["x-sentinelops-cluster-id"] for item in requests} == {"cluster-a"}
    assert all(
        item.url.path == f"{EXECUTOR_CONTROL_PREFIX}/clusters/cluster-a" for item in requests
    )


@pytest.mark.asyncio
async def test_dispatch_serializes_strict_claim_and_lease_contract(tmp_path) -> None:
    observed: dict[str, object] = {}
    response_action = _action()

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.update(json.loads(request.content))
        return _json_response(response_action)

    client, _ = _client(tmp_path, handler)
    claim = _claim()
    lease = _lease()
    try:
        dispatched = await client.mark_action_dispatched(
            claim,
            agent_lease=lease,
        )
    finally:
        await client.aclose()

    assert dispatched == response_action
    assert observed["claim"]["attempt_id"] == claim.attempt_id
    assert observed["claim"]["expires_at"].endswith("Z")
    assert observed["agent_lease"]["session_id"] == lease.session_id
    assert observed["agent_lease"]["capabilities"] == list(lease.capabilities)


@pytest.mark.asyncio
async def test_claim_and_reconciliation_no_work_use_204(tmp_path) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    client, _ = _client(tmp_path, handler)
    try:
        assert (
            await client.claim_action_execution(
                agent_lease=_lease(),
                owner_id="executor-a",
                attempt_id="attempt-a",
                ttl_seconds=60,
            )
            is None
        )
        assert (
            await client.claim_action_reconciliation(
                agent_lease=_lease(),
                owner_id="executor-a",
                ttl_seconds=60,
            )
            is None
        )
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_rejects_cross_cluster_success_response(tmp_path) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return _json_response(_lease("cluster-b"))

    client, _ = _client(tmp_path, handler)
    try:
        with pytest.raises(
            ExecutorControlProtocolError,
            match="cross-cluster",
        ):
            await client.register_cluster_agent(
                cluster_id="cluster-a",
                instance_id="pod-uid-a",
                session_id="session-a",
                capabilities=("action.execute",),
                version="test",
                ttl_seconds=60,
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_rejects_cross_cluster_action_precondition(tmp_path) -> None:
    action = _action()
    action.precondition["cluster_id"] = "cluster-b"

    async def handler(_request: httpx.Request) -> httpx.Response:
        return _json_response(action)

    client, _ = _client(tmp_path, handler)
    try:
        with pytest.raises(
            ExecutorControlProtocolError,
            match="precondition",
        ):
            await client.mark_action_dispatched(
                _claim(),
                agent_lease=_lease(),
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [401, 403])
async def test_maps_service_identity_rejection(tmp_path, status_code: int) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            json={"detail": "service identity rejected"},
        )

    client, _ = _client(tmp_path, handler)
    try:
        with pytest.raises(
            ExecutorControlAuthenticationError,
            match="service identity rejected",
        ):
            await client.claim_action_execution(
                agent_lease=_lease(),
                owner_id="executor-a",
                attempt_id="attempt-a",
                ttl_seconds=60,
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "error_code", "expected_error"),
    [
        (409, "action_intent_conflict", ActionIntentConflictError),
        (410, "lease_conflict", LeaseConflictError),
    ],
)
async def test_maps_conflict_error_codes(
    tmp_path,
    status_code: int,
    error_code: str,
    expected_error: type[RuntimeError],
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            json={"error_code": error_code, "detail": "fenced"},
        )

    client, _ = _client(tmp_path, handler)
    try:
        with pytest.raises(expected_error, match="fenced"):
            await client.mark_action_dispatched(
                _claim(),
                agent_lease=_lease(),
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_network_failure_is_not_retried(tmp_path) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("gateway unavailable", request=request)

    client, _ = _client(tmp_path, handler)
    try:
        with pytest.raises(ExecutorControlUnavailableError):
            await client.mark_action_dispatched(
                _claim(),
                agent_lease=_lease(),
            )
    finally:
        await client.aclose()

    assert calls == 1


@pytest.mark.asyncio
async def test_rejects_oversized_token_before_network_call(tmp_path) -> None:
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _json_response(_registration())

    client, token_file = _client(tmp_path, handler)
    token_file.write_bytes(b"x" * 16_385)
    try:
        with pytest.raises(
            ExecutorControlAuthenticationError,
            match="size limit",
        ):
            await client.ensure_cluster_registration(
                cluster_id="cluster-a",
                display_name="生产集群 A",
                default_namespace="sentinelops-system",
            )
    finally:
        await client.aclose()

    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "content", "message"),
    [
        (
            {"Content-Type": "application/json", "Content-Encoding": "gzip"},
            gzip.compress(b"{}"),
            "Compressed",
        ),
        (
            {"Content-Type": "text/html"},
            b"{}",
            "non-JSON",
        ),
        (
            {
                "Content-Type": "application/json",
                "Content-Length": "1048577",
            },
            b"{}",
            "size limit",
        ),
    ],
)
async def test_rejects_unbounded_or_ambiguous_gateway_responses(
    tmp_path,
    headers: dict[str, str],
    content: bytes,
    message: str,
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=headers, content=content)

    client, _ = _client(tmp_path, handler)
    try:
        with pytest.raises(ExecutorControlProtocolError, match=message):
            await client.ensure_cluster_registration(
                cluster_id="cluster-a",
                display_name="生产集群 A",
                default_namespace="sentinelops-system",
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_rejects_chunked_oversized_response_while_streaming(tmp_path) -> None:
    stream = _ObservedAsyncStream(
        [
            b"x" * (MAX_EXECUTOR_RESPONSE_BYTES // 2),
            b"x" * (MAX_EXECUTOR_RESPONSE_BYTES // 2 + 1),
            b"must-not-be-read",
        ]
    )

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "Transfer-Encoding": "chunked",
            },
            stream=stream,
        )

    client, _ = _client(tmp_path, handler)
    try:
        with pytest.raises(ExecutorControlProtocolError, match="size limit"):
            await client.ensure_cluster_registration(
                cluster_id="cluster-a",
                display_name="生产集群 A",
                default_namespace="sentinelops-system",
            )
    finally:
        await client.aclose()

    assert stream.yielded == 2
    assert stream.closed is True


@pytest.mark.asyncio
async def test_accepts_normal_chunked_response_without_content_length(tmp_path) -> None:
    expected_registration = _registration()
    payload = TypeAdapter(ClusterRegistration).dump_json(expected_registration)
    stream = _ObservedAsyncStream(
        [payload[:17], payload[17:53], payload[53:]]
    )

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "Transfer-Encoding": "chunked",
            },
            stream=stream,
        )

    client, _ = _client(tmp_path, handler)
    try:
        registration = await client.ensure_cluster_registration(
            cluster_id="cluster-a",
            display_name="生产集群 A",
            default_namespace="sentinelops-system",
        )
    finally:
        await client.aclose()

    assert registration == expected_registration
    assert stream.yielded == 3
    assert stream.closed is True


@pytest.mark.asyncio
async def test_result_and_reconciliation_contracts_are_serialized(tmp_path) -> None:
    requests: list[tuple[str, dict[str, object]]] = []
    action = _action()
    result = ToolResult(
        tool_name=action.action.tool_name,
        success=True,
        content={"controller_phase": "Succeeded"},
        duration_ms=17.5,
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.url.path, json.loads(request.content)))
        return _json_response(action)

    client, _ = _client(tmp_path, handler)
    reconciliation = _reconciliation_claim()
    lease = _lease()
    try:
        await client.complete_action(
            claim=_claim(),
            agent_lease=lease,
            result=result,
        )
        await client.complete_action_reconciliation(
            reconciliation,
            agent_lease=lease,
            result=result,
        )
        await client.retry_action_reconciliation(
            reconciliation,
            agent_lease=lease,
            error="controller still running",
            retry_after_seconds=2,
        )
        await client.dead_letter_action_reconciliation(
            reconciliation,
            agent_lease=lease,
            error="controller contract missing",
        )
    finally:
        await client.aclose()

    assert [item[0] for item in requests] == [
        f"{EXECUTOR_CONTROL_PREFIX}/action-claims/attempt-a/result",
        f"{EXECUTOR_CONTROL_PREFIX}/reconciliation-claims/reconcile-a/complete",
        f"{EXECUTOR_CONTROL_PREFIX}/reconciliation-claims/reconcile-a/retry",
        f"{EXECUTOR_CONTROL_PREFIX}/reconciliation-claims/reconcile-a/dead-letter",
    ]
    assert requests[0][1]["result"] == {
        "tool_name": "rollback_deployment",
        "success": True,
        "content": {"controller_phase": "Succeeded"},
        "error": None,
        "duration_ms": 17.5,
    }
    assert requests[0][1]["agent_lease"]["session_id"] == "session-a"
    assert requests[1][1]["claim"]["intent"]["cluster_id"] == "cluster-a"
    assert requests[1][1]["agent_lease"]["generation"] == 2
    assert requests[2][1]["retry_after_seconds"] == 2


@pytest.mark.asyncio
async def test_close_session_and_http_client(tmp_path) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    client, _ = _client(tmp_path, handler)
    lease = _lease()
    await client.close_cluster_agent(lease)
    await client.aclose()

    assert len(requests) == 1
    assert requests[0].method == "DELETE"
    assert requests[0].url.path == (f"{EXECUTOR_CONTROL_PREFIX}/sessions/session-a")
    assert json.loads(requests[0].content)["token"]["generation"] == 2
    assert client._client.is_closed is True
