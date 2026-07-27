from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinelops.domain import ToolResult
from sentinelops.executor_control import EXECUTOR_CONTROL_PREFIX
from sentinelops.storage.base import (
    ActionIntentConflictError,
    ActionReconciliationClaim,
    ClusterAgentLeaseConflictError,
    ClusterAgentLeaseToken,
    ClusterRegistrationConflictError,
    ExecutorClaim,
    IncidentStore,
    LeaseConflictError,
)
from sentinelops.workload_identity import (
    WorkloadIdentity,
    WorkloadIdentityAuthenticator,
)

_AGENT_LEASE = TypeAdapter(ClusterAgentLeaseToken)
_EXECUTOR_CLAIM = TypeAdapter(ExecutorClaim)
_RECONCILIATION_CLAIM = TypeAdapter(ActionReconciliationClaim)
_TOOL_RESULT = TypeAdapter(ToolResult)

StoreProvider = Callable[[], IncidentStore | None]
AuthenticatorProvider = Callable[[], WorkloadIdentityAuthenticator | None]

EXECUTOR_CONTROL_MAX_BODY_BYTES = 1_048_576


class ExecutorControlBodyLimitMiddleware:
    """Bound Executor control request bodies before parsing or authentication."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = EXECUTOR_CONTROL_MAX_BODY_BYTES,
    ) -> None:
        if max_body_bytes <= 0:
            raise ValueError("Executor control request body limit must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http" or not self._is_executor_control_path(scope):
            await self.app(scope, receive, send)
            return

        try:
            content_length = self._content_length(scope)
        except ValueError:
            await self._respond(
                scope,
                receive,
                send,
                status_code=400,
                detail="Invalid Content-Length header",
            )
            return
        if (
            content_length is not None
            and content_length > self.max_body_bytes
        ):
            await self._respond(
                scope,
                receive,
                send,
                status_code=413,
                detail="Executor control request body is too large",
            )
            return

        buffered: list[Message] = []
        received_bytes = 0
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            received_bytes += len(message.get("body", b""))
            if received_bytes > self.max_body_bytes:
                await self._respond(
                    scope,
                    receive,
                    send,
                    status_code=413,
                    detail="Executor control request body is too large",
                )
                return
            if not message.get("more_body", False):
                break

        buffered_index = 0

        async def replay_receive() -> Message:
            nonlocal buffered_index
            if buffered_index < len(buffered):
                message = buffered[buffered_index]
                buffered_index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    def _is_executor_control_path(scope: Scope) -> bool:
        path = str(scope.get("path", ""))
        return path == EXECUTOR_CONTROL_PREFIX or path.startswith(
            f"{EXECUTOR_CONTROL_PREFIX}/"
        )

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        raw_values = [
            value
            for name, value in scope.get("headers", [])
            if name.lower() == b"content-length"
        ]
        if not raw_values:
            return None
        values: list[str] = []
        try:
            for raw_value in raw_values:
                values.extend(
                    part.strip() for part in raw_value.decode("ascii").split(",")
                )
        except UnicodeDecodeError as exc:
            raise ValueError("Content-Length is not ASCII") from exc
        if not values or any(not value or not value.isdecimal() for value in values):
            raise ValueError("Content-Length is invalid")
        try:
            lengths = {int(value, 10) for value in values}
        except ValueError as exc:
            raise ValueError("Content-Length is invalid") from exc
        if len(lengths) != 1:
            raise ValueError("Conflicting Content-Length headers")
        return lengths.pop()

    @staticmethod
    async def _respond(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        detail: str,
    ) -> None:
        await JSONResponse(
            status_code=status_code,
            content={"detail": detail},
        )(scope, receive, send)


class _StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClusterRegistrationRequest(_StrictRequest):
    cluster_id: str = Field(min_length=1, max_length=63)
    display_name: str = Field(min_length=1, max_length=128)
    default_namespace: str = Field(min_length=1, max_length=63)


class SessionRegistrationRequest(_StrictRequest):
    cluster_id: str = Field(min_length=1, max_length=63)
    instance_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=64)
    capabilities: tuple[str, ...] = Field(min_length=1, max_length=32)
    version: str = Field(min_length=1, max_length=64)
    ttl_seconds: float = Field(gt=0, le=600)


class AgentLeaseRequest(_StrictRequest):
    token: dict[str, Any]
    ttl_seconds: float | None = Field(default=None, gt=0, le=600)


class ActionClaimRequest(_StrictRequest):
    agent_lease: dict[str, Any]
    owner_id: str = Field(min_length=1, max_length=200)
    attempt_id: str = Field(min_length=1, max_length=128)
    ttl_seconds: float = Field(gt=0, le=600)


class ActionClaimHeartbeatRequest(_StrictRequest):
    claim: dict[str, Any]
    agent_lease: dict[str, Any]
    ttl_seconds: float = Field(gt=0, le=600)


class ActionDispatchRequest(_StrictRequest):
    claim: dict[str, Any]
    agent_lease: dict[str, Any]


class ActionResultRequest(_StrictRequest):
    claim: dict[str, Any]
    agent_lease: dict[str, Any]
    result: dict[str, Any]


class ActionUnknownRequest(_StrictRequest):
    claim: dict[str, Any]
    agent_lease: dict[str, Any]
    reason: str = Field(min_length=1, max_length=2_048)


class ReconciliationClaimRequest(_StrictRequest):
    agent_lease: dict[str, Any]
    owner_id: str = Field(min_length=1, max_length=200)
    ttl_seconds: float = Field(gt=0, le=600)


class ReconciliationResultRequest(_StrictRequest):
    claim: dict[str, Any]
    agent_lease: dict[str, Any]
    result: dict[str, Any]


class ReconciliationRetryRequest(_StrictRequest):
    claim: dict[str, Any]
    agent_lease: dict[str, Any]
    error: str = Field(min_length=1, max_length=2_048)
    retry_after_seconds: float = Field(gt=0, le=3_600)


class ReconciliationDeadLetterRequest(_StrictRequest):
    claim: dict[str, Any]
    agent_lease: dict[str, Any]
    error: str = Field(min_length=1, max_length=2_048)


def build_executor_control_router(
    *,
    store_provider: StoreProvider,
    authenticator_provider: AuthenticatorProvider,
) -> APIRouter:
    router = APIRouter(prefix=EXECUTOR_CONTROL_PREFIX)

    async def authorize(
        request: Request,
        *,
        capability: str,
        expected_pod_uid: str | None = None,
    ) -> WorkloadIdentity:
        authenticator = authenticator_provider()
        if authenticator is None:
            raise HTTPException(
                status_code=503,
                detail="Executor Workload Identity 尚未初始化",
            )
        return await authenticator.authenticate(
            request,
            required_capability=capability,
            expected_pod_uid=expected_pod_uid,
        )

    def store() -> IncidentStore:
        current = store_provider()
        if current is None:
            raise HTTPException(
                status_code=503,
                detail="Control Gateway 持久化尚未初始化",
            )
        return current

    @router.put("/clusters/{cluster_id}")
    async def ensure_cluster(
        cluster_id: str,
        body: ClusterRegistrationRequest,
        request: Request,
    ) -> Any:
        identity = await authorize(
            request,
            capability="agent.register",
        )
        trust = _trusted_cluster(authenticator_provider(), identity)
        if (
            cluster_id != identity.cluster_id
            or body.cluster_id != identity.cluster_id
            or body.display_name != trust.display_name
            or body.default_namespace != trust.default_namespace
        ):
            raise HTTPException(
                status_code=403,
                detail="Workload 身份不能修改权威集群元数据",
            )
        return await _store_result(
            store().ensure_cluster_registration(
                cluster_id=identity.cluster_id,
                display_name=trust.display_name,
                default_namespace=trust.default_namespace,
            )
        )

    @router.post("/sessions")
    async def register_session(
        body: SessionRegistrationRequest,
        request: Request,
    ) -> Any:
        identity = await authorize(
            request,
            capability="agent.register",
            expected_pod_uid=body.instance_id,
        )
        _require_cluster(identity, body.cluster_id)
        requested = frozenset(body.capabilities)
        if not requested.issubset(identity.allowed_capabilities):
            raise HTTPException(
                status_code=403,
                detail="Executor 请求了未授权的 capability",
            )
        return await _store_result(
            store().register_cluster_agent(
                cluster_id=identity.cluster_id,
                instance_id=body.instance_id,
                session_id=body.session_id,
                capabilities=tuple(sorted(requested)),
                version=body.version,
                ttl_seconds=body.ttl_seconds,
            )
        )

    @router.put("/sessions/{session_id}/heartbeat")
    async def heartbeat_session(
        session_id: str,
        body: AgentLeaseRequest,
        request: Request,
    ) -> Any:
        token = _validate(_AGENT_LEASE, body.token)
        identity = await authorize(
            request,
            capability="agent.heartbeat",
            expected_pod_uid=token.instance_id,
        )
        _require_cluster(identity, token.cluster_id)
        _require_path(session_id, token.session_id)
        return await _store_result(
            store().heartbeat_cluster_agent(
                token,
                ttl_seconds=body.ttl_seconds or 60,
            )
        )

    @router.delete("/sessions/{session_id}", status_code=204)
    async def close_session(
        session_id: str,
        body: AgentLeaseRequest,
        request: Request,
    ) -> Response:
        token = _validate(_AGENT_LEASE, body.token)
        identity = await authorize(
            request,
            capability="agent.heartbeat",
            expected_pod_uid=token.instance_id,
        )
        _require_cluster(identity, token.cluster_id)
        _require_path(session_id, token.session_id)
        result = await _store_result(store().close_cluster_agent(token))
        if isinstance(result, JSONResponse):
            return result
        return Response(status_code=204)

    @router.post("/action-claims")
    async def claim_action(
        body: ActionClaimRequest,
        request: Request,
    ) -> Any:
        lease = _validate(_AGENT_LEASE, body.agent_lease)
        identity = await authorize(
            request,
            capability="action.execute",
            expected_pod_uid=lease.instance_id,
        )
        _require_cluster(identity, lease.cluster_id)
        if body.owner_id != identity.pod_uid:
            raise HTTPException(
                status_code=403,
                detail="Executor owner_id 必须绑定已验证的 Pod UID",
            )
        result = await _store_result(
            store().claim_action_execution(
                agent_lease=lease,
                owner_id=body.owner_id,
                attempt_id=body.attempt_id,
                ttl_seconds=body.ttl_seconds,
            )
        )
        return Response(status_code=204) if result is None else result

    @router.put("/action-claims/{attempt_id}/heartbeat")
    async def heartbeat_action(
        attempt_id: str,
        body: ActionClaimHeartbeatRequest,
        request: Request,
    ) -> Any:
        claim = _validate(_EXECUTOR_CLAIM, body.claim)
        lease = _validate(_AGENT_LEASE, body.agent_lease)
        identity = await authorize(
            request,
            capability="action.execute",
            expected_pod_uid=lease.instance_id,
        )
        _require_action_binding(identity, attempt_id, claim, lease=lease)
        return await _store_result(
            store().heartbeat_action_claim(
                claim,
                agent_lease=lease,
                ttl_seconds=body.ttl_seconds,
            )
        )

    @router.post("/action-claims/{attempt_id}/dispatch")
    async def dispatch_action(
        attempt_id: str,
        body: ActionDispatchRequest,
        request: Request,
    ) -> Any:
        claim = _validate(_EXECUTOR_CLAIM, body.claim)
        lease = _validate(_AGENT_LEASE, body.agent_lease)
        identity = await authorize(
            request,
            capability="action.execute",
            expected_pod_uid=lease.instance_id,
        )
        _require_action_binding(identity, attempt_id, claim, lease=lease)
        return await _store_result(
            store().mark_action_dispatched(
                claim,
                agent_lease=lease,
            )
        )

    @router.put("/action-claims/{attempt_id}/result")
    async def complete_action(
        attempt_id: str,
        body: ActionResultRequest,
        request: Request,
    ) -> Any:
        claim = _validate(_EXECUTOR_CLAIM, body.claim)
        lease = _validate(_AGENT_LEASE, body.agent_lease)
        result = _validate(_TOOL_RESULT, body.result)
        identity = await authorize(
            request,
            capability="action.execute",
            expected_pod_uid=lease.instance_id,
        )
        _require_action_binding(identity, attempt_id, claim, lease=lease)
        return await _store_result(
            store().complete_action(
                claim=claim,
                agent_lease=lease,
                result=result,
            )
        )

    @router.put("/action-claims/{attempt_id}/unknown")
    async def mark_unknown(
        attempt_id: str,
        body: ActionUnknownRequest,
        request: Request,
    ) -> Any:
        claim = _validate(_EXECUTOR_CLAIM, body.claim)
        lease = _validate(_AGENT_LEASE, body.agent_lease)
        identity = await authorize(
            request,
            capability="action.execute",
            expected_pod_uid=lease.instance_id,
        )
        _require_action_binding(identity, attempt_id, claim, lease=lease)
        return await _store_result(
            store().mark_action_unknown(
                claim=claim,
                agent_lease=lease,
                reason=body.reason,
            )
        )

    @router.post("/reconciliation-claims")
    async def claim_reconciliation(
        body: ReconciliationClaimRequest,
        request: Request,
    ) -> Any:
        lease = _validate(_AGENT_LEASE, body.agent_lease)
        identity = await authorize(
            request,
            capability="action.reconcile",
            expected_pod_uid=lease.instance_id,
        )
        _require_cluster(identity, lease.cluster_id)
        if body.owner_id != identity.pod_uid:
            raise HTTPException(
                status_code=403,
                detail="Reconciler owner_id 必须绑定已验证的 Pod UID",
            )
        result = await _store_result(
            store().claim_action_reconciliation(
                agent_lease=lease,
                owner_id=body.owner_id,
                ttl_seconds=body.ttl_seconds,
            )
        )
        return Response(status_code=204) if result is None else result

    @router.put("/reconciliation-claims/{attempt_id}/complete")
    async def complete_reconciliation(
        attempt_id: str,
        body: ReconciliationResultRequest,
        request: Request,
    ) -> Any:
        claim = _validate(_RECONCILIATION_CLAIM, body.claim)
        lease = _validate(_AGENT_LEASE, body.agent_lease)
        result = _validate(_TOOL_RESULT, body.result)
        identity = await authorize(
            request,
            capability="action.reconcile",
            expected_pod_uid=lease.instance_id,
        )
        _require_reconciliation_binding(
            identity,
            attempt_id,
            claim,
            lease=lease,
        )
        return await _store_result(
            store().complete_action_reconciliation(
                claim,
                agent_lease=lease,
                result=result,
            )
        )

    @router.put("/reconciliation-claims/{attempt_id}/retry")
    async def retry_reconciliation(
        attempt_id: str,
        body: ReconciliationRetryRequest,
        request: Request,
    ) -> Any:
        claim = _validate(_RECONCILIATION_CLAIM, body.claim)
        lease = _validate(_AGENT_LEASE, body.agent_lease)
        identity = await authorize(
            request,
            capability="action.reconcile",
            expected_pod_uid=lease.instance_id,
        )
        _require_reconciliation_binding(
            identity,
            attempt_id,
            claim,
            lease=lease,
        )
        return await _store_result(
            store().retry_action_reconciliation(
                claim,
                agent_lease=lease,
                error=body.error,
                retry_after_seconds=body.retry_after_seconds,
            )
        )

    @router.put("/reconciliation-claims/{attempt_id}/dead-letter")
    async def dead_letter_reconciliation(
        attempt_id: str,
        body: ReconciliationDeadLetterRequest,
        request: Request,
    ) -> Any:
        claim = _validate(_RECONCILIATION_CLAIM, body.claim)
        lease = _validate(_AGENT_LEASE, body.agent_lease)
        identity = await authorize(
            request,
            capability="action.reconcile",
            expected_pod_uid=lease.instance_id,
        )
        _require_reconciliation_binding(
            identity,
            attempt_id,
            claim,
            lease=lease,
        )
        return await _store_result(
            store().dead_letter_action_reconciliation(
                claim,
                agent_lease=lease,
                error=body.error,
            )
        )

    return router


def _trusted_cluster(
    authenticator: WorkloadIdentityAuthenticator | None,
    identity: WorkloadIdentity,
) -> Any:
    if authenticator is None:
        raise HTTPException(status_code=503, detail="Workload Identity 尚未初始化")
    trust = authenticator.trusts.get(identity.cluster_id)
    if trust is None:
        raise HTTPException(status_code=403, detail="Workload 集群身份未登记")
    return trust


def _validate(adapter: TypeAdapter[Any], value: object) -> Any:
    try:
        return adapter.validate_python(value)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Executor 控制协议字段无效") from exc


def _require_cluster(identity: WorkloadIdentity, cluster_id: str) -> None:
    if cluster_id != identity.cluster_id:
        raise HTTPException(status_code=403, detail="禁止跨集群控制请求")


def _require_path(actual: str, expected: str) -> None:
    if actual != expected:
        raise HTTPException(status_code=403, detail="控制请求路径与租约不一致")


def _require_claim(
    identity: WorkloadIdentity,
    attempt_id: str,
    claim: ExecutorClaim,
) -> None:
    _require_cluster(identity, claim.cluster_id)
    _require_path(attempt_id, claim.attempt_id)
    if claim.owner_id != identity.pod_uid:
        raise HTTPException(status_code=403, detail="Action claim 不属于当前 Pod")


def _require_action_binding(
    identity: WorkloadIdentity,
    attempt_id: str,
    claim: ExecutorClaim,
    *,
    lease: ClusterAgentLeaseToken,
) -> None:
    _require_claim(identity, attempt_id, claim)
    _require_cluster(identity, lease.cluster_id)
    if (
        lease.instance_id != identity.pod_uid
        or claim.session_id != lease.session_id
        or claim.session_generation != lease.generation
    ):
        raise HTTPException(status_code=403, detail="Action claim 与 Session 不一致")


def _require_reconciliation(
    identity: WorkloadIdentity,
    attempt_id: str,
    claim: ActionReconciliationClaim,
) -> None:
    _require_cluster(identity, claim.cluster_id)
    _require_path(attempt_id, claim.attempt_id)
    if claim.owner_id != identity.pod_uid:
        raise HTTPException(status_code=403, detail="对账 claim 不属于当前 Pod")


def _require_reconciliation_binding(
    identity: WorkloadIdentity,
    attempt_id: str,
    claim: ActionReconciliationClaim,
    *,
    lease: ClusterAgentLeaseToken,
) -> None:
    _require_reconciliation(identity, attempt_id, claim)
    _require_cluster(identity, lease.cluster_id)
    if (
        lease.instance_id != identity.pod_uid
        or claim.session_id != lease.session_id
        or claim.session_generation != lease.generation
    ):
        raise HTTPException(status_code=403, detail="对账 claim 与 Session 不一致")


async def _store_result(operation: Awaitable[Any]) -> Any:
    try:
        result = await operation
    except ClusterRegistrationConflictError as exc:
        return _conflict("cluster_registration_conflict", exc, status_code=409)
    except ClusterAgentLeaseConflictError as exc:
        return _conflict("cluster_agent_lease_conflict", exc, status_code=410)
    except LeaseConflictError as exc:
        return _conflict("lease_conflict", exc, status_code=410)
    except ActionIntentConflictError as exc:
        return _conflict("action_intent_conflict", exc, status_code=409)
    if result is None:
        return None
    return TypeAdapter(type(result)).dump_python(result, mode="json")


def _conflict(
    error_code: str,
    error: Exception,
    *,
    status_code: int,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error_code": error_code,
            "detail": str(error),
        },
    )
