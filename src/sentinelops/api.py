from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import socket
import weakref
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, ValidationError

from sentinelops import __version__
from sentinelops.agent import IncidentAgent
from sentinelops.change_proposals import (
    ChangeProposalPreview,
    ChangeProposalRejected,
    ChangeProposalRequest,
    DeploymentSnapshot,
    SubmittedChangeProposal,
    build_change_proposal,
)
from sentinelops.config import Settings, get_settings
from sentinelops.control_gateway import (
    ExecutorControlBodyLimitMiddleware,
    build_executor_control_router,
)
from sentinelops.demo import (
    build_demo_alert,
    enrich_alert_with_failed_trace,
    inject_auto_demo_fault,
    inject_demo_fault,
    reset_demo_environment,
)
from sentinelops.domain import (
    Alert,
    ExecutionStep,
    IncidentRecord,
    IncidentStatus,
    TimelineEvent,
    ToolResult,
)
from sentinelops.executor import ExecutorWorker, QueuedActionExecutor
from sentinelops.lab_profiles import LabIncidentProfile, LabMode, LabProfileCoordinator
from sentinelops.metrics import render_prometheus_metrics
from sentinelops.migration import require_current_schema
from sentinelops.operator_auth import (
    DEMO_OPERATE_PERMISSION,
    INCIDENT_APPROVE_PERMISSION,
    INCIDENT_CREATE_PERMISSION,
    INCIDENT_PROPOSE_PERMISSION,
    INCIDENT_VIEW_PERMISSION,
    UNLOCK_APPROVE_PERMISSION,
    UNLOCK_REQUEST_PERMISSION,
    OIDCAuthenticator,
    OperatorIdentity,
    operator_auth_configuration_error,
)
from sentinelops.remediation_controller import KubernetesRemediationGateway
from sentinelops.runtime import build_agent
from sentinelops.storage import (
    ApprovalConflictError,
    AuditAnchorUnlockConflictError,
    AuditAnchorUnlockDecision,
    AuditAnchorUnlockRequest,
    ChangeProposalConflictError,
    ClusterConnection,
    DurableActionJournal,
    IncidentStore,
    LeaseConflictError,
    LeaseToken,
    SqlIncidentStore,
    StoreConflictError,
    StoredIncident,
)
from sentinelops.tools import ToolRegistry, build_tool_registry
from sentinelops.workload_identity import WorkloadIdentityAuthenticator


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    await initialize_persistence()
    reconciliation_task = (
        asyncio.create_task(_reconciliation_loop())
        if incident_store is not None
        else None
    )
    try:
        yield
    finally:
        if reconciliation_task is not None:
            reconciliation_task.cancel()
            with suppress(asyncio.CancelledError):
                await reconciliation_task
        tasks = [*incident_tasks, *demo_fault_tasks]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await shutdown_persistence()

app = FastAPI(
    title="SentinelOps API",
    version=__version__,
    description="Model-agnostic Kubernetes incident diagnosis and remediation agent",
    lifespan=_lifespan,
)


@app.middleware("http")
async def _operator_auth_middleware(
    request: Request,
    call_next,
):
    path = request.url.path
    if not path.startswith("/api/v1/") or path == (
        "/api/v1/webhooks/alertmanager"
    ):
        return await call_next(request)
    if path.startswith("/api/v1/demo/"):
        permission = DEMO_OPERATE_PERMISSION
    elif path.startswith(
        "/api/v1/security/audit-anchor/unlock-requests"
    ):
        if request.method == "POST" and path.endswith("/decision"):
            permission = UNLOCK_APPROVE_PERMISSION
        elif (
            request.method == "POST"
            and path
            == "/api/v1/security/audit-anchor/unlock-requests"
        ):
            permission = UNLOCK_REQUEST_PERMISSION
        else:
            permission = INCIDENT_VIEW_PERMISSION
    elif request.method == "POST" and (
        path.endswith("/change-proposals/preview")
        or path.endswith("/change-proposals")
    ):
        permission = INCIDENT_PROPOSE_PERMISSION
    elif path.endswith("/approval"):
        permission = INCIDENT_APPROVE_PERMISSION
    elif request.method == "POST" and path == "/api/v1/incidents":
        permission = INCIDENT_CREATE_PERMISSION
    else:
        permission = INCIDENT_VIEW_PERMISSION
    try:
        request.state.operator_identity = await _require_operator(
            request,
            permission=permission,
        )
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )
    return await call_next(request)


app.add_middleware(ExecutorControlBodyLimitMiddleware)


incident_agents: dict[str, IncidentAgent] = {}
incident_records: dict[str, IncidentRecord] = {}
incident_versions: dict[str, int] = {}
incident_recovery_errors: dict[str, str] = {}
incident_store: IncidentStore | None = None
operator_authenticator: OIDCAuthenticator | None = None
workload_identity_authenticator: WorkloadIdentityAuthenticator | None = None
embedded_executor_task: asyncio.Task[None] | None = None
embedded_executor_tools: ToolRegistry | None = None
worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
alert_fingerprints: dict[tuple[str, str], str] = {}
resolved_incident_ids: set[str] = set()
incident_tasks: set[asyncio.Task[None]] = set()
demo_fault_tasks: set[asyncio.Task[None]] = set()
lab_profiles = LabProfileCoordinator()
incident_streams: dict[str, set[asyncio.Queue[str]]] = {}
incident_feed_streams: set[asyncio.Queue[str]] = set()

app.include_router(
    build_executor_control_router(
        store_provider=lambda: incident_store,
        authenticator_provider=lambda: workload_identity_authenticator,
    )
)


class ApprovalDecision(BaseModel):
    approval_id: str
    approval_version: int = Field(ge=1)
    approved: bool
    note: str = ""


class AuditAnchorUnlockCreate(BaseModel):
    expected_security_generation: int = Field(ge=1)
    change_ticket: str = Field(min_length=1, max_length=200)
    justification: str = Field(min_length=1, max_length=2_000)
    ttl_seconds: int = Field(default=1_800, ge=60, le=86_400)


class AuditAnchorUnlockDecisionBody(BaseModel):
    expected_request_version: int = Field(ge=1)
    expected_security_generation: int = Field(ge=1)
    approved: bool
    note: str = Field(default="", max_length=2_000)


class AuditAnchorUnlockView(BaseModel):
    request_id: str
    scope_id: str
    blocked_generation: int
    unlock_generation: int | None
    status: str
    version: int
    requester_principal_hash: str
    requester_issuer_hash: str
    change_ticket_sha256: str
    justification_sha256: str
    created_at: datetime
    expires_at: datetime
    approved_at: datetime | None
    lease_owner: str | None
    lease_generation: int
    lease_until: datetime | None
    local_snapshot_hash: str | None
    remote_snapshot_id: str | None
    remote_snapshot_root: str | None
    challenge_sha256: str | None
    attested_at: datetime | None
    completed_at: datetime | None
    terminal_reason_sha256: str | None


class AuditAnchorUnlockDecisionView(BaseModel):
    decision_id: str
    request_id: str
    request_version: int
    principal_hash: str
    issuer_hash: str
    role: str
    decision: str
    assurance: str
    note_sha256: str
    decided_at: datetime


class DemoFaultJob(BaseModel):
    id: str
    scenario: Literal[
        "bad_rollout",
        "transient_runtime_fault",
        "ambiguous_change_fault",
    ]
    status: Literal["injecting", "active", "failed"]
    phase: Literal[
        "resetting_baseline",
        "injecting_fault",
        "waiting_for_alert",
        "incident_started",
    ] = "resetting_baseline"
    incident_id: str | None = None
    result: dict[str, object] | None = None
    error: str | None = None


demo_fault_jobs: dict[str, DemoFaultJob] = {}
demo_fault_generations: dict[str, int] = {}
_demo_operation_generation = 0
_demo_write_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    weakref.WeakKeyDictionary()
)


class DemoResetJob(BaseModel):
    id: str
    status: Literal["resetting", "succeeded", "failed"]
    result: dict[str, object] | None = None
    error: str | None = None


demo_reset_jobs: dict[str, DemoResetJob] = {}


class RuntimeInfo(BaseModel):
    environment: str
    tool_backend: str
    model_provider: str
    model_name: str
    cluster_id: str
    cluster_display_name: str
    namespace: str
    approval_mode: str = "human_gated"
    alert_ingestion: str = "alertmanager_webhook"


class ClusterExecutorView(BaseModel):
    instance_id: str
    session_id: str
    generation: int
    version: str
    capabilities: list[str]
    connection_status: Literal["online", "offline"]
    last_seen_at: datetime
    lease_expires_at: datetime


class ClusterConnectionView(BaseModel):
    cluster_id: str
    display_name: str
    default_namespace: str
    connection_status: Literal["online", "offline"]
    routing_generation: int
    active_executors: int
    last_seen_at: datetime | None
    lease_expires_at: datetime | None
    capabilities: list[str]
    executors: list[ClusterExecutorView]


class AlertmanagerAlert(BaseModel):
    status: str = "firing"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str | None = None
    endsAt: str | None = None
    fingerprint: str = ""


class AlertmanagerPayload(BaseModel):
    status: str = "firing"
    receiver: str = ""
    alerts: list[AlertmanagerAlert] = Field(default_factory=list)


def _fingerprint(alert: AlertmanagerAlert) -> str:
    if alert.fingerprint:
        if len(alert.fingerprint) <= 128:
            return alert.fingerprint
        return hashlib.sha256(alert.fingerprint.encode()).hexdigest()
    canonical = json.dumps(alert.labels, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:24]


def _alert_binding_key(source_id: str, fingerprint: str) -> tuple[str, str]:
    return source_id, fingerprint


def _alert_from_alertmanager(item: AlertmanagerAlert, fingerprint: str) -> Alert:
    settings = get_settings()
    source_id = settings.alertmanager_source_id
    severity = item.labels.get("severity", "warning")
    if severity not in {"info", "warning", "critical"}:
        severity = "warning"
    return Alert(
        name=item.labels.get("alertname", "UnknownAlert"),
        namespace=item.labels.get("namespace", settings.kubernetes_namespace),
        service=item.labels.get("service", "unknown-service"),
        severity=severity,
        summary=item.annotations.get("summary", "Alertmanager reported a firing alert"),
        cluster_id=settings.cluster_id,
        starts_at=_alertmanager_time(item.startsAt) or datetime.now(UTC),
        labels={
            **item.labels,
            "cluster_id": settings.cluster_id,
            "source": "alertmanager",
            "alertmanager_source_id": source_id,
            "alertmanager_fingerprint": fingerprint,
        },
    )


def _alertmanager_time(value: str | None) -> datetime | None:
    if not value or value.startswith("0001-01-01"):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _webhook_auth_configuration_error(
    settings: Settings,
    *,
    production: bool,
) -> str | None:
    mode = settings.alertmanager_webhook_auth_mode
    if production and mode == "disabled":
        return (
            "生产环境禁止匿名 Alertmanager Webhook；"
            "请配置 bearer 或 hmac_sha256 认证"
        )
    if mode == "disabled":
        return None
    try:
        current_value = (
            settings.resolved_webhook_bearer_token()
            if mode == "bearer"
            else settings.resolved_webhook_signing_secret()
        ) or ""
        previous_value = (
            settings.resolved_webhook_bearer_token(previous=True)
            if mode == "bearer"
            else settings.resolved_webhook_signing_secret(previous=True)
        ) or ""
    except ValueError as exc:
        return str(exc)
    if mode == "bearer" and not current_value.strip():
        return "Bearer 模式缺少 SENTINELOPS_ALERTMANAGER_WEBHOOK_BEARER_TOKEN"
    if mode == "hmac_sha256" and not current_value.strip():
        return "HMAC 模式缺少 SENTINELOPS_ALERTMANAGER_WEBHOOK_SIGNING_SECRET"
    if (
        production
        and mode != "disabled"
        and len(current_value.encode()) < 32
    ):
        return "生产环境的 Alertmanager Webhook 密钥至少需要 32 字节"
    previous_configured = (
        (
            settings.alertmanager_webhook_previous_bearer_token is not None
            or bool(settings.alertmanager_webhook_previous_bearer_token_file)
        )
        if mode == "bearer"
        else (
            settings.alertmanager_webhook_previous_signing_secret is not None
            or bool(settings.alertmanager_webhook_previous_signing_secret_file)
        )
    )
    if previous_configured and not previous_value.strip():
        return "上一把 Alertmanager Webhook 密钥不能为空"
    if (
        previous_value
        and settings.alertmanager_webhook_previous_secret_expires_at is None
    ):
        return "配置上一把 Webhook 密钥时必须同时设置绝对失效时间"
    if production and previous_value and len(previous_value.encode()) < 32:
        return "生产环境的上一把 Alertmanager Webhook 密钥至少需要 32 字节"
    return None


def _single_request_header(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    return values[0] if len(values) == 1 else None


def _previous_webhook_secret_is_active(
    settings: Settings,
    *,
    now: datetime,
) -> bool:
    expires_at = settings.alertmanager_webhook_previous_secret_expires_at
    if expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    else:
        expires_at = expires_at.astimezone(UTC)
    return now <= expires_at


async def _bounded_webhook_body(
    request: Request,
    *,
    max_bytes: int,
) -> bytes:
    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1 or (
        content_types[0].split(";", 1)[0].strip().casefold()
        != "application/json"
    ):
        raise HTTPException(
            status_code=415,
            detail="Alertmanager Webhook 只接受 application/json",
        )
    content_encodings = request.headers.getlist("content-encoding")
    if len(content_encodings) > 1 or (
        content_encodings
        and content_encodings[0].strip().casefold() not in {"", "identity"}
    ):
        raise HTTPException(
            status_code=415,
            detail="Alertmanager Webhook 不支持压缩请求体",
        )
    content_lengths = request.headers.getlist("content-length")
    if len(content_lengths) > 1:
        raise HTTPException(status_code=413, detail="Webhook 请求体过大")
    if content_lengths:
        try:
            declared_length = int(content_lengths[0])
        except ValueError as exc:
            raise HTTPException(
                status_code=413,
                detail="Webhook 请求体长度无效",
            ) from exc
        if declared_length < 0 or declared_length > max_bytes:
            raise HTTPException(status_code=413, detail="Webhook 请求体过大")

    cached_body = getattr(request, "_body", None)
    if cached_body is not None:
        if len(cached_body) > max_bytes:
            raise HTTPException(status_code=413, detail="Webhook 请求体过大")
        return bytes(cached_body)

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise HTTPException(status_code=413, detail="Webhook 请求体过大")
    request._body = bytes(body)
    return request._body


async def _authenticate_alertmanager_webhook(
    request: Request,
    settings: Settings,
) -> None:
    production = settings.environment.strip().casefold() in {"prod", "production"}
    configuration_error = _webhook_auth_configuration_error(
        settings,
        production=production,
    )
    if configuration_error is not None:
        raise HTTPException(status_code=503, detail=configuration_error)

    mode = settings.alertmanager_webhook_auth_mode
    if mode == "disabled":
        return
    if mode == "bearer":
        authorization = _single_request_header(request, "authorization") or ""
        scheme, separator, credential = authorization.partition(" ")
        current_token = settings.resolved_webhook_bearer_token() or ""
        current_matches = hmac.compare_digest(credential, current_token)
        previous_token = settings.resolved_webhook_bearer_token(previous=True)
        previous_matches = False
        if previous_token is not None and _previous_webhook_secret_is_active(
            settings,
            now=datetime.now(UTC),
        ):
            previous_matches = hmac.compare_digest(
                credential,
                previous_token,
            )
        authenticated = (
            bool(separator)
            and scheme.casefold() == "bearer"
            and bool(credential)
            and (current_matches or previous_matches)
        )
        if not authenticated:
            raise HTTPException(
                status_code=401,
                detail="Alertmanager Webhook 认证失败",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return

    timestamp_text = (
        _single_request_header(request, "x-sentinelops-timestamp") or ""
    )
    signature = _single_request_header(request, "x-sentinelops-signature") or ""
    timestamp = (
        int(timestamp_text)
        if timestamp_text.isascii()
        and timestamp_text.isdecimal()
        and timestamp_text == str(int(timestamp_text))
        else 0
    )
    now_datetime = datetime.now(UTC)
    now = int(now_datetime.timestamp())
    if (
        timestamp <= 0
        or now - timestamp > settings.alertmanager_webhook_signature_ttl_seconds
        or timestamp - now
        > settings.alertmanager_webhook_signature_future_skew_seconds
    ):
        raise HTTPException(
            status_code=401,
            detail="Alertmanager Webhook 认证失败",
        )
    body = await _bounded_webhook_body(
        request,
        max_bytes=settings.alertmanager_webhook_max_body_bytes,
    )
    message = (
        b"sentinelops.alertmanager.v1\n"
        + timestamp_text.encode()
        + b"\n"
        + body
    )
    current_signature = hmac.new(
        (settings.resolved_webhook_signing_secret() or "").encode(),
        message,
        hashlib.sha256,
    ).hexdigest()
    provided_signature = (
        signature.removeprefix("v1=")
        if signature.startswith("v1=")
        else ""
    )
    current_matches = hmac.compare_digest(
        provided_signature,
        current_signature,
    )
    previous_matches = False
    previous_secret = settings.resolved_webhook_signing_secret(previous=True)
    if previous_secret is not None and _previous_webhook_secret_is_active(
        settings,
        now=now_datetime,
    ):
        previous_signature = hmac.new(
            previous_secret.encode(),
            message,
            hashlib.sha256,
        ).hexdigest()
        previous_matches = hmac.compare_digest(
            provided_signature,
            previous_signature,
        )
    if not (current_matches or previous_matches):
        raise HTTPException(
            status_code=401,
            detail="Alertmanager Webhook 认证失败",
        )


def _publish_incident(record: IncidentRecord) -> None:
    incident_records[record.id] = record
    payload = record.model_dump_json()
    queues = [*incident_streams.get(record.id, set()), *incident_feed_streams]
    for queue in queues:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        queue.put_nowait(payload)


async def initialize_persistence(
    store: IncidentStore | None = None,
    *,
    create_schema: bool | None = None,
) -> None:
    """Connect the durable store and restore safe approval pause points."""

    global embedded_executor_task, embedded_executor_tools, incident_store
    global operator_authenticator, workload_identity_authenticator

    settings = get_settings()
    production = settings.environment.strip().casefold() in {"prod", "production"}
    webhook_auth_error = _webhook_auth_configuration_error(
        settings,
        production=production,
    )
    if webhook_auth_error is not None:
        raise RuntimeError(webhook_auth_error)
    try:
        audit_hmac_key = settings.resolved_audit_hmac_key()
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    if production and (
        not audit_hmac_key
        or len(audit_hmac_key.encode()) < 32
        or settings.audit_key_id == "development-unkeyed"
    ):
        raise RuntimeError(
            "生产环境必须配置至少 32 字节的独立审计 HMAC Key 和稳定 AUDIT_KEY_ID"
        )
    if production and settings.executor_mode != "external":
        raise RuntimeError(
            "生产环境必须使用独立 Executor：设置 SENTINELOPS_EXECUTOR_MODE=external"
        )
    if production and settings.executor_backend != "controller":
        raise RuntimeError(
            "生产环境 Executor 必须通过 SentinelRemediation Controller 执行"
        )
    if production and (
        settings.control_gateway_auth_mode != "workload_oidc"
        or not settings.control_gateway_trust_bundle_file
    ):
        raise RuntimeError(
            "生产环境必须配置 Workload OIDC Control Gateway 信任清单"
        )
    if production and settings.alertmanager_source_id == "default":
        raise RuntimeError(
            "生产环境必须配置稳定且唯一的 SENTINELOPS_ALERTMANAGER_SOURCE_ID"
        )
    if production and settings.cluster_id in {
        "local",
        "default",
        "legacy-unassigned",
    }:
        raise RuntimeError(
            "生产环境必须配置稳定且唯一的 SENTINELOPS_CLUSTER_ID"
        )
    if production and settings.database_auto_create:
        raise RuntimeError(
            "生产环境禁止自动建表；请使用单独的 sentinelops db-init 迁移任务"
        )
    operator_auth_error = operator_auth_configuration_error(
        settings,
        production=production,
    )
    if operator_auth_error is not None:
        raise RuntimeError(operator_auth_error)
    if production and store is not None and (
        getattr(store, "audit_auth_algorithm", None) != "hmac-sha256"
        or getattr(store, "audit_key_id", None) != settings.audit_key_id
    ):
        raise RuntimeError("生产 IncidentStore 未绑定配置的审计 HMAC Key")
    if store is None:
        try:
            database_url = settings.resolved_database_url()
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        if not database_url:
            if settings.environment.strip().casefold() in {"prod", "production"}:
                raise RuntimeError("生产环境必须配置 SENTINELOPS_DATABASE_URL")
            return
        store = SqlIncidentStore(
            database_url,
            audit_hmac_key=audit_hmac_key,
            audit_key_id=settings.audit_key_id,
            operation_timeout_seconds=(
                settings.database_operation_timeout_seconds
            ),
        )
        should_create = (
            settings.database_auto_create if create_schema is None else create_schema
        )
    else:
        should_create = True if create_schema is None else create_schema

    if production and should_create:
        await store.close()
        raise RuntimeError(
            "生产环境禁止自动建表；请使用单独的 sentinelops db-init 迁移任务"
        )

    incident_store = store
    try:
        if should_create:
            await store.setup()
        else:
            await require_current_schema(store)
        await store.ensure_cluster_registration(
            cluster_id=settings.cluster_id,
            display_name=settings.cluster_display_name,
            default_namespace=settings.kubernetes_namespace,
        )
        if (
            settings.audit_anchor_enforcement_required
            and await store.audit_anchor_security_state() is None
        ):
            await store.set_audit_anchor_security_state(
                status="initializing",
                write_blocked=True,
                reason="first_reconciliation_pending",
                successful=False,
            )
        stored_incidents = await store.list()
        recoverable_incidents = await store.list_recoverable(
            cluster_id=settings.cluster_id
        )
    except Exception:
        await store.close()
        incident_store = None
        raise

    incident_records.clear()
    incident_agents.clear()
    incident_versions.clear()
    incident_recovery_errors.clear()
    alert_fingerprints.clear()

    if settings.executor_mode == "embedded":
        embedded_executor_tools = build_tool_registry(
            settings,
            allow_guarded_writes=settings.executor_backend == "direct",
        )

    for stored in stored_incidents:
        record = stored.record
        incident_records[record.id] = record
        incident_versions[record.id] = stored.version
        fingerprint = record.alert.labels.get("alertmanager_fingerprint")
        source_id = record.alert.labels.get("alertmanager_source_id")
        if (
            fingerprint
            and source_id
            and record.alert.cluster_id == settings.cluster_id
            and record.status not in {
                IncidentStatus.RESOLVED,
                IncidentStatus.REJECTED,
                IncidentStatus.FAILED,
                IncidentStatus.ESCALATED,
            }
        ):
            alert_fingerprints[_alert_binding_key(source_id, fingerprint)] = record.id

    for stored in recoverable_incidents:
        record = stored.record
        incident_records[record.id] = record
        incident_versions[record.id] = stored.version
        fingerprint = record.alert.labels.get("alertmanager_fingerprint")
        source_id = record.alert.labels.get("alertmanager_source_id")
        if (
            fingerprint
            and source_id
            and record.alert.cluster_id == settings.cluster_id
            and record.status not in {
                IncidentStatus.RESOLVED,
                IncidentStatus.REJECTED,
                IncidentStatus.FAILED,
                IncidentStatus.ESCALATED,
            }
        ):
            alert_fingerprints[_alert_binding_key(source_id, fingerprint)] = record.id
        await _reconcile_stored_incident(store, stored, settings=settings)

    if settings.operator_auth_mode == "oidc":
        operator_authenticator = OIDCAuthenticator(settings)
    if settings.control_gateway_auth_mode == "workload_oidc":
        if not settings.control_gateway_trust_bundle_file:
            raise RuntimeError(
                "Workload OIDC Control Gateway 缺少 trust bundle"
            )
        try:
            workload_identity_authenticator = WorkloadIdentityAuthenticator.from_file(
                settings.control_gateway_trust_bundle_file,
                production=production,
                timeout_seconds=(
                    settings.control_gateway_jwks_timeout_seconds
                ),
                clock_skew_seconds=(
                    settings.control_gateway_clock_skew_seconds
                ),
                max_token_lifetime_seconds=(
                    settings.control_gateway_max_token_lifetime_seconds
                ),
                jwks_cache_seconds=(
                    settings.control_gateway_jwks_cache_seconds
                ),
                jwks_hard_cache_seconds=(
                    settings.control_gateway_jwks_hard_cache_seconds
                ),
                jwks_min_refresh_seconds=(
                    settings.control_gateway_jwks_min_refresh_seconds
                ),
            )
        except Exception:
            if operator_authenticator is not None:
                await operator_authenticator.close()
                operator_authenticator = None
            await store.close()
            incident_store = None
            raise

    if settings.executor_mode == "embedded":
        assert embedded_executor_tools is not None
        executor = ExecutorWorker(
            store,
            (
                embedded_executor_tools
                if settings.executor_backend == "direct"
                else None
            ),
            owner_id=f"embedded-executor:{worker_id}",
            cluster_id=settings.cluster_id,
            cluster_display_name=settings.cluster_display_name,
            default_namespace=settings.kubernetes_namespace,
            instance_id=f"embedded-executor:{worker_id}",
            remediation_gateway=(
                KubernetesRemediationGateway(
                    settings.kubernetes_namespace,
                    cluster_id=settings.cluster_id,
                    poll_interval_seconds=settings.executor_poll_interval_seconds,
                    result_timeout_seconds=settings.executor_result_timeout_seconds,
                )
                if settings.executor_backend == "controller"
                else None
            ),
            claim_ttl_seconds=settings.executor_claim_ttl_seconds,
            poll_interval_seconds=settings.executor_poll_interval_seconds,
            missing_contract_grace_seconds=(
                settings.executor_missing_contract_grace_seconds
            ),
            registry_ttl_seconds=settings.executor_registry_ttl_seconds,
            registry_heartbeat_seconds=(
                settings.executor_registry_heartbeat_seconds
            ),
        )
        embedded_executor_task = asyncio.create_task(executor.run_forever())


async def _reconcile_stored_incident(
    store: IncidentStore,
    stored: StoredIncident,
    *,
    settings: Settings,
) -> None:
    record = stored.record
    if record.alert.cluster_id != settings.cluster_id:
        return
    nonterminal = record.status in {
        IncidentStatus.RECEIVED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.AWAITING_APPROVAL,
        IncidentStatus.REMEDIATING,
    }
    if not nonterminal and record.status != IncidentStatus.ESCALATED:
        return
    active_lease = await store.active_lease(record.id)
    if active_lease is not None:
        if active_lease.owner_id == worker_id:
            return
        incident_recovery_errors[record.id] = (
            f"事故正在由 Worker {active_lease.owner_id} 处理，请等待其提交结果"
        )
        return
    incident_recovery_errors.pop(record.id, None)

    intent = await store.mark_abandoned_action_unknown(
        record.id,
        reason="Worker 在派发集群操作后失联，执行结果未知且禁止自动重放",
    )
    if intent is not None:
        if intent.status in {"queued", "claimed"}:
            incident_recovery_errors[record.id] = (
                "Action Intent 已进入独立 Executor 队列，正在等待持久化执行结果"
            )
            return
        already_reconciled = any(
            event.type == "recovery.failed_closed"
            and event.data.get("action_intent_key") == intent.idempotency_key
            and event.data.get("action_intent_status") == intent.status
            for event in record.timeline
        )
        result_already_present = (
            intent.result is None or intent.result in record.execution_results
        )
        if already_reconciled and result_already_present:
            return
        intent_status = intent.status
        outcome = (
            "not_dispatched"
            if intent_status in {"prepared", "queued", "claimed", "cancelled"}
            else (
                "known_succeeded"
                if intent_status == "succeeded"
                else (
                    "known_failed"
                    if intent_status == "failed"
                    else "unknown"
                )
            )
        )
        await _escalate_unrecoverable_incident(
            store,
            record,
            stored.version,
            reason=(
                "持久化操作意图证明集群写入尚未派发；旧决策已失效并升级人工重新确认"
                if outcome == "not_dispatched"
                else (
                    "集群写入结果已经持久化，但恢复验证没有完成；"
                    "保留真实结果并升级人工验证"
                    if outcome.startswith("known_")
                    else "集群写入可能已经派发但没有可信结果，禁止自动重放"
                )
            ),
            execution_outcome=outcome,
            action_intent_status=intent_status,
            action_intent_key=intent.idempotency_key,
            action_result=intent.result,
        )
        return

    if record.status == IncidentStatus.ESCALATED:
        return

    if (
        record.status in {IncidentStatus.RECEIVED, IncidentStatus.INVESTIGATING}
        and record.alert.labels.get("source") == "alertmanager"
        and record.approval is None
        and not record.execution_results
    ):
        _schedule_investigation(record.id, record.alert, None)
        return

    if record.status == IncidentStatus.AWAITING_APPROVAL and record.approval is not None:
        approval_status = await store.approval_status(record.approval.approval_id)
        if approval_status == "pending" and stored.graph_state is not None:
            if record.id in incident_agents:
                return
            try:
                agent = build_agent(
                    settings,
                    profile_id=record.execution_profile_id,
                    progress_callback=_publish_incident,
                    tools=_agent_tool_registry(settings),
                )
                await agent.restore(record, stored.graph_state)
            except Exception as exc:
                incident_recovery_errors[record.id] = str(exc)
            else:
                incident_agents[record.id] = agent
            return
        if approval_status == "expired":
            expired = record.model_copy(deep=True)
            expired.timeline.append(
                TimelineEvent(
                    type="approval.expired",
                    message="审批窗口已到期，旧操作自动失效",
                    data={
                        "approval_id": record.approval.approval_id,
                        "approval_version": record.approval.version,
                        "execution_outcome": "not_dispatched",
                    },
                )
            )
            await _escalate_unrecoverable_incident(
                store,
                expired,
                stored.version,
                reason="人工审批已过期，确认没有派发集群写操作并升级人工重新调查",
                execution_outcome="not_dispatched",
            )
            return

    await _escalate_unrecoverable_incident(
        store,
        record,
        stored.version,
        reason="Worker 在集群写入派发前中断，确认没有执行写操作并停止自动重放",
        execution_outcome="not_dispatched",
    )


async def _reconcile_persistence_once() -> None:
    if incident_store is None:
        return
    await incident_store.reap_expired_action_claims()
    settings = get_settings()
    for stored in await incident_store.list_recoverable(
        cluster_id=settings.cluster_id
    ):
        if stored.record.alert.cluster_id != settings.cluster_id:
            continue
        incident_records[stored.record.id] = stored.record
        incident_versions[stored.record.id] = stored.version
        try:
            await _reconcile_stored_incident(
                incident_store,
                stored,
                settings=settings,
            )
        except Exception as exc:
            incident_recovery_errors[stored.record.id] = str(exc)


async def _reconciliation_loop() -> None:
    while True:
        await asyncio.sleep(get_settings().worker_reconciliation_interval_seconds)
        try:
            await _reconcile_persistence_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            # A transient database outage must not permanently kill recovery.
            continue


async def _escalate_unrecoverable_incident(
    store: IncidentStore,
    record: IncidentRecord,
    version: int,
    *,
    reason: str,
    execution_outcome: str | None = None,
    action_intent_status: str | None = None,
    action_intent_key: str | None = None,
    action_result: ToolResult | None = None,
) -> None:
    failed_closed = record.model_copy(deep=True)
    failed_closed.status = IncidentStatus.ESCALATED
    failed_closed.approval = None
    failed_closed.active_step_id = None
    if action_result is not None and action_result not in failed_closed.execution_results:
        failed_closed.execution_results.append(action_result)
    failed_closed.timeline.append(
        TimelineEvent(
            type="recovery.failed_closed",
            message=reason,
            data={
                "automatic_replay": False,
                **(
                    {"execution_outcome": execution_outcome}
                    if execution_outcome is not None
                    else {}
                ),
                **(
                    {"action_intent_status": action_intent_status}
                    if action_intent_status is not None
                    else {}
                ),
                **(
                    {"action_intent_key": action_intent_key}
                    if action_intent_key is not None
                    else {}
                ),
            },
        )
    )
    try:
        stored = await store.save(
            failed_closed,
            expected_version=version,
            graph_state=None,
        )
    except StoreConflictError as exc:
        incident_recovery_errors[record.id] = str(exc)
        return
    incident_records[record.id] = stored.record
    incident_versions[record.id] = stored.version


async def shutdown_persistence() -> None:
    global embedded_executor_task, embedded_executor_tools, incident_store
    global operator_authenticator, workload_identity_authenticator

    if embedded_executor_task is not None:
        embedded_executor_task.cancel()
        with suppress(asyncio.CancelledError):
            await embedded_executor_task
        embedded_executor_task = None
    embedded_executor_tools = None
    if operator_authenticator is not None:
        await operator_authenticator.close()
        operator_authenticator = None
    if workload_identity_authenticator is not None:
        await workload_identity_authenticator.close()
        workload_identity_authenticator = None
    if incident_store is not None:
        await incident_store.close()
    incident_store = None


async def _require_operator(
    request: Request,
    *,
    permission: str,
) -> OperatorIdentity:
    settings = get_settings()
    if settings.operator_auth_mode == "disabled":
        return OperatorIdentity(
            issuer="unverified",
            subject="unattributed-api-client",
            subject_hash="unattributed-api-client",
            permissions=frozenset(),
            assurance="unverified",
            expires_at=None,
        )
    if operator_authenticator is None:
        raise HTTPException(
            status_code=503,
            detail="OIDC 操作者认证尚未初始化",
        )
    return await operator_authenticator.authenticate(
        request,
        required_permission=permission,
    )


def _verified_unlock_identity(request: Request) -> OperatorIdentity:
    identity = getattr(request.state, "operator_identity", None)
    if (
        not isinstance(identity, OperatorIdentity)
        or identity.assurance != "oidc-human"
        or len(identity.subject_hash) != 64
    ):
        raise HTTPException(
            status_code=403,
            detail="审计锚点解锁只接受已验证的 OIDC 人类身份",
        )
    return identity


def _unlock_operation_id(request: Request, *, action: str) -> str:
    values = request.headers.getlist("idempotency-key")
    if len(values) != 1:
        raise HTTPException(
            status_code=400,
            detail="解锁操作必须提供唯一的 Idempotency-Key",
        )
    key = values[0].strip()
    if not 8 <= len(key.encode()) <= 256 or any(
        ord(character) < 33 or ord(character) > 126 for character in key
    ):
        raise HTTPException(
            status_code=400,
            detail="Idempotency-Key 必须是 8 到 256 字节的可打印 ASCII",
        )
    digest = hashlib.sha256(key.encode()).hexdigest()
    return f"audit-anchor-unlock:{action}:{digest}"


def _unlock_view(
    request: AuditAnchorUnlockRequest,
) -> AuditAnchorUnlockView:
    return AuditAnchorUnlockView.model_validate(
        request,
        from_attributes=True,
    )


def _unlock_decision_view(
    decision: AuditAnchorUnlockDecision,
) -> AuditAnchorUnlockDecisionView:
    return AuditAnchorUnlockDecisionView.model_validate(
        decision,
        from_attributes=True,
    )


def _operator_token_expired(request: Request) -> bool:
    identity = getattr(request.state, "operator_identity", None)
    return (
        isinstance(identity, OperatorIdentity)
        and identity.expires_at is not None
        and datetime.now(UTC) >= identity.expires_at
    )


def _operator_stream_timeout(request: Request) -> float:
    identity = getattr(request.state, "operator_identity", None)
    if (
        not isinstance(identity, OperatorIdentity)
        or identity.expires_at is None
    ):
        return 15
    remaining = (
        identity.expires_at - datetime.now(UTC)
    ).total_seconds()
    return max(0.1, min(15, remaining))


async def _persist_incident(
    record: IncidentRecord,
    *,
    agent: IncidentAgent | None = None,
    lease_token: LeaseToken | None = None,
) -> None:
    if incident_store is None:
        return
    graph_state = (
        await agent.export_state(record.id)
        if agent is not None and record.status == IncidentStatus.AWAITING_APPROVAL
        else None
    )
    expected_version = incident_versions.get(record.id)
    try:
        stored = await incident_store.save(
            record,
            expected_version=expected_version,
            graph_state=graph_state,
            lease_token=lease_token,
        )
    except StoreConflictError:
        current = await incident_store.get(record.id)
        if current is not None:
            resolved_events = [
                event
                for event in current.record.timeline
                if event.type == "alertmanager.resolved"
            ]
            intent = await incident_store.latest_action_intent(record.id)
            if (
                lease_token is not None
                and record.execution_results
                and resolved_events
                and intent is not None
                and intent.status in {"succeeded", "failed"}
            ):
                merged = record.model_copy(deep=True)
                existing = {
                    (event.type, event.created_at, event.message)
                    for event in merged.timeline
                }
                merged.timeline.extend(
                    event
                    for event in resolved_events
                    if (event.type, event.created_at, event.message) not in existing
                )
                stored = await incident_store.save(
                    merged,
                    expected_version=current.version,
                    graph_state=None,
                    lease_token=lease_token,
                )
                incident_records[record.id] = stored.record
                incident_versions[record.id] = stored.version
                record.updated_at = stored.record.updated_at
                return
            incident_records[record.id] = current.record
            incident_versions[record.id] = current.version
        raise
    incident_versions[record.id] = stored.version
    record.updated_at = stored.record.updated_at


@asynccontextmanager
async def _incident_lease(incident_id: str) -> AsyncIterator[LeaseToken | None]:
    if incident_store is None:
        yield None
        return
    settings = get_settings()
    token = await incident_store.acquire_lease(
        incident_id,
        owner_id=worker_id,
        ttl_seconds=settings.worker_lease_ttl_seconds,
    )
    heartbeat_interval = min(
        settings.worker_lease_heartbeat_seconds,
        settings.worker_lease_ttl_seconds / 3,
    )

    async def heartbeat() -> None:
        while True:
            await asyncio.sleep(heartbeat_interval)
            await incident_store.heartbeat_lease(
                token,
                ttl_seconds=settings.worker_lease_ttl_seconds,
            )

    heartbeat_task = asyncio.create_task(heartbeat())
    try:
        yield token
    finally:
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError, LeaseConflictError):
            await heartbeat_task
        with suppress(LeaseConflictError):
            await incident_store.release_lease(token)


def _action_journal(token: LeaseToken | None) -> DurableActionJournal | None:
    if incident_store is None or token is None:
        return None
    return DurableActionJournal(incident_store, token)


def _action_executor(token: LeaseToken | None) -> QueuedActionExecutor | None:
    if incident_store is None or token is None:
        return None
    settings = get_settings()
    return QueuedActionExecutor(
        incident_store,
        token,
        poll_interval_seconds=min(
            settings.executor_poll_interval_seconds,
            0.25,
        ),
        result_timeout_seconds=settings.executor_result_timeout_seconds,
    )


def _agent_tool_registry(settings: Settings) -> ToolRegistry:
    if embedded_executor_tools is not None:
        return ToolRegistry(
            embedded_executor_tools.backend,
            embedded_executor_tools.list_specs(),
            allow_guarded_writes=False,
        )
    return build_tool_registry(settings, allow_guarded_writes=incident_store is None)


async def _investigate_alert(
    incident_id: str,
    alert: Alert,
    profile: LabIncidentProfile | None = None,
) -> None:
    settings = get_settings()
    if alert.cluster_id != settings.cluster_id:
        return
    lease_token: LeaseToken | None = None
    try:
        async with _incident_lease(incident_id) as token:
            lease_token = token
            fingerprint = alert.labels.get("alertmanager_fingerprint")
            if incident_store is not None and fingerprint:
                source_id = alert.labels.get(
                    "alertmanager_source_id",
                    settings.alertmanager_source_id,
                )
                active_incident = await incident_store.active_alert_incident(
                    source_id=source_id,
                    fingerprint=fingerprint,
                )
                durable_incident = await incident_store.get(incident_id)
                if (
                    active_incident != incident_id
                    or durable_incident is None
                    or durable_incident.record.status
                    not in {
                        IncidentStatus.RECEIVED,
                        IncidentStatus.INVESTIGATING,
                    }
                ):
                    return
            agent = build_agent(
                settings,
                runbook=profile.runbook if profile else None,
                profile_id=profile.id if profile else "production-default",
                auto_approve_max_risk=profile.auto_approve_max_risk if profile else None,
                verification_probe_url=(
                    settings.demo_order_url if profile and profile.enrich_failed_trace else None
                ),
                progress_callback=_publish_incident,
                action_journal=_action_journal(token),
                action_executor=_action_executor(token),
                tools=_agent_tool_registry(settings),
            )
            incident_agents[incident_id] = agent
            if incident_id in resolved_incident_ids:
                await agent.invalidate_pending_approval(
                    incident_id,
                    reason="Alertmanager 在调查启动前发送 resolved",
                )
            if profile and profile.enrich_failed_trace:
                alert = await enrich_alert_with_failed_trace(settings, alert)
                current = incident_records[incident_id].model_copy(deep=True)
                preflight = next(
                    (step for step in current.execution_trace if step.id == "enrich_trace:1"),
                    None,
                )
                if preflight:
                    completed_at = datetime.now(UTC)
                    preflight.status = "completed"
                    preflight.completed_at = completed_at
                    preflight.duration_ms = max(
                        0,
                        (
                            completed_at - (preflight.started_at or completed_at)
                        ).total_seconds()
                        * 1000,
                    )
                    preflight.detail = "已关联告警、失败请求和调用链上下文"
                    current.active_step_id = None
                    _publish_incident(current)
            record = await agent.start(alert, incident_id=incident_id)
            _publish_incident(record)
            await _persist_incident(record, agent=agent, lease_token=token)
    except LeaseConflictError:
        # Another API replica owns the durable investigation lease.
        return
    except StoreConflictError:
        # A newer replica or a resolved webhook already owns the durable truth.
        # Never overwrite it with this worker's stale completion.
        return
    except Exception as exc:
        current = incident_records[incident_id]
        failed = current.model_copy(
            update={
                "status": IncidentStatus.FAILED,
                "active_step_id": None,
                "timeline": [
                    *current.timeline,
                    TimelineEvent(
                        type="automation.failed",
                        message="自动调查失败",
                        data={"error": str(exc)},
                    ),
                ],
            }
        )
        _publish_incident(failed)
        with suppress(LeaseConflictError, StoreConflictError):
            await _persist_incident(failed, lease_token=lease_token)


def _schedule_investigation(
    incident_id: str,
    alert: Alert,
    profile: LabIncidentProfile | None = None,
) -> None:
    if alert.cluster_id != get_settings().cluster_id:
        return
    task = asyncio.create_task(_investigate_alert(incident_id, alert, profile))
    incident_tasks.add(task)
    task.add_done_callback(incident_tasks.discard)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/ready")
async def readiness() -> dict[str, str]:
    settings = get_settings()
    production = settings.environment.strip().casefold() in {"prod", "production"}
    if production and incident_store is None:
        raise HTTPException(status_code=503, detail="Durable incident store is not configured")
    if incident_store is not None:
        try:
            await incident_store.list(limit=1)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Durable incident store is unavailable",
            ) from exc
    return {"status": "ready"}


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    snapshot = (
        await incident_store.audit_anchor_metrics()
        if incident_store is not None
        else None
    )
    return Response(
        content=render_prometheus_metrics(snapshot),
        media_type="text/plain; version=0.0.4",
    )


@app.post(
    "/api/v1/security/audit-anchor/unlock-requests",
    response_model=AuditAnchorUnlockView,
    status_code=201,
)
async def create_audit_anchor_unlock_request(
    body: AuditAnchorUnlockCreate,
    request: Request,
) -> AuditAnchorUnlockView:
    if incident_store is None:
        raise HTTPException(
            status_code=503,
            detail="持久化存储不可用，禁止创建解锁申请",
        )
    identity = _verified_unlock_identity(request)
    operation_id = _unlock_operation_id(request, action="request")
    try:
        created = await incident_store.request_audit_anchor_unlock(
            expected_security_generation=body.expected_security_generation,
            requester_principal_hash=identity.subject_hash,
            requester_issuer=identity.issuer,
            change_ticket=body.change_ticket,
            justification=body.justification,
            ttl_seconds=body.ttl_seconds,
            operation_id=operation_id,
            actor_assurance=identity.assurance,
        )
    except AuditAnchorUnlockConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _unlock_view(created)


@app.get(
    "/api/v1/security/audit-anchor/unlock-requests/{request_id}",
    response_model=AuditAnchorUnlockView,
)
async def get_audit_anchor_unlock_request(
    request_id: str,
) -> AuditAnchorUnlockView:
    if incident_store is None:
        raise HTTPException(status_code=503, detail="持久化存储不可用")
    unlock_request = await incident_store.get_audit_anchor_unlock_request(
        request_id
    )
    if unlock_request is None:
        raise HTTPException(status_code=404, detail="解锁申请不存在")
    return _unlock_view(unlock_request)


@app.get(
    "/api/v1/security/audit-anchor/unlock-requests/{request_id}/decisions",
    response_model=list[AuditAnchorUnlockDecisionView],
)
async def list_audit_anchor_unlock_decisions(
    request_id: str,
) -> list[AuditAnchorUnlockDecisionView]:
    if incident_store is None:
        raise HTTPException(status_code=503, detail="持久化存储不可用")
    unlock_request = await incident_store.get_audit_anchor_unlock_request(
        request_id
    )
    if unlock_request is None:
        raise HTTPException(status_code=404, detail="解锁申请不存在")
    decisions = await incident_store.list_audit_anchor_unlock_decisions(
        request_id
    )
    return [_unlock_decision_view(item) for item in decisions]


@app.post(
    "/api/v1/security/audit-anchor/unlock-requests/{request_id}/decision",
    response_model=AuditAnchorUnlockView,
)
async def decide_audit_anchor_unlock_request(
    request_id: str,
    body: AuditAnchorUnlockDecisionBody,
    request: Request,
) -> AuditAnchorUnlockView:
    if incident_store is None:
        raise HTTPException(
            status_code=503,
            detail="持久化存储不可用，禁止审批解锁",
        )
    identity = _verified_unlock_identity(request)
    operation_id = _unlock_operation_id(request, action="decision")
    try:
        decided = await incident_store.decide_audit_anchor_unlock(
            request_id=request_id,
            expected_request_version=body.expected_request_version,
            expected_security_generation=body.expected_security_generation,
            approver_principal_hash=identity.subject_hash,
            approver_issuer=identity.issuer,
            approved=body.approved,
            note=body.note,
            operation_id=operation_id,
            actor_assurance=identity.assurance,
        )
    except AuditAnchorUnlockConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _unlock_view(decided)


@app.post("/api/v1/incidents", response_model=IncidentRecord, status_code=201)
async def create_incident(alert: Alert) -> IncidentRecord:
    settings = get_settings()
    if alert.cluster_id != settings.cluster_id:
        raise HTTPException(
            status_code=409,
            detail=(
                f"事故绑定集群 {alert.cluster_id} 与当前控制面集群 "
                f"{settings.cluster_id} 不一致"
            ),
        )
    placeholder = IncidentRecord(alert=alert)
    _publish_incident(placeholder)
    await _persist_incident(placeholder)
    lease_token: LeaseToken | None = None
    try:
        async with _incident_lease(placeholder.id) as token:
            lease_token = token
            settings = get_settings()
            incident_agent = build_agent(
                settings,
                progress_callback=_publish_incident,
                action_journal=_action_journal(token),
                action_executor=_action_executor(token),
                tools=_agent_tool_registry(settings),
            )
            record = await incident_agent.start(alert, incident_id=placeholder.id)
            incident_agents[record.id] = incident_agent
            _publish_incident(record)
            await _persist_incident(
                record,
                agent=incident_agent,
                lease_token=token,
            )
    except Exception as exc:
        failed = placeholder.model_copy(
            update={
                "status": IncidentStatus.FAILED,
                "timeline": [
                    *placeholder.timeline,
                    TimelineEvent(
                        type="automation.failed",
                        message="自动调查失败",
                        data={"error": str(exc)},
                    ),
                ],
            }
        )
        _publish_incident(failed)
        with suppress(LeaseConflictError, StoreConflictError):
            await _persist_incident(failed, lease_token=lease_token)
        raise HTTPException(status_code=503, detail="Incident investigation failed") from exc
    return record


@app.post("/api/v1/demo/incidents", response_model=IncidentRecord, status_code=201)
async def create_demo_incident() -> IncidentRecord:
    _require_demo_api_enabled()
    try:
        alert = await build_demo_alert(get_settings())
        return await create_incident(alert)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


async def _run_demo_fault(job_id: str) -> None:
    settings = get_settings()
    job = demo_fault_jobs[job_id]
    generation = demo_fault_generations.get(job_id, _demo_operation_generation)
    try:
        async with _demo_write_lock():
            if _demo_fault_was_invalidated(job_id, generation):
                _mark_demo_fault_invalidated(job_id)
                return
            await reset_demo_environment(settings)
            if _demo_fault_was_invalidated(job_id, generation):
                _mark_demo_fault_invalidated(job_id)
                return
            await _release_demo_alert_deduplication()
            lab_profiles.arm(_job_profile_mode(job), job.id)
            demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
                update={"phase": "injecting_fault"}
            )
            result = await asyncio.wait_for(
                (
                    inject_auto_demo_fault(settings)
                    if job.scenario == "transient_runtime_fault"
                    else inject_demo_fault(settings)
                ),
                timeout=settings.demo_alert_timeout_seconds + 10,
            )
            if _demo_fault_was_invalidated(job_id, generation):
                _disarm_job_profile(job)
                _mark_demo_fault_invalidated(job_id)
                return
    except TimeoutError:
        _disarm_job_profile(job)
        demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
            update={
                "status": "failed",
                "error": (
                    "连接 kind Kubernetes API 超时，"
                    "请确认 Docker Desktop 和 kind 集群正在运行。"
                ),
            }
        )
    except Exception as exc:
        _disarm_job_profile(job)
        demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
            update={"status": "failed", "error": str(exc)}
        )
    else:
        if job.scenario == "ambiguous_change_fault":
            result = {
                **result,
                "fault_type": "ambiguous_change_fault",
                "investigation_mode": "bounded_reflection",
            }
        demo_fault_jobs[job_id] = demo_fault_jobs[job_id].model_copy(
            update={"status": "active", "phase": "waiting_for_alert", "result": result}
        )


@app.post("/api/v1/demo/faults", response_model=DemoFaultJob, status_code=202)
async def create_demo_fault() -> DemoFaultJob:
    _require_demo_api_enabled()
    return _create_demo_fault_job("bad_rollout")


@app.post("/api/v1/demo/auto-faults", response_model=DemoFaultJob, status_code=202)
async def create_auto_demo_fault() -> DemoFaultJob:
    _require_demo_api_enabled()
    return _create_demo_fault_job("transient_runtime_fault")


@app.post("/api/v1/demo/reflection-faults", response_model=DemoFaultJob, status_code=202)
async def create_reflection_demo_fault() -> DemoFaultJob:
    _require_demo_api_enabled()
    return _create_demo_fault_job("ambiguous_change_fault")


async def _run_demo_reset(job_id: str) -> None:
    try:
        async with _demo_write_lock():
            result = await reset_demo_environment(get_settings())
            await _release_demo_alert_deduplication()
        demo_reset_jobs[job_id] = demo_reset_jobs[job_id].model_copy(
            update={"status": "succeeded", "result": result}
        )
    except Exception as exc:
        demo_reset_jobs[job_id] = demo_reset_jobs[job_id].model_copy(
            update={"status": "failed", "error": str(exc)}
        )


@app.post("/api/v1/demo/reset", response_model=DemoResetJob, status_code=202)
async def reset_demo() -> DemoResetJob:
    global _demo_operation_generation

    _require_demo_api_enabled()
    active_job = next(
        (job for job in demo_reset_jobs.values() if job.status == "resetting"),
        None,
    )
    if active_job:
        return active_job

    # Record reset intent before the background task waits for the write lock. Any
    # running or queued injector from the previous generation must not publish an
    # active fault after the operator has requested a healthy baseline.
    _demo_operation_generation += 1
    lab_profiles.clear()
    for fault_job in list(demo_fault_jobs.values()):
        if fault_job.status in {"injecting", "active"}:
            _mark_demo_fault_invalidated(fault_job.id)

    job = DemoResetJob(id=str(uuid4()), status="resetting")
    demo_reset_jobs[job.id] = job
    task = asyncio.create_task(_run_demo_reset(job.id))
    demo_fault_tasks.add(task)
    task.add_done_callback(demo_fault_tasks.discard)
    return job


@app.get("/api/v1/demo/resets/{job_id}", response_model=DemoResetJob)
async def get_demo_reset(job_id: str) -> DemoResetJob:
    _require_demo_api_enabled()
    try:
        return demo_reset_jobs[job_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="演示环境恢复任务不存在") from exc


def _create_demo_fault_job(
    scenario: Literal[
        "bad_rollout",
        "transient_runtime_fault",
        "ambiguous_change_fault",
    ],
) -> DemoFaultJob:
    if any(job.status == "resetting" for job in demo_reset_jobs.values()):
        raise HTTPException(
            status_code=409,
            detail="演示环境正在恢复健康基线，请等待恢复任务完成后再注入故障",
        )

    active_job = next(
        (
            job
            for job in demo_fault_jobs.values()
            if job.status == "injecting" and job.scenario == scenario
        ),
        None,
    )
    if active_job:
        return active_job

    job = DemoFaultJob(id=str(uuid4()), scenario=scenario, status="injecting")
    demo_fault_jobs[job.id] = job
    demo_fault_generations[job.id] = _demo_operation_generation
    task = asyncio.create_task(_run_demo_fault(job.id))
    demo_fault_tasks.add(task)
    task.add_done_callback(demo_fault_tasks.discard)
    return job


def _demo_write_lock() -> asyncio.Lock:
    """Return one Demo cluster-write lock for the current event loop.

    Tests may create a fresh event loop for each case. Keeping one lock per loop
    avoids reusing a contended asyncio primitive across those loop lifecycles,
    while the API server still has exactly one lock for all Demo writes.
    """

    loop = asyncio.get_running_loop()
    lock = _demo_write_locks.get(loop)
    if lock is None:
        lock = asyncio.Lock()
        _demo_write_locks[loop] = lock
    return lock


def _demo_fault_was_invalidated(job_id: str, generation: int) -> bool:
    job = demo_fault_jobs[job_id]
    return generation != _demo_operation_generation or job.status == "failed"


def _mark_demo_fault_invalidated(job_id: str) -> None:
    job = demo_fault_jobs[job_id]
    _disarm_job_profile(job)
    demo_fault_jobs[job_id] = job.model_copy(
        update={
            "status": "failed",
            "error": "故障注入已被演示环境恢复请求取消",
        }
    )


def _require_demo_api_enabled() -> None:
    settings = get_settings()
    environment = settings.environment.strip().casefold()
    namespace_mismatch = (
        settings.tool_backend == "kubernetes"
        and settings.kubernetes_namespace != settings.demo_namespace
    )
    if not settings.demo_enabled or environment in {"prod", "production"}:
        raise HTTPException(status_code=404, detail="Not Found")
    if namespace_mismatch:
        raise HTTPException(
            status_code=503,
            detail="Demo Kubernetes namespace is not isolated from the configured runtime",
        )


def _disarm_job_profile(job: DemoFaultJob) -> None:
    if job.scenario == "bad_rollout":
        lab_profiles.disarm("manual_approval")
    elif job.scenario == "transient_runtime_fault":
        lab_profiles.disarm("automatic_remediation")
    elif job.scenario == "ambiguous_change_fault":
        lab_profiles.disarm("bounded_reflection")


def _job_profile_mode(job: DemoFaultJob) -> LabMode:
    if job.scenario == "bad_rollout":
        return "manual_approval"
    if job.scenario == "transient_runtime_fault":
        return "automatic_remediation"
    return "bounded_reflection"


async def _release_demo_alert_deduplication() -> None:
    demo_alerts = {"HighInventoryErrorRate", "InventoryTransientRuntimeFault"}
    released_incident_ids: set[str] = set()
    for binding_key, incident_id in list(alert_fingerprints.items()):
        record = incident_records.get(incident_id)
        if record and record.alert.name in demo_alerts:
            alert_fingerprints.pop(binding_key, None)
            released_incident_ids.add(incident_id)
    if incident_store is not None:
        await incident_store.release_alert_bindings(released_incident_ids)


@app.get("/api/v1/demo/faults/{job_id}", response_model=DemoFaultJob)
async def get_demo_fault(job_id: str) -> DemoFaultJob:
    _require_demo_api_enabled()
    try:
        return demo_fault_jobs[job_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="故障注入任务不存在") from exc


@app.post("/api/v1/webhooks/alertmanager", status_code=202)
async def receive_alertmanager_webhook(
    request: Request,
) -> dict[str, object]:
    settings = get_settings()
    await _authenticate_alertmanager_webhook(request, settings)
    try:
        payload = AlertmanagerPayload.model_validate_json(
            await _bounded_webhook_body(
                request,
                max_bytes=settings.alertmanager_webhook_max_body_bytes,
            )
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail="Alertmanager Webhook 请求体格式无效",
        ) from exc
    accepted: list[dict[str, object]] = []
    for item in payload.alerts:
        fingerprint = _fingerprint(item)
        source_id = settings.alertmanager_source_id
        binding_key = _alert_binding_key(source_id, fingerprint)
        if item.status == "resolved":
            incident_id: str | None = None
            durable_resolution: StoredIncident | None = None
            resolution_status = "resolved"
            if incident_store is not None:
                try:
                    resolution = await incident_store.resolve_alert(
                        source_id=get_settings().alertmanager_source_id,
                        fingerprint=fingerprint,
                        starts_at=_alertmanager_time(item.startsAt),
                        resolved_at=_alertmanager_time(item.endsAt),
                    )
                except Exception as exc:
                    raise HTTPException(
                        status_code=503,
                        detail="Alertmanager 去重数据库暂时不可用",
                    ) from exc
                incident_id = resolution.incident_id
                durable_resolution = resolution.incident
                resolution_status = (
                    "stale" if resolution.outcome == "stale" else "resolved"
                )
                if resolution_status == "stale" and incident_id is not None:
                    alert_fingerprints[binding_key] = incident_id
                else:
                    alert_fingerprints.pop(binding_key, None)
            else:
                incident_id = alert_fingerprints.pop(binding_key, None)
            if incident_id:
                if resolution_status != "stale":
                    resolved_incident_ids.add(incident_id)
                agent = incident_agents.get(incident_id)
                if incident_store is not None and durable_resolution is None:
                    durable_resolution = await incident_store.record_alert_resolved(
                        incident_id,
                        fingerprint=fingerprint,
                    )
                if agent is not None and resolution_status != "stale":
                    await agent.invalidate_pending_approval(
                        incident_id,
                        reason=f"Alertmanager fingerprint {fingerprint} 已 resolved",
                    )
                if durable_resolution is not None:
                    incident_records[incident_id] = durable_resolution.record
                    incident_versions[incident_id] = durable_resolution.version
                    _publish_incident(durable_resolution.record)
                elif agent is None and incident_id in incident_records:
                    current = incident_records[incident_id].model_copy(deep=True)
                    current.status = IncidentStatus.RESOLVED
                    current.approval = None
                    current.active_step_id = None
                    now = datetime.now(UTC)
                    for step in current.execution_trace:
                        if step.status == "running":
                            step.status = "skipped"
                            step.completed_at = now
                            step.detail = "上游告警已恢复，调查任务已取消"
                    current.timeline.append(
                        TimelineEvent(
                            type="alertmanager.resolved",
                            message="告警已恢复，尚未执行任何修复操作",
                            data={"fingerprint": fingerprint},
                        )
                    )
                    _publish_incident(current)
            accepted.append(
                {
                    "fingerprint": fingerprint,
                    "status": resolution_status,
                    "incident_id": incident_id,
                }
            )
            continue
        if item.status != "firing":
            continue
        existing_id = (
            alert_fingerprints.get(binding_key)
            if incident_store is None
            else None
        )
        if existing_id:
            accepted.append(
                {
                    "fingerprint": fingerprint,
                    "status": "deduplicated",
                    "incident_id": existing_id,
                }
            )
            continue
        alert = _alert_from_alertmanager(item, fingerprint)
        profile = lab_profiles.consume(
            alert_name=alert.name,
            service=alert.service,
            confidence_threshold=get_settings().diagnosis_confidence_threshold,
        )
        now = datetime.now(UTC)
        execution_trace = [
            ExecutionStep(
                id="incident_received:1",
                kind="graph",
                title="接收事故告警",
                detail=alert.summary,
                status="completed",
                started_at=now,
                completed_at=now,
                duration_ms=0,
            )
        ]
        active_step_id = None
        if profile and profile.enrich_failed_trace:
            execution_trace.append(
                ExecutionStep(
                    id="enrich_trace:1",
                    kind="tool",
                    title="关联告警与失败调用链",
                    detail="正在从 Tempo 补齐触发告警的失败请求上下文",
                    status="running",
                    started_at=now,
                )
            )
            active_step_id = "enrich_trace:1"
        placeholder = IncidentRecord(
            alert=alert,
            execution_profile_id=profile.id if profile else "production-default",
            status=IncidentStatus.INVESTIGATING,
            timeline=[
                TimelineEvent(
                    type="alertmanager.received",
                    message="Alertmanager 自动推送了一个真实告警",
                    data={"fingerprint": fingerprint},
                )
            ],
            execution_trace=execution_trace,
            active_step_id=active_step_id,
        )
        if incident_store is not None:
            try:
                claim = await incident_store.claim_alert_firing(
                    placeholder,
                    source_id=get_settings().alertmanager_source_id,
                    fingerprint=fingerprint,
                    starts_at=_alertmanager_time(item.startsAt),
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="Alertmanager 去重数据库暂时不可用",
                ) from exc
            if claim.incident is not None and claim.incident_id is not None:
                durable_record = claim.incident.record
                incident_records[claim.incident_id] = durable_record
                incident_versions[claim.incident_id] = claim.incident.version
                _publish_incident(durable_record)
                if claim.outcome in {"accepted", "deduplicated"}:
                    alert_fingerprints[binding_key] = claim.incident_id
                    if (
                        claim.outcome == "accepted"
                        and profile
                        and profile.run_id in demo_fault_jobs
                    ):
                        demo_fault_jobs[profile.run_id] = demo_fault_jobs[
                            profile.run_id
                        ].model_copy(
                            update={
                                "phase": "incident_started",
                                "incident_id": claim.incident_id,
                            }
                        )
                    if durable_record.status in {
                        IncidentStatus.RECEIVED,
                        IncidentStatus.INVESTIGATING,
                    }:
                        _schedule_investigation(
                            claim.incident_id,
                            durable_record.alert,
                            profile if claim.outcome == "accepted" else None,
                        )
            accepted.append(
                {
                    "fingerprint": fingerprint,
                    "status": claim.outcome,
                    "incident_id": claim.incident_id,
                }
            )
            continue

        _publish_incident(placeholder)
        if profile and profile.run_id in demo_fault_jobs:
            demo_fault_jobs[profile.run_id] = demo_fault_jobs[profile.run_id].model_copy(
                update={"phase": "incident_started", "incident_id": placeholder.id}
            )
        alert_fingerprints[binding_key] = placeholder.id
        _schedule_investigation(placeholder.id, alert, profile)
        accepted.append(
            {
                "fingerprint": fingerprint,
                "status": "accepted",
                "incident_id": placeholder.id,
            }
        )
    return {"accepted": accepted}


@app.get("/api/v1/incidents", response_model=list[IncidentRecord])
async def list_incidents() -> list[IncidentRecord]:
    cluster_id = get_settings().cluster_id
    if incident_store is not None:
        stored_records = await incident_store.list()
        for stored in stored_records:
            if stored.record.alert.cluster_id != cluster_id:
                continue
            incident_records[stored.record.id] = stored.record
            incident_versions[stored.record.id] = stored.version
    return sorted(
        (
            record
            for record in incident_records.values()
            if record.alert.cluster_id == cluster_id
        ),
        key=lambda record: record.created_at,
        reverse=True,
    )


@app.get("/api/v1/runtime", response_model=RuntimeInfo)
async def get_runtime() -> RuntimeInfo:
    settings = get_settings()
    return RuntimeInfo(
        environment=settings.environment,
        tool_backend=settings.tool_backend,
        model_provider=settings.model_provider,
        model_name=settings.model_name,
        cluster_id=settings.cluster_id,
        cluster_display_name=settings.cluster_display_name,
        namespace=settings.kubernetes_namespace,
        approval_mode="risk_based",
    )


def _cluster_connection_view(
    connection: ClusterConnection,
) -> ClusterConnectionView:
    registration = connection.registration
    agents = sorted(
        connection.agents,
        key=lambda item: (item.instance_id, item.generation),
    )
    active = [
        item for item in agents if item.connection_status == "online"
    ]
    all_last_seen = [item.last_seen_at for item in agents]
    active_lease_expiries = [item.lease_until for item in active]
    visible_lease_expiries = active_lease_expiries or [
        item.lease_until for item in agents
    ]
    return ClusterConnectionView(
        cluster_id=registration.cluster_id,
        display_name=registration.display_name,
        default_namespace=registration.default_namespace,
        connection_status=connection.status,
        routing_generation=registration.routing_generation,
        active_executors=len(active),
        last_seen_at=max(all_last_seen) if all_last_seen else None,
        lease_expires_at=(
            max(visible_lease_expiries)
            if visible_lease_expiries
            else None
        ),
        capabilities=sorted(
            {
                capability
                for agent in active
                for capability in agent.capabilities
            }
        ),
        executors=[
            ClusterExecutorView(
                instance_id=agent.instance_id,
                session_id=agent.session_id,
                generation=agent.generation,
                version=agent.version,
                capabilities=list(agent.capabilities),
                connection_status=agent.connection_status,
                last_seen_at=agent.last_seen_at,
                lease_expires_at=agent.lease_until,
            )
            for agent in agents
        ],
    )


@app.get("/api/v1/clusters", response_model=list[ClusterConnectionView])
async def list_cluster_connections() -> list[ClusterConnectionView]:
    if incident_store is None:
        return []
    return [
        _cluster_connection_view(connection)
        for connection in await incident_store.list_cluster_connections()
    ]


@app.get(
    "/api/v1/clusters/{cluster_id}",
    response_model=ClusterConnectionView,
)
async def get_cluster_connection(cluster_id: str) -> ClusterConnectionView:
    if incident_store is None:
        raise HTTPException(status_code=404, detail="集群尚未注册")
    connection = await incident_store.get_cluster_connection(cluster_id)
    if connection is None:
        raise HTTPException(status_code=404, detail="集群尚未注册")
    return _cluster_connection_view(connection)


@app.get("/api/v1/incidents/events")
async def stream_all_incidents(request: Request) -> StreamingResponse:
    async def events() -> AsyncIterator[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=50)
        incident_feed_streams.add(queue)
        try:
            yield ": connected\n\n"
            while True:
                if _operator_token_expired(request):
                    return
                try:
                    payload = await asyncio.wait_for(
                        queue.get(),
                        timeout=_operator_stream_timeout(request),
                    )
                    yield f"data: {payload}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            incident_feed_streams.discard(queue)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentRecord)
async def get_incident(incident_id: str) -> IncidentRecord:
    cluster_id = get_settings().cluster_id
    if incident_store is not None:
        stored = await incident_store.get(incident_id)
        if stored is not None and stored.record.alert.cluster_id == cluster_id:
            incident_records[incident_id] = stored.record
            incident_versions[incident_id] = stored.version
            return stored.record
    try:
        record = incident_records[incident_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Incident not found") from exc
    if record.alert.cluster_id != cluster_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    return record


@app.post(
    "/api/v1/incidents/{incident_id}/change-proposals/preview",
    response_model=ChangeProposalPreview,
)
async def preview_incident_change_proposal(
    incident_id: str,
    body: ChangeProposalRequest,
) -> ChangeProposalPreview:
    return await _build_incident_change_proposal(incident_id, body)


async def _build_incident_change_proposal(
    incident_id: str,
    body: ChangeProposalRequest,
) -> ChangeProposalPreview:
    record = await get_incident(incident_id)
    if record.status not in {IncidentStatus.ESCALATED, IncidentStatus.FAILED}:
        raise HTTPException(
            status_code=409,
            detail="只有已停止自动写入的事故才能创建动态变更提案",
        )
    settings = get_settings()
    if record.alert.cluster_id != settings.cluster_id:
        raise HTTPException(
            status_code=409,
            detail="事故不属于当前控制面绑定的集群，禁止读取本集群快照",
        )
    if record.alert.namespace != settings.kubernetes_namespace:
        raise HTTPException(
            status_code=409,
            detail="事故 namespace 与当前控制面绑定的 namespace 不一致",
        )
    tools = _agent_tool_registry(settings)
    snapshot_result = await tools.call(
        "get_deployment_snapshot",
        {"name": record.alert.service},
    )
    if not snapshot_result.success:
        raise HTTPException(
            status_code=503,
            detail=(
                "无法读取目标 Deployment 的安全快照："
                f"{snapshot_result.error or 'unknown error'}"
            ),
        )
    try:
        snapshot = DeploymentSnapshot.model_validate(snapshot_result.content)
        return build_change_proposal(
            incident_id=incident_id,
            alert=record.alert,
            request=body,
            snapshot=snapshot,
        )
    except (ChangeProposalRejected, ValidationError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"动态变更提案未通过安全检查：{exc}",
        ) from exc


@app.post(
    "/api/v1/incidents/{incident_id}/change-proposals",
    response_model=SubmittedChangeProposal,
    status_code=202,
)
async def submit_incident_change_proposal(
    incident_id: str,
    body: ChangeProposalRequest,
    request: Request,
) -> SubmittedChangeProposal:
    if incident_store is None:
        raise HTTPException(
            status_code=503,
            detail="提交 GitOps 提案需要持久化数据库",
        )
    identity = getattr(request.state, "operator_identity", None)
    if not isinstance(identity, OperatorIdentity):
        identity = await _require_operator(
            request,
            permission=INCIDENT_PROPOSE_PERMISSION,
        )
    preview = await _build_incident_change_proposal(incident_id, body)
    try:
        stored = await incident_store.submit_change_proposal(
            preview,
            actor_id=identity.subject_hash,
            actor_assurance=identity.assurance,
        )
    except ChangeProposalConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return SubmittedChangeProposal.model_validate(
        stored,
        from_attributes=True,
    )


@app.get(
    "/api/v1/change-proposals/{proposal_id}",
    response_model=SubmittedChangeProposal,
)
async def get_submitted_change_proposal(
    proposal_id: str,
) -> SubmittedChangeProposal:
    if incident_store is None:
        raise HTTPException(
            status_code=503,
            detail="查询 GitOps 提案需要持久化数据库",
        )
    stored = await incident_store.get_change_proposal(proposal_id)
    if stored is None:
        raise HTTPException(
            status_code=404,
            detail="Change proposal not found",
        )
    return SubmittedChangeProposal.model_validate(
        stored,
        from_attributes=True,
    )


@app.get("/api/v1/incidents/{incident_id}/events")
async def stream_incident(
    incident_id: str,
    request: Request,
) -> StreamingResponse:
    record = incident_records.get(incident_id)
    if record is None or record.alert.cluster_id != get_settings().cluster_id:
        raise HTTPException(status_code=404, detail="Incident not found")

    async def events() -> AsyncIterator[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=20)
        subscribers = incident_streams.setdefault(incident_id, set())
        subscribers.add(queue)
        try:
            yield f"data: {incident_records[incident_id].model_dump_json()}\n\n"
            while True:
                if _operator_token_expired(request):
                    return
                try:
                    payload = await asyncio.wait_for(
                        queue.get(),
                        timeout=_operator_stream_timeout(request),
                    )
                    yield f"data: {payload}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            subscribers.discard(queue)
            if not subscribers:
                incident_streams.pop(incident_id, None)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.post("/api/v1/incidents/{incident_id}/approval", response_model=IncidentRecord)
async def decide_incident(
    incident_id: str,
    decision: ApprovalDecision,
    request: Request,
) -> IncidentRecord:
    current = await get_incident(incident_id)
    settings = get_settings()
    if current.alert.cluster_id != settings.cluster_id:
        raise HTTPException(
            status_code=409,
            detail=(
                f"事故属于集群 {current.alert.cluster_id}，当前控制面仅执行 "
                f"{settings.cluster_id} 的操作"
            ),
        )
    identity = getattr(
        request.state,
        "operator_identity",
        None,
    )
    if not isinstance(identity, OperatorIdentity):
        identity = await _require_operator(
            request,
            permission=INCIDENT_APPROVE_PERMISSION,
        )
    try:
        if incident_id in incident_recovery_errors:
            if incident_store is not None:
                await _reconcile_persistence_once()
        if incident_id in incident_recovery_errors:
            raise RuntimeError(incident_recovery_errors[incident_id])
        if incident_id not in incident_agents and incident_id in incident_records:
            raise RuntimeError("当前副本尚未取得该事故的安全执行权，请稍后重试")
        agent = incident_agents[incident_id]
        async with _incident_lease(incident_id) as token:
            agent.set_action_journal(_action_journal(token))
            executor = _action_executor(token)
            if executor is not None:
                agent.set_action_executor(executor)
            if incident_store is not None:
                await incident_store.claim_approval(
                    incident_id,
                    approval_id=decision.approval_id,
                    approval_version=decision.approval_version,
                    approved=decision.approved,
                    note=decision.note,
                    actor_id=identity.subject_hash,
                    actor_assurance=identity.assurance,
                )
            try:
                record = await agent.resume(
                    incident_id,
                    approval_id=decision.approval_id,
                    approval_version=decision.approval_version,
                    approved=decision.approved,
                    note=decision.note,
                )
            except RuntimeError:
                current = agent.get(incident_id)
                _publish_incident(current)
                await _persist_incident(current, lease_token=token)
                raise
            _publish_incident(record)
            await _persist_incident(record, lease_token=token)
            return record
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Incident not found") from exc
    except (
        ApprovalConflictError,
        LeaseConflictError,
        RuntimeError,
        StoreConflictError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
