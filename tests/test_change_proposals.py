from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

import sentinelops.api as api_module
from sentinelops.api import app
from sentinelops.change_proposals import (
    ChangeField,
    ChangeOperation,
    ChangeProposalRejected,
    ChangeProposalRequest,
    DeploymentSnapshot,
    build_change_proposal,
)
from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentRecord, IncidentStatus
from sentinelops.storage import SqlIncidentStore
from sentinelops.tools import ToolRegistry
from sentinelops.tools.simulator import SimulatedKubernetesBackend


def _alert() -> Alert:
    return Alert(
        name="ManualInvestigationRequired",
        namespace="sentinelops-demo",
        service="order-service",
        severity="critical",
        summary="标准动作无法安全处理，需要人工提出变更",
    )


def _snapshot() -> DeploymentSnapshot:
    return DeploymentSnapshot(
        name="order-service",
        cluster_id="local",
        namespace="sentinelops-demo",
        uid="deployment-uid",
        resource_version="42",
        generation=7,
        containers=[
            {
                "name": "order-service",
                "image": "order-service@sha256:abc",
                "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits": {"cpu": "500m", "memory": "512Mi"},
                },
                "readinessProbe": {
                    "initialDelaySeconds": 2,
                    "periodSeconds": 5,
                    "timeoutSeconds": 1,
                    "failureThreshold": 3,
                },
                "livenessProbe": {
                    "initialDelaySeconds": 5,
                    "periodSeconds": 10,
                    "timeoutSeconds": 1,
                    "failureThreshold": 3,
                },
            }
        ],
    )


def _request(*operations: ChangeOperation) -> ChangeProposalRequest:
    return ChangeProposalRequest(
        rationale="根据资源饱和证据调整容器资源并延长探针超时",
        operations=list(operations),
    )


def test_change_proposal_builds_bounded_diff_without_execution_capability() -> None:
    request = _request(
        ChangeOperation(
            field=ChangeField.CPU_REQUEST,
            container="order-service",
            value="250m",
        ),
        ChangeOperation(
            field=ChangeField.READINESS_TIMEOUT,
            container="order-service",
            value=3,
        ),
    )

    preview = build_change_proposal(
        incident_id="incident-1",
        alert=_alert(),
        request=request,
        snapshot=_snapshot(),
    )

    assert preview.status == "validated_preview"
    assert preview.executable is False
    assert preview.requires_human_approval is True
    assert preview.execution_channel == "gitops_pr"
    assert preview.target["cluster_id"] == "local"
    assert preview.target["uid"] == "deployment-uid"
    assert preview.target["resource_version"] == "42"
    assert [(item.before, item.after) for item in preview.diff] == [
        ("100m", "250m"),
        (1, 3),
    ]
    container_patch = preview.strategic_merge_patch["spec"]["template"]["spec"][
        "containers"
    ][0]
    assert container_patch == {
        "name": "order-service",
        "resources": {"requests": {"cpu": "250m"}},
        "readinessProbe": {"timeoutSeconds": 3},
    }
    assert "direct_cluster_write" in preview.blocked_capabilities
    assert "shell" in preview.blocked_capabilities


def test_change_proposal_digest_binds_snapshot_and_requested_diff() -> None:
    request = _request(
        ChangeOperation(
            field=ChangeField.MEMORY_LIMIT,
            container="order-service",
            value="1Gi",
        )
    )
    first = build_change_proposal(
        incident_id="incident-1",
        alert=_alert(),
        request=request,
        snapshot=_snapshot(),
    )
    second = build_change_proposal(
        incident_id="incident-1",
        alert=_alert(),
        request=request,
        snapshot=_snapshot(),
    )
    changed_snapshot = _snapshot().model_copy(update={"resource_version": "43"})
    changed = build_change_proposal(
        incident_id="incident-1",
        alert=_alert(),
        request=request,
        snapshot=changed_snapshot,
    )

    assert first.proposal_digest == second.proposal_digest
    assert first.proposal_id == second.proposal_id
    assert changed.proposal_digest != first.proposal_digest


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        (
            ChangeOperation(
                field=ChangeField.CPU_REQUEST,
                container="sidecar",
                value="250m",
            ),
            "不属于目标 Deployment",
        ),
        (
            ChangeOperation(
                field=ChangeField.CPU_LIMIT,
                container="order-service",
                value="1000Gi",
            ),
            "64 CPU 上限",
        ),
        (
            ChangeOperation(
                field=ChangeField.READINESS_TIMEOUT,
                container="order-service",
                value=301,
            ),
            "必须在",
        ),
        (
            ChangeOperation(
                field=ChangeField.CPU_REQUEST,
                container="order-service",
                value="100m",
            ),
            "修改前后没有变化",
        ),
    ],
)
def test_change_proposal_rejects_unsafe_or_unbounded_changes(
    operation: ChangeOperation,
    message: str,
) -> None:
    with pytest.raises(ChangeProposalRejected, match=message):
        build_change_proposal(
            incident_id="incident-1",
            alert=_alert(),
            request=_request(operation),
            snapshot=_snapshot(),
        )


def test_change_proposal_rejects_request_above_limit() -> None:
    with pytest.raises(ChangeProposalRejected, match="request 不能高于 limit"):
        build_change_proposal(
            incident_id="incident-1",
            alert=_alert(),
            request=_request(
                ChangeOperation(
                    field=ChangeField.CPU_REQUEST,
                    container="order-service",
                    value="2",
                )
            ),
            snapshot=_snapshot(),
        )


def test_change_request_schema_has_no_arbitrary_path_or_shell_escape() -> None:
    with pytest.raises(ValidationError):
        ChangeProposalRequest.model_validate(
            {
                "rationale": "尝试执行一个未注册的任意命令",
                "operations": [
                    {
                        "field": "shell",
                        "container": "order-service",
                        "value": "kubectl delete namespace production",
                        "path": "/spec/template/spec/containers/0/securityContext",
                    }
                ],
            }
        )


@pytest.mark.asyncio
async def test_api_previews_change_only_after_automation_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = IncidentRecord(
        alert=_alert(),
        status=IncidentStatus.ESCALATED,
    )
    api_module.incident_records[record.id] = record
    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: Settings(
            tool_backend="simulator",
            kubernetes_namespace="sentinelops-demo",
        ),
    )
    backend = SimulatedKubernetesBackend()
    monkeypatch.setattr(
        api_module,
        "_agent_tool_registry",
        lambda _settings: ToolRegistry(backend),
    )
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/incidents/{record.id}/change-proposals/preview",
                json={
                    "rationale": "人工调查确认需要适当提高容器的 CPU request",
                    "operations": [
                        {
                            "field": "container.resources.requests.cpu",
                            "container": "order-service",
                            "value": "250m",
                        }
                    ],
                },
            )
    finally:
        api_module.incident_records.pop(record.id, None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["incident_id"] == record.id
    assert payload["executable"] is False
    assert payload["target"]["name"] == "order-service"
    assert payload["target"]["namespace"] == "sentinelops-demo"
    assert backend.resolved is False
    assert backend.current_revision == 2


@pytest.mark.asyncio
async def test_api_rejects_dynamic_preview_for_live_automatic_incident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = IncidentRecord(
        alert=_alert(),
        status=IncidentStatus.AWAITING_APPROVAL,
    )
    api_module.incident_records[record.id] = record
    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: Settings(kubernetes_namespace="sentinelops-demo"),
    )
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/incidents/{record.id}/change-proposals/preview",
                json={
                    "rationale": "不能与当前自动修复流程并发创建动态变更",
                    "operations": [
                        {
                            "field": "container.resources.requests.cpu",
                            "container": "order-service",
                            "value": "250m",
                        }
                    ],
                },
            )
    finally:
        api_module.incident_records.pop(record.id, None)

    assert response.status_code == 409
    assert "已停止自动写入" in response.json()["detail"]


@pytest.mark.asyncio
async def test_api_submits_fresh_proposal_to_durable_gitops_outbox(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'proposal-api.db'}"
    )
    await store.setup()
    record = IncidentRecord(
        alert=_alert(),
        status=IncidentStatus.ESCALATED,
    )
    await store.save(record, expected_version=None, graph_state=None)
    api_module.incident_store = store
    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: Settings(
            tool_backend="simulator",
            kubernetes_namespace="sentinelops-demo",
        ),
    )
    monkeypatch.setattr(
        api_module,
        "_agent_tool_registry",
        lambda _settings: ToolRegistry(SimulatedKubernetesBackend()),
    )
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as client:
            submitted = await client.post(
                f"/api/v1/incidents/{record.id}/change-proposals",
                json={
                    "rationale": "人工调查确认需要适当提高容器的 CPU request",
                    "operations": [
                        {
                            "field": "container.resources.requests.cpu",
                            "container": "order-service",
                            "value": "250m",
                        }
                    ],
                },
            )
            proposal_id = submitted.json()["preview"]["proposal_id"]
            fetched = await client.get(
                f"/api/v1/change-proposals/{proposal_id}"
            )
    finally:
        api_module.incident_store = None
        await store.close()

    assert submitted.status_code == 202
    assert submitted.json()["status"] == "submitted"
    assert fetched.status_code == 200
    assert fetched.json()["preview"]["proposal_id"] == proposal_id
