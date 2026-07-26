from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
)

from sentinelops.domain import Alert, RiskLevel

_KUBERNETES_NAME = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$"
)
_QUANTITY = re.compile(r"^(?P<number>[0-9]+(?:\.[0-9]+)?)(?P<unit>m|Ki|Mi|Gi|Ti)?$")


class ChangeField(StrEnum):
    CPU_REQUEST = "container.resources.requests.cpu"
    CPU_LIMIT = "container.resources.limits.cpu"
    MEMORY_REQUEST = "container.resources.requests.memory"
    MEMORY_LIMIT = "container.resources.limits.memory"
    READINESS_INITIAL_DELAY = "container.readinessProbe.initialDelaySeconds"
    READINESS_PERIOD = "container.readinessProbe.periodSeconds"
    READINESS_TIMEOUT = "container.readinessProbe.timeoutSeconds"
    READINESS_FAILURE_THRESHOLD = "container.readinessProbe.failureThreshold"
    LIVENESS_INITIAL_DELAY = "container.livenessProbe.initialDelaySeconds"
    LIVENESS_PERIOD = "container.livenessProbe.periodSeconds"
    LIVENESS_TIMEOUT = "container.livenessProbe.timeoutSeconds"
    LIVENESS_FAILURE_THRESHOLD = "container.livenessProbe.failureThreshold"


class ChangeOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: ChangeField
    container: str = Field(min_length=1, max_length=253)
    value: StrictStr | StrictInt

    @field_validator("value")
    @classmethod
    def bounded_value(cls, value: str | int) -> str | int:
        if isinstance(value, str) and not 1 <= len(value) <= 64:
            raise ValueError("字符串值必须在 1 到 64 个字符之间")
        return value


class ChangeProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rationale: str = Field(min_length=10, max_length=2_000)
    operations: list[ChangeOperation] = Field(min_length=1, max_length=8)


class ProbeSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    initialDelaySeconds: int | None = None
    periodSeconds: int | None = None
    timeoutSeconds: int | None = None
    failureThreshold: int | None = None


class ContainerSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    image: str
    resources: dict[str, dict[str, str]] = Field(default_factory=dict)
    readinessProbe: ProbeSnapshot | None = None
    livenessProbe: ProbeSnapshot | None = None


class DeploymentSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    namespace: str
    uid: str
    resource_version: str
    generation: int
    containers: list[ContainerSnapshot] = Field(min_length=1)


class ChangeDiff(BaseModel):
    field: ChangeField
    container: str
    image: str
    before: str | int | None
    after: str | int


class ChangeProposalPreview(BaseModel):
    proposal_id: str
    proposal_digest: str
    incident_id: str
    status: str = "validated_preview"
    executable: bool = False
    risk: RiskLevel = RiskLevel.HIGH
    requires_human_approval: bool = True
    execution_channel: str = "gitops_pr"
    rationale: str
    target: dict[str, str | int]
    diff: list[ChangeDiff]
    strategic_merge_patch: dict[str, Any]
    blocked_capabilities: list[str]
    generated_at: datetime
    expires_at: datetime


class SubmittedChangeProposal(BaseModel):
    preview: ChangeProposalPreview
    status: str
    version: int
    submitted_by: str
    submitted_assurance: str
    created_at: datetime
    updated_at: datetime
    published_at: datetime | None
    receipt: dict[str, Any] | None


class ChangeProposalRejected(ValueError):
    pass


_RESOURCE_FIELDS = {
    ChangeField.CPU_REQUEST: ("requests", "cpu"),
    ChangeField.CPU_LIMIT: ("limits", "cpu"),
    ChangeField.MEMORY_REQUEST: ("requests", "memory"),
    ChangeField.MEMORY_LIMIT: ("limits", "memory"),
}
_PROBE_FIELDS = {
    ChangeField.READINESS_INITIAL_DELAY: ("readinessProbe", "initialDelaySeconds"),
    ChangeField.READINESS_PERIOD: ("readinessProbe", "periodSeconds"),
    ChangeField.READINESS_TIMEOUT: ("readinessProbe", "timeoutSeconds"),
    ChangeField.READINESS_FAILURE_THRESHOLD: (
        "readinessProbe",
        "failureThreshold",
    ),
    ChangeField.LIVENESS_INITIAL_DELAY: ("livenessProbe", "initialDelaySeconds"),
    ChangeField.LIVENESS_PERIOD: ("livenessProbe", "periodSeconds"),
    ChangeField.LIVENESS_TIMEOUT: ("livenessProbe", "timeoutSeconds"),
    ChangeField.LIVENESS_FAILURE_THRESHOLD: ("livenessProbe", "failureThreshold"),
}


def build_change_proposal(
    *,
    incident_id: str,
    alert: Alert,
    request: ChangeProposalRequest,
    snapshot: DeploymentSnapshot,
    ttl_minutes: int = 10,
) -> ChangeProposalPreview:
    if snapshot.name != alert.service or snapshot.namespace != alert.namespace:
        raise ChangeProposalRejected(
            "Deployment 快照与事故 service/namespace 不一致"
        )
    if not snapshot.uid or not snapshot.resource_version:
        raise ChangeProposalRejected("Deployment 快照缺少 UID 或 resourceVersion")
    containers = {container.name: container for container in snapshot.containers}
    if len(containers) != len(snapshot.containers):
        raise ChangeProposalRejected("Deployment 快照包含重复容器名称")

    seen: set[tuple[str, ChangeField]] = set()
    diff: list[ChangeDiff] = []
    container_patches: dict[str, dict[str, Any]] = {}
    resulting_resources = {
        container.name: {
            group: dict(values)
            for group, values in container.resources.items()
            if group in {"requests", "limits"}
        }
        for container in snapshot.containers
    }

    for operation in request.operations:
        if _KUBERNETES_NAME.fullmatch(operation.container) is None:
            raise ChangeProposalRejected(
                f"容器名称 {operation.container!r} 不符合 Kubernetes 命名规则"
            )
        container = containers.get(operation.container)
        if container is None:
            raise ChangeProposalRejected(
                f"容器 {operation.container!r} 不属于目标 Deployment"
            )
        identity = (operation.container, operation.field)
        if identity in seen:
            raise ChangeProposalRejected(
                f"同一字段不能重复修改：{operation.container}/{operation.field}"
            )
        seen.add(identity)
        patch = container_patches.setdefault(
            operation.container,
            {"name": operation.container},
        )

        if operation.field in _RESOURCE_FIELDS:
            if not isinstance(operation.value, str):
                raise ChangeProposalRejected(
                    f"{operation.field} 必须使用 Kubernetes quantity 字符串"
                )
            group, resource = _RESOURCE_FIELDS[operation.field]
            _validate_quantity(operation.field, operation.value)
            before = container.resources.get(group, {}).get(resource)
            patch.setdefault("resources", {}).setdefault(group, {})[
                resource
            ] = operation.value
            resulting_resources.setdefault(operation.container, {}).setdefault(
                group, {}
            )[resource] = operation.value
        else:
            if not isinstance(operation.value, int) or isinstance(operation.value, bool):
                raise ChangeProposalRejected(f"{operation.field} 必须是整数")
            probe_name, attribute = _PROBE_FIELDS[operation.field]
            _validate_probe_value(attribute, operation.value)
            probe = getattr(container, probe_name)
            if probe is None:
                raise ChangeProposalRejected(
                    f"容器 {operation.container} 当前没有 {probe_name}，"
                    "禁止用动态提案创建全新探针"
                )
            before = getattr(probe, attribute)
            patch.setdefault(probe_name, {})[attribute] = operation.value

        if before == operation.value:
            raise ChangeProposalRejected(
                f"{operation.container}/{operation.field} 修改前后没有变化"
            )
        diff.append(
            ChangeDiff(
                field=operation.field,
                container=operation.container,
                image=container.image,
                before=before,
                after=operation.value,
            )
        )

    _validate_resource_relationships(resulting_resources)
    merge_patch: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": snapshot.name,
            "namespace": snapshot.namespace,
        },
        "spec": {
            "template": {
                "spec": {
                    "containers": list(container_patches.values()),
                }
            }
        },
    }
    digest_payload = {
        "incident_id": incident_id,
        "target": {
            "name": snapshot.name,
            "namespace": snapshot.namespace,
            "uid": snapshot.uid,
            "resource_version": snapshot.resource_version,
            "generation": snapshot.generation,
        },
        "rationale": request.rationale,
        "diff": [item.model_dump(mode="json") for item in diff],
        "strategic_merge_patch": merge_patch,
    }
    canonical = json.dumps(
        digest_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    generated_at = datetime.now(UTC)
    return ChangeProposalPreview(
        proposal_id=str(UUID(digest[:32])),
        proposal_digest=digest,
        incident_id=incident_id,
        rationale=request.rationale,
        target=digest_payload["target"],
        diff=diff,
        strategic_merge_patch=merge_patch,
        blocked_capabilities=[
            "shell",
            "kubectl",
            "resource_delete",
            "secret_access",
            "rbac_change",
            "privileged_container",
            "image_change",
            "environment_value_change",
            "direct_cluster_write",
        ],
        generated_at=generated_at,
        expires_at=generated_at + timedelta(minutes=ttl_minutes),
    )


def _validate_quantity(field: ChangeField, value: str) -> None:
    match = _QUANTITY.fullmatch(value)
    if match is None:
        raise ChangeProposalRejected(f"{field} 使用了不支持的 quantity 格式")
    number = Decimal(match.group("number"))
    unit = match.group("unit") or ""
    if number <= 0:
        raise ChangeProposalRejected(f"{field} 必须大于 0")
    if "cpu" in field.value:
        cores = number / 1000 if unit == "m" else number
        if unit not in {"", "m"} or cores > 64:
            raise ChangeProposalRejected(f"{field} 超出 64 CPU 上限")
        return
    factors = {
        "": Decimal(1),
        "Ki": Decimal(1024),
        "Mi": Decimal(1024**2),
        "Gi": Decimal(1024**3),
        "Ti": Decimal(1024**4),
    }
    if unit not in factors or number * factors[unit] > Decimal(256 * 1024**3):
        raise ChangeProposalRejected(f"{field} 超出 256Gi 内存上限")


def _validate_probe_value(attribute: str, value: int) -> None:
    lower, upper = (
        (0, 3_600)
        if attribute == "initialDelaySeconds"
        else ((1, 20) if attribute == "failureThreshold" else (1, 300))
    )
    if value < lower or value > upper:
        raise ChangeProposalRejected(
            f"{attribute} 必须在 {lower} 到 {upper} 之间"
        )


def _validate_resource_relationships(
    resources_by_container: dict[str, dict[str, dict[str, str]]],
) -> None:
    for container, resources in resources_by_container.items():
        for resource in ("cpu", "memory"):
            request = resources.get("requests", {}).get(resource)
            limit = resources.get("limits", {}).get(resource)
            if request is None or limit is None:
                continue
            try:
                request_value = _quantity_value(resource, request)
                limit_value = _quantity_value(resource, limit)
            except (InvalidOperation, KeyError) as exc:
                raise ChangeProposalRejected(
                    f"无法比较容器 {container} 的现有 {resource} request/limit"
                ) from exc
            if request_value > limit_value:
                raise ChangeProposalRejected(
                    f"容器 {container} 的 {resource} request 不能高于 limit"
                )


def _quantity_value(resource: str, value: str) -> Decimal:
    match = _QUANTITY.fullmatch(value)
    if match is None:
        raise InvalidOperation
    number = Decimal(match.group("number"))
    unit = match.group("unit") or ""
    if resource == "cpu":
        if unit not in {"", "m"}:
            raise InvalidOperation
        return number / 1000 if unit == "m" else number
    factors = {
        "": Decimal(1),
        "Ki": Decimal(1024),
        "Mi": Decimal(1024**2),
        "Gi": Decimal(1024**3),
        "Ti": Decimal(1024**4),
    }
    return number * factors[unit]
