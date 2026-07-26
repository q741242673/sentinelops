from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException

from sentinelops.domain import ToolResult
from sentinelops.storage.base import StoredActionIntent

GROUP = "ops.sentinelops.io"
VERSION = "v1alpha1"
PLURAL = "sentinelremediations"
TERMINAL_PHASES = {"Succeeded", "Failed", "Rejected", "Stale", "Cancelled"}
_SAFE_REJECTED_REASONS = {
    "ActionIdentityMismatch",
    "ActionNotRegistered",
    "ActionTargetMismatch",
    "AdmissionFenceNotEnforced",
    "AdmissionIntegrityDrift",
    "AdmissionIntegrityUnknown",
    "ApprovalBindingMissing",
    "ApprovalDigestMismatch",
    "AuthorizationInvalid",
    "AuthorizationPolicyDigestMismatch",
    "AutomaticAuthorizationInvalid",
    "CatalogDigestMismatch",
    "FenceGenerationMismatch",
    "InvalidActionParameters",
    "RollbackProofMissing",
    "SnapshotDigestMismatch",
    "TargetNamespaceMismatch",
    "UnsupportedTarget",
}
_SAFE_STALE_REASONS = {
    "CurrentReplicaSetChanged",
    "CurrentRevisionChanged",
    "CurrentRevisionMissing",
    "CurrentTemplateChanged",
    "FenceExpired",
    "FenceMarkerInvalid",
    "FenceSuperseded",
    "GenerationChanged",
    "PauseStateChanged",
    "ReplicaCountChanged",
    "ResourceVersionChanged",
    "RollbackHealthProofChanged",
    "RollbackHealthProofDigestChanged",
    "RollbackTargetChanged",
    "TargetMissing",
    "TargetUIDChanged",
}

_ACTION_CONTRACTS: dict[str, dict[str, Any]] = {
    "restart_deployment": {
        "name": "restart_deployment",
        "risk": "medium",
        "parameters": ["name"],
        "requiredPreconditions": [
            "resourceVersion",
            "generation",
            "desiredReplicas",
            "paused",
            "currentRevision",
            "currentReplicaSetUid",
            "currentTemplateHash",
            "capturedAt",
        ],
        "reversible": False,
        "verificationProfile": "workload_strict",
        "version": "v1",
    },
    "rollback_deployment": {
        "name": "rollback_deployment",
        "risk": "high",
        "parameters": ["name", "revision"],
        "requiredPreconditions": [
            "resourceVersion",
            "generation",
            "desiredReplicas",
            "paused",
            "currentRevision",
            "currentReplicaSetUid",
            "currentTemplateHash",
            "capturedAt",
            "rollbackTarget",
        ],
        "reversible": True,
        "verificationProfile": "workload_strict",
        "version": "v1",
    },
    "scale_deployment": {
        "name": "scale_deployment",
        "risk": "high",
        "parameters": ["name", "replicas"],
        "requiredPreconditions": [
            "resourceVersion",
            "generation",
            "desiredReplicas",
            "paused",
            "currentRevision",
            "currentReplicaSetUid",
            "currentTemplateHash",
            "capturedAt",
        ],
        "reversible": True,
        "verificationProfile": "workload_strict",
        "version": "v1",
    },
}


def canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def action_catalog_digest(action_plugin: str) -> str:
    try:
        contract = _ACTION_CONTRACTS[action_plugin]
    except KeyError as exc:
        raise ValueError(f"Action Plugin 未注册：{action_plugin}") from exc
    return canonical_digest(contract)


def authorization_policy_digest(
    action_plugin: str,
    decision: str,
    catalog_digest: str,
) -> str:
    return canonical_digest(
        {
            "actionPlugin": action_plugin,
            "catalogDigest": catalog_digest,
            "decision": decision,
            "version": "v1",
        }
    )


def human_approval_digest(
    action_id: str,
    approval_id: str,
    approval_version: int,
    policy_digest: str,
) -> str:
    return canonical_digest(
        {
            "actionId": action_id,
            "approvalId": approval_id,
            "approvalVersion": approval_version,
            "decision": "human_approval",
            "policyDigest": policy_digest,
        }
    )


def rollback_health_proof_digest(proof: dict[str, Any]) -> str:
    identity = {
        "subject": _required_string(proof, "subject"),
        "verifiedAt": _normalized_time(proof.get("verified_at"), "verified_at"),
        "verifier": _required_string(proof, "verifier"),
        "version": _required_string(proof, "version"),
    }
    return canonical_digest(identity)


def build_sentinel_remediation(intent: StoredActionIntent) -> dict[str, Any]:
    if not re.fullmatch(r"[a-f0-9]{64}", intent.idempotency_key):
        raise ValueError("Action Intent 幂等键不是 64 位 SHA-256")
    action_name = intent.action.tool_name
    catalog_digest = action_catalog_digest(action_name)
    parameters = _action_parameters(action_name, intent.action.arguments)
    precondition = _execution_precondition(intent.precondition)
    decision = (
        "human_approval"
        if intent.approval_id is not None or intent.approval_version is not None
        else "risk_policy"
    )
    policy_digest = authorization_policy_digest(
        action_name,
        decision,
        catalog_digest,
    )
    authorization: dict[str, Any] = {
        "decision": decision,
        "policyDigest": policy_digest,
    }
    if decision == "human_approval":
        if intent.approval_id is None or intent.approval_version is None:
            raise ValueError("Action Intent 的人工审批身份不完整")
        authorization.update(
            {
                "approvalId": intent.approval_id,
                "approvalVersion": intent.approval_version,
                "approvalDigest": human_approval_digest(
                    intent.idempotency_key,
                    intent.approval_id,
                    intent.approval_version,
                    policy_digest,
                ),
            }
        )
    namespace = _required_string(intent.precondition, "namespace")
    target_name = _required_string(intent.precondition, "target")
    if parameters["name"] != target_name:
        raise ValueError("Action 参数与执行快照目标不一致")
    snapshot_digest = canonical_digest(precondition)
    precondition["snapshotDigest"] = snapshot_digest
    return {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": "SentinelRemediation",
        "metadata": {
            "name": intent.idempotency_key,
            "namespace": namespace,
        },
        "spec": {
            "actionId": intent.idempotency_key,
            "incidentId": intent.incident_id,
            "action": {
                "plugin": action_name,
                "catalogDigest": catalog_digest,
                "parameters": parameters,
            },
            "target": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "namespace": namespace,
                "name": target_name,
                "uid": _required_string(intent.precondition, "deployment_uid"),
            },
            "precondition": precondition,
            "authorization": authorization,
            "fence": {
                "generation": precondition["generation"],
                "expiresAt": _normalized_time(
                    intent.precondition.get("expires_at"),
                    "expires_at",
                    truncate_subseconds=True,
                ),
            },
        },
    }


def _action_parameters(
    action_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    expected = {
        "restart_deployment": {"name"},
        "rollback_deployment": {"name", "revision"},
        "scale_deployment": {"name", "replicas"},
    }[action_name]
    if set(arguments) != expected:
        raise ValueError(f"{action_name} 参数与注册合同不一致")
    parameters: dict[str, Any] = {"name": _required_string(arguments, "name")}
    if action_name == "rollback_deployment":
        revision = arguments.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("rollback revision 必须是正整数")
        parameters["revision"] = revision
    if action_name == "scale_deployment":
        replicas = arguments.get("replicas")
        if (
            not isinstance(replicas, int)
            or isinstance(replicas, bool)
            or not 0 <= replicas <= 100
        ):
            raise ValueError("scale replicas 必须处于 0 到 100")
        parameters["replicas"] = replicas
    return parameters


def _execution_precondition(source: dict[str, object]) -> dict[str, Any]:
    precondition: dict[str, Any] = {
        "resourceVersion": _required_string(source, "resource_version"),
        "generation": _required_positive_int(source, "generation"),
        "desiredReplicas": _required_nonnegative_int(source, "desired_replicas"),
        "paused": _required_bool(source, "paused"),
        "currentRevision": _required_positive_int(source, "current_revision"),
        "currentReplicaSetUid": _required_string(
            source,
            "current_replica_set_uid",
        ),
        "currentTemplateHash": _required_string(source, "current_template_hash"),
        "capturedAt": _normalized_time(
            source.get("captured_at"),
            "captured_at",
            truncate_subseconds=True,
        ),
    }
    rollback = source.get("rollback_target")
    if rollback is not None:
        if not isinstance(rollback, dict):
            raise ValueError("rollback_target 不是对象")
        proof = rollback.get("health_proof")
        if not isinstance(proof, dict):
            raise ValueError("rollback_target 缺少健康证明")
        precondition["rollbackTarget"] = {
            "revision": _required_positive_int(rollback, "revision"),
            "replicaSetUid": _required_string(rollback, "replica_set_uid"),
            "healthProofDigest": rollback_health_proof_digest(proof),
        }
    return precondition


def _normalized_time(
    value: object,
    field: str,
    *,
    truncate_subseconds: bool = False,
) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"{field} 不是合法时间") from exc
    else:
        raise ValueError(f"{field} 缺失")
    if parsed.tzinfo is None:
        raise ValueError(f"{field} 必须带时区")
    normalized = parsed.astimezone(UTC)
    if truncate_subseconds:
        # Kubernetes metav1.Time canonical JSON uses whole-second RFC3339.
        # Hash the representation the typed Go Controller will recompute.
        normalized = normalized.replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _required_string(source: dict[str, Any] | dict[str, object], field: str) -> str:
    value = source.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} 缺少非空字符串")
    return value


def _required_positive_int(source: dict[str, Any] | dict[str, object], field: str) -> int:
    value = source.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{field} 必须是正整数")
    return value


def _required_nonnegative_int(
    source: dict[str, Any] | dict[str, object],
    field: str,
) -> int:
    value = source.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} 必须是非负整数")
    return value


def _required_bool(source: dict[str, object], field: str) -> bool:
    value = source.get(field)
    if not isinstance(value, bool):
        raise ValueError(f"{field} 必须是布尔值")
    return value


ObservationState = Literal[
    "not_found",
    "in_progress",
    "terminal",
    "unknown",
]


@dataclass(frozen=True)
class RemediationObservation:
    state: ObservationState
    phase: str | None = None
    result: ToolResult | None = None
    reason: str | None = None
    retryable: bool = True


class RemediationGateway(Protocol):
    async def execute(self, intent: StoredActionIntent) -> ToolResult: ...

    async def observe(
        self,
        intent: StoredActionIntent,
    ) -> RemediationObservation: ...


class KubernetesRemediationGateway:
    """Create one immutable execution contract and wait for Controller status."""

    def __init__(
        self,
        namespace: str,
        *,
        custom_objects_api: Any | None = None,
        poll_interval_seconds: float = 0.25,
        result_timeout_seconds: float = 120,
        api_timeout_seconds: float = 5,
    ) -> None:
        self.namespace = namespace
        self.poll_interval_seconds = poll_interval_seconds
        self.result_timeout_seconds = result_timeout_seconds
        self.api_timeout_seconds = api_timeout_seconds
        self.custom_objects = custom_objects_api or self._build_api()

    @staticmethod
    def _build_api() -> client.CustomObjectsApi:
        try:
            config.load_incluster_config()
        except ConfigException:
            config.load_kube_config()
        configuration = client.Configuration.get_default_copy()
        hostname = urlsplit(configuration.host).hostname
        if hostname in {"127.0.0.1", "localhost", "::1"}:
            configuration.proxy = None
        return client.CustomObjectsApi(client.ApiClient(configuration))

    async def execute(self, intent: StoredActionIntent) -> ToolResult:
        body = build_sentinel_remediation(intent)
        namespace = body["metadata"]["namespace"]
        if namespace != self.namespace:
            raise ValueError("Executor 只能向配置的 workload namespace 提交合同")
        submitted = await self._create_or_confirm(body)
        submitted_uid = self._resource_uid(submitted)
        resource = await self._wait_for_terminal(
            intent.idempotency_key,
            expected_uid=submitted_uid,
        )
        observation = self._interpret_resource(intent, resource)
        if observation.state != "terminal" or observation.result is None:
            raise RuntimeError(
                observation.reason
                or "Controller 终态不能形成可信的执行结果"
            )
        return observation.result

    async def observe(
        self,
        intent: StoredActionIntent,
    ) -> RemediationObservation:
        """Read an existing contract without ever creating or replaying it."""
        expected = build_sentinel_remediation(intent)
        if expected["metadata"]["namespace"] != self.namespace:
            return RemediationObservation(
                state="unknown",
                reason="Action Intent namespace 与 Executor 配置不一致",
                retryable=False,
            )
        try:
            resource = await self._get(intent.idempotency_key)
        except ApiException as exc:
            if exc.status == 404:
                return RemediationObservation(
                    state="not_found",
                    reason="SentinelRemediation 不存在，禁止恢复时补建",
                )
            raise
        return self._interpret_resource(intent, resource)

    async def _create_or_confirm(
        self,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            created = await asyncio.to_thread(
                self.custom_objects.create_namespaced_custom_object,
                GROUP,
                VERSION,
                self.namespace,
                PLURAL,
                body,
                _request_timeout=self.api_timeout_seconds,
            )
            if not isinstance(created, dict):
                raise RuntimeError(
                    "Kubernetes 创建 SentinelRemediation 后返回了无效资源"
                )
            return created
        except ApiException as exc:
            if exc.status != 409:
                raise
        existing = await self._get(body["metadata"]["name"])
        if canonical_digest(existing.get("spec")) != canonical_digest(body["spec"]):
            raise RuntimeError("同名 SentinelRemediation 已绑定不同执行合同")
        return existing

    async def _wait_for_terminal(
        self,
        name: str,
        *,
        expected_uid: str,
    ) -> dict[str, Any]:
        async def poll() -> dict[str, Any]:
            while True:
                resource = await self._get(name)
                if self._resource_uid(resource) != expected_uid:
                    raise RuntimeError(
                        "SentinelRemediation 在等待期间被同名资源替换"
                    )
                status = resource.get("status")
                if isinstance(status, dict) and status.get("phase") in TERMINAL_PHASES:
                    return resource
                await asyncio.sleep(self.poll_interval_seconds)

        try:
            return await asyncio.wait_for(
                poll(),
                timeout=self.result_timeout_seconds,
            )
        except TimeoutError as exc:
            raise TimeoutError(
                f"等待 SentinelRemediation/{name} 终态超时"
            ) from exc

    async def _get(self, name: str) -> dict[str, Any]:
        resource = await asyncio.to_thread(
            self.custom_objects.get_namespaced_custom_object,
            GROUP,
            VERSION,
            self.namespace,
            PLURAL,
            name,
            _request_timeout=self.api_timeout_seconds,
        )
        if not isinstance(resource, dict):
            raise RuntimeError("Kubernetes 返回了无效的 SentinelRemediation")
        return resource

    def _interpret_resource(
        self,
        intent: StoredActionIntent,
        resource: dict[str, Any],
    ) -> RemediationObservation:
        expected = build_sentinel_remediation(intent)
        invalid = self._validate_resource_identity(expected, resource)
        if invalid is not None:
            return RemediationObservation(
                state="unknown",
                reason=invalid,
                retryable=False,
            )
        status = resource.get("status")
        if not isinstance(status, dict) or not status.get("phase"):
            return RemediationObservation(
                state="in_progress",
                reason="Controller 尚未报告执行阶段",
            )
        phase = status.get("phase")
        if phase not in TERMINAL_PHASES:
            return RemediationObservation(
                state=(
                    "unknown"
                    if phase == "Unknown"
                    else "in_progress"
                ),
                phase=str(phase),
                reason=(
                    "Controller 报告未知执行结果"
                    if phase == "Unknown"
                    else "Controller 尚未到达终态"
                ),
            )
        invalid = self._validate_terminal_status(resource, status)
        if invalid is not None:
            return RemediationObservation(
                state="unknown",
                phase=str(phase),
                reason=invalid,
                retryable=False,
            )

        reason = str(status["reason"])
        result = status.get("result")
        if phase == "Succeeded":
            if not self._has_write_boundary_proof(status):
                return RemediationObservation(
                    state="unknown",
                    phase=phase,
                    reason="Controller 成功终态缺少写入分界证明",
                    retryable=False,
                )
            invalid = self._validate_success_result(
                intent,
                expected,
                result,
            )
            if invalid is not None:
                return RemediationObservation(
                    state="unknown",
                    phase=phase,
                    reason=invalid,
                    retryable=False,
                )
            assert isinstance(result, dict)
            tool_result = self._tool_result(
                intent,
                resource,
                status,
                result=result,
                success=True,
            )
            return RemediationObservation(
                state="terminal",
                phase=phase,
                result=tool_result,
                reason=reason,
            )

        crossed_write_boundary = (
            "attempt" in status or "startedAt" in status
        )
        if (
            phase in {"Failed", "Cancelled"}
            or crossed_write_boundary
            or (phase == "Rejected" and reason not in _SAFE_REJECTED_REASONS)
            or (phase == "Stale" and reason not in _SAFE_STALE_REASONS)
        ):
            return RemediationObservation(
                state="unknown",
                phase=phase,
                reason=(
                    f"Controller 终态 {phase}/{reason} "
                    "不能证明写操作未发生"
                ),
                retryable=False,
            )
        if result is not None:
            return RemediationObservation(
                state="unknown",
                phase=phase,
                reason="Controller 失败终态不应携带执行成功结果",
                retryable=False,
            )
        tool_result = self._tool_result(
            intent,
            resource,
            status,
            result={},
            success=False,
        )
        return RemediationObservation(
            state="terminal",
            phase=phase,
            result=tool_result,
            reason=reason,
        )

    def _validate_resource_identity(
        self,
        expected: dict[str, Any],
        resource: dict[str, Any],
    ) -> str | None:
        if resource.get("apiVersion") != expected["apiVersion"]:
            return "SentinelRemediation apiVersion 不匹配"
        if resource.get("kind") != expected["kind"]:
            return "SentinelRemediation kind 不匹配"
        metadata = resource.get("metadata")
        if not isinstance(metadata, dict):
            return "SentinelRemediation 缺少 metadata"
        if metadata.get("name") != expected["metadata"]["name"]:
            return "SentinelRemediation name 不匹配"
        if metadata.get("namespace") != expected["metadata"]["namespace"]:
            return "SentinelRemediation namespace 不匹配"
        try:
            self._resource_uid(resource)
        except RuntimeError as exc:
            return str(exc)
        generation = metadata.get("generation")
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 1
        ):
            return "SentinelRemediation metadata.generation 无效"
        if (
            not isinstance(metadata.get("resourceVersion"), str)
            or not metadata["resourceVersion"]
        ):
            return "SentinelRemediation 缺少 resourceVersion"
        if canonical_digest(resource.get("spec")) != canonical_digest(
            expected["spec"]
        ):
            return "SentinelRemediation spec 与持久化 Action Intent 不一致"
        return None

    @staticmethod
    def _validate_terminal_status(
        resource: dict[str, Any],
        status: dict[str, Any],
    ) -> str | None:
        metadata = resource["metadata"]
        generation = metadata["generation"]
        if status.get("observedGeneration") != generation:
            return "Controller 终态没有绑定当前 resource generation"
        if not isinstance(status.get("controllerId"), str) or not status[
            "controllerId"
        ]:
            return "Controller 终态缺少 controllerId"
        if not isinstance(status.get("finishedAt"), str) or not status[
            "finishedAt"
        ]:
            return "Controller 终态缺少 finishedAt"
        try:
            _normalized_time(status["finishedAt"], "status.finishedAt")
            if "startedAt" in status:
                _normalized_time(status["startedAt"], "status.startedAt")
        except ValueError as exc:
            return str(exc)
        if "attempt" in status and (
            not isinstance(status["attempt"], int)
            or isinstance(status["attempt"], bool)
            or status["attempt"] < 1
        ):
            return "Controller 终态 attempt 无效"
        if not isinstance(status.get("reason"), str) or not status["reason"]:
            return "Controller 终态缺少 reason"
        conditions = status.get("conditions")
        if not isinstance(conditions, list):
            return "Controller 终态缺少 Executed condition"
        executed = [
            item
            for item in conditions
            if isinstance(item, dict) and item.get("type") == "Executed"
        ]
        if len(executed) != 1:
            return "Controller 终态必须包含唯一 Executed condition"
        condition = executed[0]
        expected_condition = (
            "True" if status["phase"] == "Succeeded" else "False"
        )
        if condition.get("status") != expected_condition:
            return "Executed condition 与 Controller phase 不一致"
        if condition.get("observedGeneration") != generation:
            return "Executed condition 没有绑定当前 generation"
        if condition.get("reason") != status["reason"]:
            return "Executed condition reason 与终态不一致"
        return None

    @staticmethod
    def _validate_success_result(
        intent: StoredActionIntent,
        expected: dict[str, Any],
        result: object,
    ) -> str | None:
        if not isinstance(result, dict):
            return "Controller 成功终态缺少 result"
        required = {
            "beforeResourceVersion",
            "afterResourceVersion",
            "observedActionId",
            "outcomeDigest",
            "message",
        }
        if set(result) != required:
            return "Controller 成功结果字段不完整或包含未知字段"
        if any(
            not isinstance(result[field], str) or not result[field]
            for field in required
        ):
            return "Controller 成功结果包含空字段"
        if result["observedActionId"] != intent.idempotency_key:
            return "Controller 成功结果没有绑定 Action Intent"
        if (
            result["beforeResourceVersion"]
            != expected["spec"]["precondition"]["resourceVersion"]
        ):
            return "Controller 成功结果的写前 resourceVersion 不匹配"
        outcome_payload = {
            key: value
            for key, value in result.items()
            if key != "outcomeDigest"
        }
        if result["outcomeDigest"] != canonical_digest(outcome_payload):
            return "Controller 成功结果 outcomeDigest 校验失败"
        if result["afterResourceVersion"] == result["beforeResourceVersion"]:
            return "Controller 成功结果没有证明资源版本发生变化"
        return None

    @staticmethod
    def _has_write_boundary_proof(status: dict[str, Any]) -> bool:
        attempt = status.get("attempt")
        started_at = status.get("startedAt")
        valid_attempt = (
            isinstance(attempt, int)
            and not isinstance(attempt, bool)
            and attempt >= 1
        )
        valid_started_at = isinstance(started_at, str) and bool(started_at)
        return valid_attempt and valid_started_at

    def _tool_result(
        self,
        intent: StoredActionIntent,
        resource: dict[str, Any],
        status: dict[str, Any],
        *,
        result: dict[str, Any],
        success: bool,
    ) -> ToolResult:
        metadata = resource["metadata"]
        phase = str(status["phase"])
        reason = str(status["reason"])
        executed_condition = next(
            item
            for item in status["conditions"]
            if isinstance(item, dict) and item.get("type") == "Executed"
        )
        content = {
            "sentinel_remediation": intent.idempotency_key,
            "remediation_uid": metadata["uid"],
            "remediation_generation": metadata["generation"],
            "spec_digest": canonical_digest(resource["spec"]),
            "controller_id": status["controllerId"],
            "controller_phase": phase,
            "controller_reason": reason,
            "observed_generation": status["observedGeneration"],
            "finished_at": status["finishedAt"],
            "executed_condition_digest": canonical_digest(
                executed_condition
            ),
            "controller_result": result,
        }
        return ToolResult(
            tool_name=intent.action.tool_name,
            success=success,
            content=content,
            error=None if success else self._failure_message(status),
            duration_ms=0,
        )

    @staticmethod
    def _resource_uid(resource: dict[str, Any]) -> str:
        metadata = resource.get("metadata")
        uid = metadata.get("uid") if isinstance(metadata, dict) else None
        if not isinstance(uid, str) or not uid:
            raise RuntimeError("SentinelRemediation 缺少不可变 UID")
        return uid

    @staticmethod
    def _failure_message(status: dict[str, Any]) -> str:
        reason = str(status.get("reason") or status.get("phase") or "ControllerRejected")
        conditions = status.get("conditions")
        if isinstance(conditions, list):
            for condition in conditions:
                if (
                    isinstance(condition, dict)
                    and condition.get("type") == "Executed"
                    and condition.get("message")
                ):
                    return f"{reason}: {condition['message']}"
        return reason
