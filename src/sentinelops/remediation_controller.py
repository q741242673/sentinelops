from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from datetime import UTC, datetime
from typing import Any, Protocol
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


class RemediationGateway(Protocol):
    async def execute(self, intent: StoredActionIntent) -> ToolResult: ...


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
        started = time.perf_counter()
        body = build_sentinel_remediation(intent)
        namespace = body["metadata"]["namespace"]
        if namespace != self.namespace:
            raise ValueError("Executor 只能向配置的 workload namespace 提交合同")
        await self._create_or_confirm(body)
        resource = await self._wait_for_terminal(intent.idempotency_key)
        status = resource.get("status")
        if not isinstance(status, dict):
            raise RuntimeError("Controller 终态缺少 status")
        phase = status.get("phase")
        reason = str(status.get("reason") or phase or "ControllerResult")
        result = status.get("result")
        content = {
            "sentinel_remediation": intent.idempotency_key,
            "controller_phase": phase,
            "controller_reason": reason,
            "controller_result": result if isinstance(result, dict) else {},
        }
        if phase == "Succeeded":
            if (
                not isinstance(result, dict)
                or result.get("observedActionId") != intent.idempotency_key
                or not result.get("outcomeDigest")
            ):
                raise RuntimeError("Controller 成功结果没有绑定 Action Intent")
            return ToolResult(
                tool_name=intent.action.tool_name,
                success=True,
                content=content,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        return ToolResult(
            tool_name=intent.action.tool_name,
            success=False,
            content=content,
            error=self._failure_message(status),
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    async def _create_or_confirm(self, body: dict[str, Any]) -> None:
        try:
            await asyncio.to_thread(
                self.custom_objects.create_namespaced_custom_object,
                GROUP,
                VERSION,
                self.namespace,
                PLURAL,
                body,
                _request_timeout=self.api_timeout_seconds,
            )
            return
        except ApiException as exc:
            if exc.status != 409:
                raise
        existing = await self._get(body["metadata"]["name"])
        if canonical_digest(existing.get("spec")) != canonical_digest(body["spec"]):
            raise RuntimeError("同名 SentinelRemediation 已绑定不同执行合同")

    async def _wait_for_terminal(self, name: str) -> dict[str, Any]:
        async def poll() -> dict[str, Any]:
            while True:
                resource = await self._get(name)
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

    @staticmethod
    def _failure_message(status: dict[str, Any]) -> str:
        reason = str(status.get("reason") or status.get("phase") or "ControllerRejected")
        conditions = status.get("conditions")
        if isinstance(conditions, list):
            for condition in reversed(conditions):
                if isinstance(condition, dict) and condition.get("message"):
                    return f"{reason}: {condition['message']}"
        return reason
