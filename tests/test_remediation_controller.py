from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

import pytest
from kubernetes.client.exceptions import ApiException

from sentinelops.domain import RemediationAction, RiskLevel
from sentinelops.remediation_controller import (
    KubernetesRemediationGateway,
    action_catalog_digest,
    authorization_policy_digest,
    build_sentinel_remediation,
    canonical_digest,
    human_approval_digest,
)
from sentinelops.storage.base import StoredActionIntent


class FakeCustomObjectsApi:
    def __init__(
        self,
        *,
        terminal_phase: str = "Succeeded",
        terminal_reason: str = "ActionApplied",
        outcome_digest_override: str | None = None,
        crossed_write_boundary: bool = False,
    ) -> None:
        self.resource: dict | None = None
        self.create_calls = 0
        self.get_calls = 0
        self.terminal_phase = terminal_phase
        self.terminal_reason = terminal_reason
        self.outcome_digest_override = outcome_digest_override
        self.crossed_write_boundary = crossed_write_boundary

    def create_namespaced_custom_object(
        self,
        _group,
        _version,
        _namespace,
        _plural,
        body,
        **_kwargs,
    ):
        self.create_calls += 1
        if self.resource is not None:
            raise ApiException(status=409, reason="AlreadyExists")
        self.resource = deepcopy(body)
        self.resource["metadata"].update(
            {
                "uid": "remediation-uid",
                "generation": 1,
                "resourceVersion": "41",
            }
        )
        return deepcopy(self.resource)

    def get_namespaced_custom_object(
        self,
        _group,
        _version,
        _namespace,
        _plural,
        _name,
        **_kwargs,
    ):
        self.get_calls += 1
        assert self.resource is not None
        resource = deepcopy(self.resource)
        if self.get_calls >= 2:
            outcome = {
                "beforeResourceVersion": resource["spec"]["precondition"][
                    "resourceVersion"
                ],
                "afterResourceVersion": "42",
                "observedActionId": resource["spec"]["actionId"],
                "message": "registered action was applied exactly once",
            }
            outcome["outcomeDigest"] = canonical_digest(outcome)
            if self.outcome_digest_override is not None:
                outcome["outcomeDigest"] = self.outcome_digest_override
            resource["status"] = {
                "phase": self.terminal_phase,
                "reason": self.terminal_reason,
                "observedGeneration": resource["metadata"]["generation"],
                "controllerId": "controller-a",
                "finishedAt": "2026-07-26T06:01:00Z",
                "result": (
                    outcome if self.terminal_phase == "Succeeded" else None
                ),
                "conditions": [
                    {
                        "type": "Executed",
                        "status": (
                            "True" if self.terminal_phase == "Succeeded" else "False"
                        ),
                        "reason": self.terminal_reason,
                        "message": "controller terminal result",
                        "observedGeneration": resource["metadata"][
                            "generation"
                        ],
                    }
                ],
            }
            if (
                self.terminal_phase == "Succeeded"
                or self.crossed_write_boundary
            ):
                resource["status"].update(
                    {
                        "attempt": 1,
                        "startedAt": "2026-07-26T06:00:30Z",
                    }
                )
        return resource


class MissingCustomObjectsApi:
    def __init__(self) -> None:
        self.create_calls = 0
        self.get_calls = 0

    def create_namespaced_custom_object(self, *_args, **_kwargs):
        self.create_calls += 1
        raise AssertionError("只读恢复不能创建 SentinelRemediation")

    def get_namespaced_custom_object(self, *_args, **_kwargs):
        self.get_calls += 1
        raise ApiException(status=404, reason="NotFound")


def _intent(
    action_name: str = "restart_deployment",
    *,
    approval: bool = False,
) -> StoredActionIntent:
    arguments: dict[str, object] = {"name": "order-service"}
    risk = RiskLevel.MEDIUM
    if action_name == "rollback_deployment":
        arguments["revision"] = 1
        risk = RiskLevel.HIGH
    if action_name == "scale_deployment":
        arguments["replicas"] = 5
        risk = RiskLevel.HIGH
    precondition: dict[str, object] = {
        "action_fingerprint": "approved-action",
        "tool_name": action_name,
        "target": "order-service",
        "namespace": "sentinelops-workloads",
        "deployment_uid": "deployment-uid",
        "generation": 4,
        "resource_version": "17",
        "desired_replicas": 3,
        "paused": False,
        "current_revision": 2,
        "current_replica_set_uid": "replica-set-current",
        "current_template_hash": "hash-v2",
        "current_replicas": 3,
        "current_ready_replicas": 2,
        "captured_at": "2026-07-26T06:00:00+00:00",
        "expires_at": "2026-07-26T06:15:00+00:00",
    }
    if action_name == "rollback_deployment":
        precondition["rollback_target"] = {
            "revision": 1,
            "replica_set_uid": "replica-set-healthy",
            "health_proof": {
                "subject": "sha256:healthy-subject",
                "version": "v1",
                "verified_at": "2026-07-26T05:55:00Z",
                "verifier": "sentinelops-health-proof/v1",
            },
        }
    return StoredActionIntent(
        idempotency_key="a" * 64,
        incident_id="incident-01",
        lease_generation=2,
        approval_id="approval-01" if approval else None,
        approval_version=3 if approval else None,
        action=RemediationAction(
            tool_name=action_name,
            arguments=arguments,
            rationale="restore the last known safe state",
            expected_outcome="workload becomes healthy",
            risk=risk,
        ),
        precondition=precondition,
        status="dispatched",
        result=None,
        error=None,
        executor_id="executor-a",
        executor_generation=1,
        executor_lease_until=datetime(2026, 7, 26, 6, 10, tzinfo=UTC),
        attempt_id="attempt-01",
    )


def test_python_catalog_digests_match_controller_contract() -> None:
    assert (
        action_catalog_digest("restart_deployment")
        == "29dbaa37e2caaaaa8056267c1b6ff8c9dc18f5fe3311353154634beee7c65bf9"
    )
    assert (
        action_catalog_digest("rollback_deployment")
        == "c431542012a61d0f456d839569c3b7f9d4c3a817395357dbfc77374f3fa445ea"
    )
    assert (
        action_catalog_digest("scale_deployment")
        == "856ea7b9c7740c7147307a7c665ed6c2a851c45b117889de78e29758f551127d"
    )


def test_build_automatic_contract_binds_snapshot_and_workload_generation() -> None:
    body = build_sentinel_remediation(_intent())

    assert body["metadata"] == {
        "name": "a" * 64,
        "namespace": "sentinelops-workloads",
    }
    spec = body["spec"]
    assert spec["action"]["plugin"] == "restart_deployment"
    assert spec["target"]["uid"] == "deployment-uid"
    assert spec["fence"] == {
        "generation": 4,
        "expiresAt": "2026-07-26T06:15:00Z",
    }
    snapshot = dict(spec["precondition"])
    snapshot_digest = snapshot.pop("snapshotDigest")
    assert snapshot_digest == canonical_digest(snapshot)
    assert spec["authorization"]["decision"] == "risk_policy"
    assert spec["authorization"]["policyDigest"] == authorization_policy_digest(
        "restart_deployment",
        "risk_policy",
        spec["action"]["catalogDigest"],
    )
    assert "approvalId" not in spec["authorization"]


def test_snapshot_uses_metav1_whole_second_canonical_time() -> None:
    intent = _intent()
    intent.precondition["captured_at"] = "2026-07-26T10:06:19.316941Z"
    intent.precondition["expires_at"] = "2026-07-26T10:11:19.316941Z"

    spec = build_sentinel_remediation(intent)["spec"]
    snapshot = dict(spec["precondition"])
    snapshot_digest = snapshot.pop("snapshotDigest")

    assert snapshot["capturedAt"] == "2026-07-26T10:06:19Z"
    assert spec["fence"]["expiresAt"] == "2026-07-26T10:11:19Z"
    assert snapshot_digest == canonical_digest(snapshot)


def test_build_human_approval_contract_binds_action_id_and_version() -> None:
    body = build_sentinel_remediation(
        _intent("rollback_deployment", approval=True)
    )
    spec = body["spec"]
    authorization = spec["authorization"]

    assert authorization["decision"] == "human_approval"
    assert authorization["approvalId"] == "approval-01"
    assert authorization["approvalVersion"] == 3
    assert authorization["approvalDigest"] == human_approval_digest(
        "a" * 64,
        "approval-01",
        3,
        authorization["policyDigest"],
    )
    assert (
        spec["precondition"]["rollbackTarget"]["healthProofDigest"]
        == canonical_digest(
            {
                "subject": "sha256:healthy-subject",
                "verifiedAt": "2026-07-26T05:55:00Z",
                "verifier": "sentinelops-health-proof/v1",
                "version": "v1",
            }
        )
    )


def test_contract_rejects_action_target_mismatch() -> None:
    intent = _intent()
    intent.precondition["target"] = "unrelated-service"

    with pytest.raises(ValueError, match="目标不一致"):
        build_sentinel_remediation(intent)


@pytest.mark.asyncio
async def test_gateway_creates_contract_and_waits_for_bound_success() -> None:
    api = FakeCustomObjectsApi()
    gateway = KubernetesRemediationGateway(
        "sentinelops-workloads",
        custom_objects_api=api,
        poll_interval_seconds=0,
        result_timeout_seconds=1,
    )

    result = await gateway.execute(_intent())

    assert result.success is True
    assert result.tool_name == "restart_deployment"
    assert result.content["controller_phase"] == "Succeeded"
    assert result.content["sentinel_remediation"] == "a" * 64
    assert result.content["observed_generation"] == 1
    assert result.content["finished_at"] == "2026-07-26T06:01:00Z"
    assert len(result.content["executed_condition_digest"]) == 64
    assert api.create_calls == 1
    assert api.get_calls == 2


@pytest.mark.asyncio
async def test_gateway_reuses_only_an_identical_existing_contract() -> None:
    api = FakeCustomObjectsApi()
    api.resource = build_sentinel_remediation(_intent())
    api.resource["metadata"].update(
        {
            "uid": "existing-remediation-uid",
            "generation": 1,
            "resourceVersion": "40",
        }
    )
    gateway = KubernetesRemediationGateway(
        "sentinelops-workloads",
        custom_objects_api=api,
        poll_interval_seconds=0,
        result_timeout_seconds=1,
    )

    result = await gateway.execute(_intent())

    assert result.success is True
    assert api.create_calls == 1

    assert api.resource is not None
    api.resource["spec"]["target"]["uid"] = "replacement-uid"
    with pytest.raises(RuntimeError, match="不同执行合同"):
        await gateway.execute(_intent())


@pytest.mark.asyncio
async def test_controller_rejection_is_a_failed_tool_result() -> None:
    api = FakeCustomObjectsApi(
        terminal_phase="Stale",
        terminal_reason="ResourceVersionChanged",
    )
    gateway = KubernetesRemediationGateway(
        "sentinelops-workloads",
        custom_objects_api=api,
        poll_interval_seconds=0,
        result_timeout_seconds=1,
    )

    result = await gateway.execute(_intent())

    assert result.success is False
    assert result.content["controller_phase"] == "Stale"
    assert result.error == "ResourceVersionChanged: controller terminal result"


@pytest.mark.asyncio
async def test_observe_missing_contract_never_creates_or_replays_it() -> None:
    api = MissingCustomObjectsApi()
    gateway = KubernetesRemediationGateway(
        "sentinelops-workloads",
        custom_objects_api=api,
    )

    observation = await gateway.observe(_intent())

    assert observation.state == "not_found"
    assert api.get_calls == 1
    assert api.create_calls == 0


@pytest.mark.asyncio
async def test_observe_accepts_only_a_fully_bound_controller_result() -> None:
    api = FakeCustomObjectsApi()
    api.create_namespaced_custom_object(
        None,
        None,
        None,
        None,
        build_sentinel_remediation(_intent()),
    )
    api.get_calls = 1
    gateway = KubernetesRemediationGateway(
        "sentinelops-workloads",
        custom_objects_api=api,
    )

    observation = await gateway.observe(_intent())

    assert observation.state == "terminal"
    assert observation.result is not None
    assert observation.result.success is True
    assert observation.result.duration_ms == 0

    assert api.resource is not None
    api.resource["spec"]["target"]["uid"] = "spoofed-target"
    rejected = await gateway.observe(_intent())
    assert rejected.state == "unknown"
    assert "spec" in str(rejected.reason)


@pytest.mark.asyncio
async def test_observe_rejects_false_success_digest_and_unknown_stale_outcome() -> None:
    api = FakeCustomObjectsApi(outcome_digest_override="0" * 64)
    api.create_namespaced_custom_object(
        None,
        None,
        None,
        None,
        build_sentinel_remediation(_intent()),
    )
    api.get_calls = 1
    gateway = KubernetesRemediationGateway(
        "sentinelops-workloads",
        custom_objects_api=api,
    )

    invalid_digest = await gateway.observe(_intent())
    assert invalid_digest.state == "unknown"
    assert "outcomeDigest" in str(invalid_digest.reason)

    unsafe_api = FakeCustomObjectsApi(
        terminal_phase="Stale",
        terminal_reason="ActionOutcomeUnknown",
    )
    unsafe_api.create_namespaced_custom_object(
        None,
        None,
        None,
        None,
        build_sentinel_remediation(_intent()),
    )
    unsafe_api.get_calls = 1
    unsafe_gateway = KubernetesRemediationGateway(
        "sentinelops-workloads",
        custom_objects_api=unsafe_api,
    )
    unsafe = await unsafe_gateway.observe(_intent())
    assert unsafe.state == "unknown"
    assert "不能证明写操作未发生" in str(unsafe.reason)

    after_write_api = FakeCustomObjectsApi(
        terminal_phase="Stale",
        terminal_reason="FenceSuperseded",
        crossed_write_boundary=True,
    )
    after_write_api.create_namespaced_custom_object(
        None,
        None,
        None,
        None,
        build_sentinel_remediation(_intent()),
    )
    after_write_api.get_calls = 1
    after_write_gateway = KubernetesRemediationGateway(
        "sentinelops-workloads",
        custom_objects_api=after_write_api,
    )
    after_write = await after_write_gateway.observe(_intent())
    assert after_write.state == "unknown"
    assert "不能证明写操作未发生" in str(after_write.reason)
