from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinelops.agent.policy import ActionPolicy
from sentinelops.domain import RemediationAction, RiskLevel, ToolResult
from sentinelops.llm.rule_based import RuleBasedProvider
from sentinelops.tools.base import tool_call_fingerprint
from sentinelops.tools.registry import ToolRegistry
from sentinelops.tools.simulator import SimulatedKubernetesBackend


def action(tool_name: str, risk: RiskLevel) -> RemediationAction:
    return RemediationAction(
        tool_name=tool_name,
        arguments={},
        rationale="test",
        expected_outcome="test",
        risk=risk,
    )


def test_policy_requires_approval_above_threshold() -> None:
    policy = ActionPolicy(RiskLevel.LOW)
    assert policy.requires_approval(action("restart_deployment", RiskLevel.MEDIUM))
    assert not policy.requires_approval(action("list_pods", RiskLevel.READ_ONLY))


def test_policy_permanently_denies_dangerous_tools() -> None:
    policy = ActionPolicy(RiskLevel.CRITICAL)
    with pytest.raises(PermissionError):
        policy.validate(action("exec_in_pod", RiskLevel.HIGH))


@pytest.mark.asyncio
async def test_registry_rejects_unlisted_tool() -> None:
    registry = ToolRegistry(SimulatedKubernetesBackend())
    result = await registry.call("arbitrary_shell", {"command": "whoami"})
    assert result.success is False
    assert result.error == "Tool is not allowlisted"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "arguments", "error"),
    [
        ("restart_deployment", {"name": "order-service", "extra": True}, "Unexpected"),
        ("restart_deployment", {"name": 123}, "must be a string"),
        ("restart_deployment", {"name": "Order_Service"}, "required pattern"),
        ("restart_deployment", {"name": f"a{'b' * 63}"}, "required pattern"),
        (
            "restart_deployment",
            {"name": ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62])},
            "exceeds 253",
        ),
        ("rollback_deployment", {"name": "order-service", "revision": "1"}, "integer"),
        ("rollback_deployment", {"name": "order-service", "revision": True}, "integer"),
        ("rollback_deployment", {"name": "order-service", "revision": 0}, "at least 1"),
        ("scale_deployment", {"name": "order-service", "replicas": "3"}, "integer"),
        ("scale_deployment", {"name": "order-service", "replicas": False}, "integer"),
        ("scale_deployment", {"name": "order-service", "replicas": -1}, "at least 0"),
        ("scale_deployment", {"name": "order-service", "replicas": 101}, "at most 100"),
    ],
)
async def test_registry_rejects_invalid_write_arguments_before_backend(
    tool_name: str,
    arguments: dict,
    error: str,
) -> None:
    backend = AsyncMock()
    registry = ToolRegistry(backend)

    result = await registry.call(tool_name, arguments)

    assert result.success is False
    assert error in str(result.error)
    backend.call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("restart_deployment", {"name": "a"}),
        ("restart_deployment", {"name": f"a{'b' * 62}"}),
        (
            "restart_deployment",
            {"name": ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])},
        ),
        ("rollback_deployment", {"name": "order-service", "revision": 1}),
        ("scale_deployment", {"name": "order-service", "replicas": 0}),
        ("scale_deployment", {"name": "order-service", "replicas": 100}),
    ],
)
async def test_registry_accepts_valid_write_argument_boundaries(
    tool_name: str,
    arguments: dict,
) -> None:
    backend = AsyncMock()
    backend.call.return_value = ToolResult(tool_name=tool_name, success=True)
    registry = ToolRegistry(backend)

    result = await registry.call_guarded(tool_name, arguments, {"snapshot": "test"})

    assert result.success is True
    guarded_arguments = backend.call.await_args.args[1]
    assert {
        key: value
        for key, value in guarded_arguments.items()
        if key != "_precondition"
    } == arguments


@pytest.mark.asyncio
async def test_registry_plain_call_rejects_write_tools_even_with_valid_arguments() -> None:
    backend = AsyncMock()
    registry = ToolRegistry(backend)

    result = await registry.call(
        "rollback_deployment", {"name": "order-service", "revision": 1}
    )

    assert result.success is False
    assert "host-generated execution precondition" in str(result.error)
    backend.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_agent_read_registry_cannot_cross_guarded_write_boundary() -> None:
    backend = AsyncMock()
    registry = ToolRegistry(backend, allow_guarded_writes=False)

    result = await registry.call_guarded(
        "rollback_deployment",
        {"name": "order-service", "revision": 1},
        {"resource_version": "17"},
    )

    assert result.success is False
    assert "does not hold the cluster-write capability" in str(result.error)
    backend.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_registry_preserves_existing_read_tool_argument_compatibility() -> None:
    backend = AsyncMock()
    backend.call.return_value = ToolResult(tool_name="get_pod_logs", success=True)
    registry = ToolRegistry(backend)
    arguments = {"label_selector": "app=order-service", "tail_lines": 200}

    result = await registry.call("get_pod_logs", arguments)

    assert result.success is True
    backend.call.assert_awaited_once_with("get_pod_logs", arguments)


@pytest.mark.asyncio
async def test_registry_binds_guard_to_validated_tool_and_public_arguments() -> None:
    backend = AsyncMock()
    backend.call.return_value = ToolResult(
        tool_name="rollback_deployment", success=True
    )
    registry = ToolRegistry(backend)
    arguments = {"name": "order-service", "revision": 1}

    await registry.call_guarded(
        "rollback_deployment",
        arguments,
        {
            "guarded_tool_name": "restart_deployment",
            "public_arguments_fingerprint": "attacker-controlled",
            "deployment_uid": "deployment-uid",
        },
    )

    guarded_arguments = backend.call.await_args.args[1]
    assert guarded_arguments["_precondition"]["guarded_tool_name"] == (
        "rollback_deployment"
    )
    assert guarded_arguments["_precondition"][
        "public_arguments_fingerprint"
    ] == tool_call_fingerprint("rollback_deployment", arguments)
    assert guarded_arguments["_precondition"]["deployment_uid"] == "deployment-uid"


def test_rule_provider_infers_bad_rollout_from_live_cluster_evidence() -> None:
    observations = {
        "scenario": "live_cluster",
        "pods": {
            "items": [
                {
                    "ready": False,
                    "restarts": 3,
                    "waiting_reasons": ["CrashLoopBackOff"],
                }
            ]
        },
        "logs": {"lines": ["FATAL: application configuration is invalid"]},
    }

    assert RuleBasedProvider._infer_scenario(observations) == "bad_rollout"


@pytest.mark.asyncio
async def test_simulator_rollout_uses_structured_health_status() -> None:
    backend = SimulatedKubernetesBackend(scenario="bad_rollout")

    result = await backend.call("get_rollout_history", {"name": "order-service"})

    assert result.success is True
    assert [item["health_status"] for item in result.content["revisions"]] == [
        "healthy",
        "unknown",
    ]
    assert [item["health_proof"]["valid"] for item in result.content["revisions"]] == [
        True,
        False,
    ]
