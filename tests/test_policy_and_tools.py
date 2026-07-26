from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinelops.actions import (
    STANDARD_ACTION_CATALOG,
    ActionCatalog,
    ActionPlugin,
    VerificationProfile,
)
from sentinelops.agent.policy import ActionPolicy
from sentinelops.domain import RemediationAction, RiskLevel, ToolResult
from sentinelops.llm.rule_based import RuleBasedProvider
from sentinelops.tools.base import ToolSpec, tool_call_fingerprint
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


def execution_precondition(
    tool_name: str,
    arguments: dict[str, object],
) -> dict[str, object]:
    precondition: dict[str, object] = {
        "action_fingerprint": "approved-action",
        "tool_name": tool_name,
        "target": arguments["name"],
        "namespace": "default",
        "deployment_uid": "deployment-uid",
        "generation": 2,
        "resource_version": "17",
        "desired_replicas": 1,
        "paused": False,
        "current_revision": 2,
        "current_replica_set_uid": "replica-set-uid",
        "current_template_hash": "template-hash",
        "current_replicas": 1,
        "current_ready_replicas": 0,
        "captured_at": "2099-07-26T00:00:00+00:00",
        "expires_at": "2099-07-26T00:15:00+00:00",
    }
    if tool_name == "rollback_deployment":
        precondition["rollback_target"] = {
            "revision": arguments["revision"],
            "replica_set_uid": "healthy-replica-set",
            "health_proof": {"subject": "healthy-revision"},
        }
    return precondition


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

    result = await registry.call_guarded(
        tool_name,
        arguments,
        execution_precondition(tool_name, arguments),
    )

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
            **execution_precondition("rollback_deployment", arguments),
            "guarded_tool_name": "restart_deployment",
            "public_arguments_fingerprint": "attacker-controlled",
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


def test_standard_action_catalog_declares_execution_contracts() -> None:
    plugins = {plugin.name: plugin for plugin in STANDARD_ACTION_CATALOG.list()}

    assert set(plugins) == {
        "restart_deployment",
        "rollback_deployment",
        "scale_deployment",
    }
    assert plugins["rollback_deployment"].reversible is True
    assert plugins["restart_deployment"].destructive is False
    assert (
        plugins["scale_deployment"].verification_profile
        == VerificationProfile.WORKLOAD_STRICT
    )
    assert "resource_version" in plugins["restart_deployment"].required_preconditions
    assert "rollback_target" in plugins["rollback_deployment"].required_preconditions


def test_action_catalog_rejects_duplicate_and_read_only_plugins() -> None:
    plugin = ActionPlugin(
        name="safe_action",
        description="test action",
        risk=RiskLevel.LOW,
        input_schema={
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
        target_argument="name",
        reversible=True,
    )
    with pytest.raises(ValueError, match="Duplicate"):
        ActionCatalog([plugin, plugin])
    with pytest.raises(ValueError, match="cannot be read-only"):
        ActionCatalog([plugin.model_copy(update={"risk": RiskLevel.READ_ONLY})])


def test_registry_rejects_write_spec_without_matching_action_plugin() -> None:
    with pytest.raises(ValueError, match="no enabled Action Plugin"):
        ToolRegistry(
            AsyncMock(),
            specs=[
                ToolSpec(
                    name="arbitrary_shell",
                    description="unsafe dynamic command",
                    risk=RiskLevel.CRITICAL,
                    input_schema={
                        "properties": {"command": {"type": "string"}},
                        "required": ["command"],
                    },
                )
            ],
        )


def test_registry_rejects_action_spec_that_weakens_plugin_contract() -> None:
    plugin = STANDARD_ACTION_CATALOG.require("rollback_deployment")
    with pytest.raises(ValueError, match="does not match"):
        ToolRegistry(
            AsyncMock(),
            specs=[
                ToolSpec(
                    name=plugin.name,
                    description=plugin.description,
                    risk=RiskLevel.LOW,
                    input_schema=plugin.input_schema,
                )
            ],
        )


@pytest.mark.asyncio
async def test_guarded_write_rejects_missing_plugin_preconditions() -> None:
    backend = AsyncMock()
    registry = ToolRegistry(backend)

    result = await registry.call_guarded(
        "restart_deployment",
        {"name": "order-service"},
        {
            "tool_name": "restart_deployment",
            "target": "order-service",
            "resource_version": "17",
        },
    )

    assert result.success is False
    assert "Execution precondition is missing" in str(result.error)
    backend.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_guarded_write_rejects_target_mismatch_at_catalog_boundary() -> None:
    backend = AsyncMock()
    registry = ToolRegistry(backend)
    arguments = {"name": "order-service"}
    precondition = execution_precondition("restart_deployment", arguments)
    precondition["target"] = "unrelated-service"

    result = await registry.call_guarded(
        "restart_deployment",
        arguments,
        precondition,
    )

    assert result.success is False
    assert "target does not match" in str(result.error)
    backend.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_guarded_write_rejects_expired_plugin_snapshot() -> None:
    backend = AsyncMock()
    registry = ToolRegistry(backend)
    arguments = {"name": "order-service"}
    precondition = execution_precondition("restart_deployment", arguments)
    precondition["expires_at"] = "2020-01-01T00:00:00+00:00"

    result = await registry.call_guarded(
        "restart_deployment",
        arguments,
        precondition,
    )

    assert result.success is False
    assert "has expired" in str(result.error)
    backend.call.assert_not_awaited()


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
