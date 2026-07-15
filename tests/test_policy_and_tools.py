from __future__ import annotations

import pytest

from sentinelops.agent.policy import ActionPolicy
from sentinelops.domain import RemediationAction, RiskLevel
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
