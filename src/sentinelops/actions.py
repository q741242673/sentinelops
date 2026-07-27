from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from sentinelops.domain import RemediationAction, RiskLevel

if TYPE_CHECKING:
    from sentinelops.tools.base import ToolSpec


class ApprovalMode(StrEnum):
    """How a registered write action reaches its execution boundary."""

    RISK_POLICY = "risk_policy"
    ALWAYS = "always"


class VerificationProfile(StrEnum):
    """Server-owned recovery contract associated with an action."""

    WORKLOAD_STRICT = "workload_strict"


class ActionPlugin(BaseModel):
    """Server-owned contract for one executable remediation capability.

    The model may select one of these contracts, but it cannot create or alter
    them. Execution code remains host-owned and is routed by ``name``.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    risk: RiskLevel
    input_schema: dict[str, Any]
    target_argument: str = Field(min_length=1)
    approval_mode: ApprovalMode = ApprovalMode.RISK_POLICY
    verification_profile: VerificationProfile = VerificationProfile.WORKLOAD_STRICT
    required_preconditions: tuple[str, ...] = ()
    reversible: bool
    destructive: bool = False
    enabled: bool = True

    def as_tool_spec(self) -> ToolSpec:
        from sentinelops.tools.base import ToolSpec

        return ToolSpec(
            name=self.name,
            description=self.description,
            risk=self.risk,
            input_schema=self.input_schema,
        )


class ActionCatalog:
    """Host-owned registry of the only write actions an Executor may dispatch."""

    def __init__(self, plugins: Iterable[ActionPlugin]) -> None:
        registered: dict[str, ActionPlugin] = {}
        for plugin in plugins:
            if plugin.risk == RiskLevel.READ_ONLY:
                raise ValueError(f"Action plugin {plugin.name} cannot be read-only")
            if plugin.name in registered:
                raise ValueError(f"Duplicate action plugin: {plugin.name}")
            if plugin.target_argument not in plugin.input_schema.get("properties", {}):
                raise ValueError(
                    f"Action plugin {plugin.name} target_argument is not in input_schema"
                )
            registered[plugin.name] = plugin
        self._plugins = registered

    def list(self, *, enabled_only: bool = True) -> list[ActionPlugin]:
        plugins = list(self._plugins.values())
        if enabled_only:
            return [plugin for plugin in plugins if plugin.enabled]
        return plugins

    def get(self, name: str) -> ActionPlugin | None:
        plugin = self._plugins.get(name)
        return plugin if plugin is not None and plugin.enabled else None

    def require(self, name: str) -> ActionPlugin:
        plugin = self.get(name)
        if plugin is None:
            raise PermissionError(f"Action is not registered or enabled: {name}")
        return plugin

    def validate_action(
        self,
        action: RemediationAction,
        *,
        allowed_targets: set[str] | None = None,
    ) -> str | None:
        plugin = self.get(action.tool_name)
        if plugin is None:
            return f"{action.tool_name} 没有注册为可执行 Action Plugin"
        target = action.arguments.get(plugin.target_argument)
        if not isinstance(target, str) or not target:
            return f"{action.tool_name} 缺少合法目标参数 {plugin.target_argument}"
        if allowed_targets is not None and target not in allowed_targets:
            return f"{action.tool_name} 的目标 {target!r} 不在本次事故的可信修复范围内"
        return None

    def validate_precondition(
        self,
        name: str,
        arguments: dict[str, Any],
        precondition: dict[str, Any],
    ) -> str | None:
        plugin = self.get(name)
        if plugin is None:
            return f"Action is not registered or enabled: {name}"
        missing = [
            key
            for key in plugin.required_preconditions
            if precondition.get(key) is None or precondition.get(key) == ""
        ]
        if missing:
            return "Execution precondition is missing: " + ", ".join(missing)
        target = arguments.get(plugin.target_argument)
        if precondition.get("target") != target:
            return "Execution precondition target does not match action arguments"
        if precondition.get("tool_name") != name:
            return "Execution precondition tool does not match registered action"
        try:
            expires_at = datetime.fromisoformat(str(precondition["expires_at"]))
        except (KeyError, ValueError):
            return "Execution precondition has an invalid expiration time"
        if expires_at.tzinfo is None:
            return "Execution precondition expiration time must include a timezone"
        if datetime.now(UTC) >= expires_at.astimezone(UTC):
            return "Execution precondition has expired"
        return None

    def tool_specs(self) -> list[ToolSpec]:
        return [plugin.as_tool_spec() for plugin in self.list()]


KUBERNETES_NAME_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 253,
    "pattern": (
        r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$"
    ),
}

WORKLOAD_PRECONDITIONS = (
    "action_fingerprint",
    "tool_name",
    "target",
    "cluster_id",
    "namespace",
    "deployment_uid",
    "generation",
    "resource_version",
    "desired_replicas",
    "paused",
    "current_revision",
    "current_replica_set_uid",
    "current_template_hash",
    "current_replicas",
    "current_ready_replicas",
    "captured_at",
    "expires_at",
)

STANDARD_ACTION_CATALOG = ActionCatalog(
    [
        ActionPlugin(
            name="restart_deployment",
            description="Trigger a rolling restart of a deployment",
            risk=RiskLevel.MEDIUM,
            input_schema={
                "type": "object",
                "properties": {"name": KUBERNETES_NAME_SCHEMA},
                "required": ["name"],
                "additionalProperties": False,
            },
            target_argument="name",
            required_preconditions=WORKLOAD_PRECONDITIONS,
            reversible=False,
        ),
        ActionPlugin(
            name="rollback_deployment",
            description="Rollback a deployment to a known revision",
            risk=RiskLevel.HIGH,
            input_schema={
                "type": "object",
                "properties": {
                    "name": KUBERNETES_NAME_SCHEMA,
                    "revision": {"type": "integer", "minimum": 1},
                },
                "required": ["name", "revision"],
                "additionalProperties": False,
            },
            target_argument="name",
            required_preconditions=(*WORKLOAD_PRECONDITIONS, "rollback_target"),
            reversible=True,
        ),
        ActionPlugin(
            name="scale_deployment",
            description="Change desired deployment replicas",
            risk=RiskLevel.HIGH,
            input_schema={
                "type": "object",
                "properties": {
                    "name": KUBERNETES_NAME_SCHEMA,
                    "replicas": {"type": "integer", "minimum": 0, "maximum": 100},
                },
                "required": ["name", "replicas"],
                "additionalProperties": False,
            },
            target_argument="name",
            required_preconditions=WORKLOAD_PRECONDITIONS,
            reversible=True,
        ),
    ]
)
