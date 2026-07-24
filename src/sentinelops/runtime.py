from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from sentinelops.agent import IncidentAgent
from sentinelops.agent.execution import ActionExecutor, ActionJournal
from sentinelops.agent.runbook import IncidentRunbook
from sentinelops.config import Settings, get_settings
from sentinelops.domain import IncidentRecord, RiskLevel
from sentinelops.llm import build_provider
from sentinelops.tools import ToolRegistry, build_tool_registry


def build_agent(
    settings: Settings | None = None,
    *,
    runbook: IncidentRunbook | None = None,
    profile_id: str = "production-default",
    auto_approve_max_risk: RiskLevel | None = None,
    verification_probe_url: str | None = None,
    verification_policy: Literal["strict", "offline"] | None = None,
    progress_callback: Callable[[IncidentRecord], None] | None = None,
    action_journal: ActionJournal | None = None,
    action_executor: ActionExecutor | None = None,
    tools: ToolRegistry | None = None,
) -> IncidentAgent:
    settings = settings or get_settings()
    tools = tools or build_tool_registry(
        settings, allow_guarded_writes=action_executor is None
    )
    return IncidentAgent(
        provider=build_provider(settings),
        tools=tools,
        auto_approve_max_risk=(
            auto_approve_max_risk or RiskLevel(settings.auto_approve_max_risk)
        ),
        verification_probe_url=verification_probe_url or settings.verification_probe_url,
        verification_policy=(
            verification_policy
            or ("strict" if settings.tool_backend == "kubernetes" else "offline")
        ),
        diagnosis_confidence_threshold=settings.diagnosis_confidence_threshold,
        max_reflection_rounds=settings.max_reflection_rounds,
        runbook=runbook,
        profile_id=profile_id,
        progress_callback=progress_callback,
        action_journal=action_journal,
        action_executor=action_executor,
    )
