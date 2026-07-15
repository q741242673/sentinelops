from __future__ import annotations

from sentinelops.agent import IncidentAgent
from sentinelops.config import Settings, get_settings
from sentinelops.domain import RiskLevel
from sentinelops.llm import build_provider
from sentinelops.tools import build_tool_registry


def build_agent(
    settings: Settings | None = None, *, scenario: str = "bad_rollout"
) -> IncidentAgent:
    settings = settings or get_settings()
    return IncidentAgent(
        provider=build_provider(settings),
        tools=build_tool_registry(settings, scenario=scenario),
        auto_approve_max_risk=RiskLevel(settings.auto_approve_max_risk),
    )
