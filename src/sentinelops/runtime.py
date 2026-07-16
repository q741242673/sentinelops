from __future__ import annotations

from collections.abc import Callable

from sentinelops.agent import IncidentAgent
from sentinelops.config import Settings, get_settings
from sentinelops.domain import IncidentRecord, RiskLevel
from sentinelops.llm import build_provider
from sentinelops.tools import build_tool_registry


def build_agent(
    settings: Settings | None = None,
    *,
    scenario: str = "bad_rollout",
    progress_callback: Callable[[IncidentRecord], None] | None = None,
) -> IncidentAgent:
    settings = settings or get_settings()
    return IncidentAgent(
        provider=build_provider(settings),
        tools=build_tool_registry(settings, scenario=scenario),
        auto_approve_max_risk=RiskLevel(settings.auto_approve_max_risk),
        verification_probe_url=settings.demo_order_url,
        diagnosis_confidence_threshold=settings.diagnosis_confidence_threshold,
        max_reflection_rounds=settings.max_reflection_rounds,
        progress_callback=progress_callback,
    )
