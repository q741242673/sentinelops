from __future__ import annotations

from typing import Any

from sentinelops.agent.state import IncidentState
from sentinelops.domain import Diagnosis, RemediationPlan


class IncidentRunbook:
    """Trusted server-side extension point for service-specific operational policy.

    Alert labels and model output must never construct or select a runbook. The host selects
    one from authenticated configuration or an explicit, server-owned workflow profile.
    """

    id = "production-default"

    def reflection_decision(
        self,
        state: IncidentState,
        diagnosis: Diagnosis,
    ) -> bool | None:
        """Return True/False to override the generic quality gate, or None to defer."""
        return None

    def planning_guidance(self, state: IncidentState) -> str | None:
        """Return trusted runbook guidance to append to the planning system prompt."""
        return None

    def additional_remediation_targets(self, state: IncidentState) -> set[str]:
        """Return explicitly trusted targets in addition to the alerted service."""
        return set()

    def plan_feedback(
        self,
        state: IncidentState,
        plan: RemediationPlan,
        specs: dict[str, Any],
    ) -> str | None:
        """Reject a plan that violates this trusted runbook."""
        return None
