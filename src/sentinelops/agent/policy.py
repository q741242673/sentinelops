from __future__ import annotations

from sentinelops.domain import RISK_ORDER, RemediationAction, RiskLevel


class ActionPolicy:
    def __init__(self, auto_approve_max_risk: RiskLevel) -> None:
        self.auto_approve_max_risk = auto_approve_max_risk

    def requires_approval(self, action: RemediationAction) -> bool:
        return RISK_ORDER[action.risk] > RISK_ORDER[self.auto_approve_max_risk]

    def validate(self, action: RemediationAction) -> None:
        permanently_denied = {"exec_in_pod", "read_secret", "create_privileged_pod"}
        if action.tool_name in permanently_denied:
            raise PermissionError(f"Action is permanently denied: {action.tool_name}")
