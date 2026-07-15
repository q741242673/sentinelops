from __future__ import annotations

import json
from typing import Any, TypeVar

from pydantic import BaseModel

from sentinelops.domain import (
    Diagnosis,
    Evidence,
    Hypothesis,
    RemediationAction,
    RemediationPlan,
    RiskLevel,
)

T = TypeVar("T", bound=BaseModel)


class RuleBasedProvider:
    """Deterministic offline provider used for demos and CI.

    It deliberately implements the same contract as remote LLM providers so the
    complete graph can be exercised without an API key.
    """

    name = "rule_based"

    async def structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: type[T],
        metadata: dict[str, Any] | None = None,
    ) -> T:
        payload = json.loads(prompt)
        observations = payload.get("observations", {})
        scenario = self._infer_scenario(observations)

        if schema is Diagnosis:
            return self._diagnose(scenario, observations)  # type: ignore[return-value]
        if schema is RemediationPlan:
            return self._plan(scenario, payload)  # type: ignore[return-value]
        raise TypeError(f"RuleBasedProvider does not support schema {schema.__name__}")

    @staticmethod
    def _infer_scenario(observations: dict[str, Any]) -> str:
        declared = observations.get("scenario")
        if declared in {"bad_rollout", "db_pool_exhaustion", "inventory_faulty_rollout"}:
            return declared

        pods = observations.get("pods", {}).get("items", [])
        logs = "\n".join(observations.get("logs", {}).get("lines", [])).lower()
        all_evidence = json.dumps(observations, ensure_ascii=False).lower()
        if "inventory_reservation_failed" in all_evidence or "synthetic_timeout" in all_evidence:
            return "inventory_faulty_rollout"
        has_unhealthy_rollout_pod = any(
            (not pod.get("ready"))
            and (
                pod.get("restarts", 0) > 0
                or set(pod.get("waiting_reasons", [])) & {"CrashLoopBackOff", "Error"}
            )
            for pod in pods
        )
        if has_unhealthy_rollout_pod or "fatal" in logs:
            return "bad_rollout"
        return "db_pool_exhaustion"

    def _diagnose(self, scenario: str, observations: dict[str, Any]) -> Diagnosis:
        if scenario == "inventory_faulty_rollout":
            evidence = [
                Evidence(
                    source="prometheus",
                    query="query_prometheus",
                    finding="Inventory request metrics contain HTTP 503 responses",
                    raw=observations.get("prometheus", {}),
                ),
                Evidence(
                    source="loki",
                    query="search_loki",
                    finding="Inventory logs report synthetic reservation timeouts",
                    raw=observations.get("loki", {}),
                ),
                Evidence(
                    source="tempo",
                    query="get_trace",
                    finding="The failed checkout trace crosses the inventory service",
                    raw=observations.get("trace", {}),
                ),
                Evidence(
                    source="kubernetes.rollout",
                    query="get_rollout_history",
                    finding="The error-producing configuration is deployment revision 2",
                    raw=observations.get("rollout", {}),
                ),
            ]
            root_cause = "Inventory deployment revision 2 enabled a synthetic reservation failure"
            hypothesis = "The latest inventory configuration rollout introduced the 503 errors"
        elif scenario == "bad_rollout":
            evidence = [
                Evidence(
                    source="kubernetes.events",
                    query="list_events",
                    finding="New pods entered CrashLoopBackOff immediately after rollout",
                    raw=observations.get("events", {}),
                ),
                Evidence(
                    source="kubernetes.rollout",
                    query="get_rollout_history",
                    finding="Error spike started after deployment revision 2",
                    raw=observations.get("rollout", {}),
                ),
            ]
            root_cause = "Deployment revision 2 contains a broken application image"
            hypothesis = "The latest rollout introduced the incident"
        else:
            evidence = [
                Evidence(
                    source="kubernetes.logs",
                    query="get_pod_logs",
                    finding="Requests fail while acquiring database connections",
                    raw=observations.get("logs", {}),
                ),
                Evidence(
                    source="metrics",
                    query="get_service_metrics",
                    finding="Database connection pool utilization reached 100%",
                    raw=observations.get("metrics", {}),
                ),
            ]
            root_cause = "Database connection pool exhaustion in the order service"
            hypothesis = "The order service exhausted its database connection pool"

        return Diagnosis(
            root_cause=root_cause,
            confidence=0.94,
            hypotheses=[Hypothesis(statement=hypothesis, confidence=0.94, evidence=evidence)],
            evidence_summary=[item.finding for item in evidence],
        )

    def _plan(self, scenario: str, payload: dict[str, Any]) -> RemediationPlan:
        if scenario == "inventory_faulty_rollout":
            service = payload["alert"]["service"]
            action = RemediationAction(
                tool_name="rollback_deployment",
                arguments={"name": service, "revision": 1},
                rationale=(
                    "Revision 2 introduced inventory 503 responses while revision 1 was healthy"
                ),
                expected_outcome="Inventory 503 responses stop and checkout traffic recovers",
                risk=RiskLevel.HIGH,
            )
        elif scenario == "bad_rollout":
            action = RemediationAction(
                tool_name="rollback_deployment",
                arguments={"name": "order-service", "revision": 1},
                rationale="The incident correlates with revision 2 and its pods are unhealthy",
                expected_outcome=(
                    "Revision 1 becomes available and the error rate returns to baseline"
                ),
                risk=RiskLevel.HIGH,
            )
        else:
            action = RemediationAction(
                tool_name="restart_deployment",
                arguments={"name": "order-service"},
                rationale="Recycle leaked database connections while preserving desired state",
                expected_outcome=(
                    "Connection pool utilization and request errors return to baseline"
                ),
                risk=RiskLevel.MEDIUM,
            )
        return RemediationPlan(
            summary=f"Remediate {payload['diagnosis']['root_cause']}",
            actions=[action],
            rollback="Stop automation and restore the previous deployment revision",
            verification=["Available replicas equal desired replicas", "Error rate is below 1%"],
        )
