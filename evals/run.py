from __future__ import annotations

import asyncio
import json
from pathlib import Path
from time import perf_counter

from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentStatus
from sentinelops.runtime import build_agent

SCENARIOS = {
    "bad_rollout": "broken application image",
    "db_pool_exhaustion": "connection pool exhaustion",
}


async def evaluate() -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    settings = Settings(tool_backend="simulator", model_provider="rule_based")
    for scenario, expected in SCENARIOS.items():
        agent = build_agent(settings, scenario=scenario)
        alert = Alert(
            name="SyntheticIncident",
            namespace="sentinelops-demo",
            service="order-service",
            severity="critical",
            summary=f"Synthetic evaluation scenario: {scenario}",
        )
        started = perf_counter()
        record = await agent.start(alert)
        record = await agent.resume(record.id, approved=True, note="Automated evaluation")
        diagnosis = record.diagnosis.root_cause.lower() if record.diagnosis else ""
        results.append(
            {
                "scenario": scenario,
                "root_cause_correct": expected in diagnosis,
                "recovery_success": record.status == IncidentStatus.RESOLVED,
                "tool_calls": len(record.execution_results),
                "duration_ms": round((perf_counter() - started) * 1000, 2),
            }
        )
    return results


if __name__ == "__main__":
    report = asyncio.run(evaluate())
    output = Path("evals/report.json")
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
