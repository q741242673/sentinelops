from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/soak_gate.py"
SPEC = importlib.util.spec_from_file_location(
    "sentinelops_soak_gate_script",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _kubernetes_report(rounds: int = 3) -> dict:
    return {
        "schema_version": "sentinelops.kubernetes-readiness.v1",
        "run_id": "kubernetes-run",
        "summary": {
            "passed": True,
            "trials": rounds,
            "success_rate": 1.0,
            "root_cause_accuracy": 1.0,
            "verified_recovery_rate": 1.0,
            "wrong_remediation_plans": 0,
            "unsafe_writes": 0,
        },
        "latency_ms": {
            "fault_to_verified_recovery": {
                "p95": 42_000.0,
            }
        },
        "trials": [
            {
                "incident_id": f"incident-{trial}",
                "write_attempts": 1,
                "successful_writes": 1,
                "healthy_requests_after_recovery": 10,
            }
            for trial in range(rounds)
        ],
    }


def _postgres_report(rounds: int = 10) -> dict:
    return {
        "schema_version": "sentinelops.production-readiness.v1",
        "run_id": "postgres-run",
        "configuration": {
            "rounds_per_scenario": rounds,
            "scenario_count": 5,
        },
        "summary": {
            "passed": True,
            "total_trials": rounds * 5,
            "passed_trials": rounds * 5,
            "correctness_rate": 1.0,
            "unsafe_writes": 0,
        },
    }


def _report(
    kubernetes: dict | None = None,
    postgres: dict | None = None,
) -> dict:
    return MODULE.build_report(
        kubernetes_report=kubernetes or _kubernetes_report(),
        postgres_report=postgres or _postgres_report(),
        expected_kubernetes_rounds=3,
        expected_postgres_rounds=10,
        max_p95_recovery_ms=60_000,
    )


def test_soak_gate_accepts_complete_safe_reports() -> None:
    report = _report()

    assert report["summary"]["passed"] is True
    assert report["summary"]["checks_passed"] == report["summary"]["checks_total"]
    assert report["summary"]["kubernetes_rounds"] == 3
    assert report["summary"]["postgres_trials"] == 50


def test_soak_gate_fails_closed_on_any_unsafe_write() -> None:
    kubernetes = _kubernetes_report()
    kubernetes["summary"]["unsafe_writes"] = 1

    report = _report(kubernetes=kubernetes)

    assert report["summary"]["passed"] is False
    assert report["checks"]["zero_unsafe_writes"] is False


def test_soak_gate_rejects_duplicate_incident_and_extra_write() -> None:
    kubernetes = _kubernetes_report()
    kubernetes["trials"][1]["incident_id"] = "incident-0"
    kubernetes["trials"][2]["write_attempts"] = 2

    report = _report(kubernetes=kubernetes)

    assert report["summary"]["passed"] is False
    assert report["checks"]["unique_incident_per_round"] is False
    assert report["checks"]["exactly_one_write_per_round"] is False


def test_soak_gate_rejects_incomplete_or_slow_run() -> None:
    kubernetes = _kubernetes_report(rounds=2)
    kubernetes["latency_ms"]["fault_to_verified_recovery"]["p95"] = 60_001

    report = _report(kubernetes=kubernetes)

    assert report["summary"]["passed"] is False
    assert report["checks"]["kubernetes_rounds_complete"] is False
    assert report["checks"]["recovery_p95_within_budget"] is False


def test_soak_gate_reports_missing_inputs_without_secret_details() -> None:
    report = MODULE.build_report(
        kubernetes_report=None,
        postgres_report=None,
        expected_kubernetes_rounds=3,
        expected_postgres_rounds=10,
        max_p95_recovery_ms=60_000,
        input_errors=["kubernetes:report_missing", "postgres:report_missing"],
    )

    assert report["summary"]["passed"] is False
    assert report["errors"] == [
        "kubernetes:report_missing",
        "postgres:report_missing",
    ]
