from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _read_report(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "report_missing"
    except (OSError, json.JSONDecodeError):
        return None, "report_unreadable"
    if not isinstance(payload, dict):
        return None, "report_not_an_object"
    return payload, None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _latency_p95(report: dict[str, Any] | None, name: str) -> float | None:
    latency = _as_dict(report.get("latency_ms") if report else None)
    metric = _as_dict(latency.get(name))
    value = metric.get("p95")
    return float(value) if isinstance(value, int | float) else None


def _provenance(
    report: dict[str, Any] | None,
) -> tuple[str | None, int | None, int | None, bool, bool]:
    provenance = _as_dict(
        report.get("provenance") if report else None
    )
    source = _as_dict(provenance.get("source"))
    execution = _as_dict(provenance.get("execution"))
    checks = _as_dict(provenance.get("checks"))
    subjects = _as_list(provenance.get("subjects"))
    has_container = any(
        isinstance(subject, dict)
        and subject.get("kind") == "container_image"
        and isinstance(subject.get("build_image_digest"), str)
        and str(subject["build_image_digest"]).startswith("sha256:")
        and len(_as_list(subject.get("running_image_ids"))) == 1
        for subject in subjects
    )
    valid = (
        provenance.get("schema_version")
        == "sentinelops.report-provenance.v1"
        and isinstance(source.get("commit"), str)
        and re.fullmatch(r"[0-9a-f]{40}", str(source["commit"]))
        is not None
        and source.get("dirty") is False
        and bool(checks)
        and all(value is True for value in checks.values())
    )
    run_id = execution.get("run_id")
    run_attempt = execution.get("run_attempt")
    return (
        str(source["commit"]) if valid else None,
        int(run_id) if isinstance(run_id, int) else None,
        int(run_attempt) if isinstance(run_attempt, int) else None,
        valid,
        has_container,
    )


def build_report(
    *,
    kubernetes_report: dict[str, Any] | None,
    postgres_report: dict[str, Any] | None,
    topology_report: dict[str, Any] | None,
    chaos_report: dict[str, Any] | None,
    expected_kubernetes_rounds: int,
    expected_postgres_rounds: int,
    max_p95_recovery_ms: float,
    max_p95_chaos_recovery_ms: float,
    max_p95_executor_takeover_ms: float,
    expected_git_commit: str | None = None,
    expected_github_run_id: int | None = None,
    input_errors: list[str] | None = None,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    errors = list(input_errors or [])
    kubernetes_summary = _as_dict(
        kubernetes_report.get("summary") if kubernetes_report else None
    )
    kubernetes_latency = _as_dict(
        kubernetes_report.get("latency_ms") if kubernetes_report else None
    )
    recovery_latency = _as_dict(
        kubernetes_latency.get("fault_to_verified_recovery")
    )
    kubernetes_trials = _as_list(
        kubernetes_report.get("trials") if kubernetes_report else None
    )
    incident_ids = [
        trial.get("incident_id")
        for trial in kubernetes_trials
        if isinstance(trial, dict) and trial.get("incident_id")
    ]

    checks["kubernetes_report_schema"] = bool(
        kubernetes_report
        and kubernetes_report.get("schema_version")
        == "sentinelops.kubernetes-readiness.v1"
    )
    checks["kubernetes_rounds_complete"] = (
        kubernetes_summary.get("trials") == expected_kubernetes_rounds
        and len(kubernetes_trials) == expected_kubernetes_rounds
    )
    checks["kubernetes_success_rate"] = (
        kubernetes_summary.get("passed") is True
        and kubernetes_summary.get("success_rate") == 1.0
    )
    checks["root_cause_accuracy"] = (
        kubernetes_summary.get("root_cause_accuracy") == 1.0
    )
    checks["verified_recovery_rate"] = (
        kubernetes_summary.get("verified_recovery_rate") == 1.0
    )
    checks["zero_wrong_remediation_plans"] = (
        kubernetes_summary.get("wrong_remediation_plans") == 0
    )
    checks["zero_unsafe_writes"] = (
        kubernetes_summary.get("unsafe_writes") == 0
    )
    checks["unique_incident_per_round"] = (
        len(incident_ids) == expected_kubernetes_rounds
        and len(set(incident_ids)) == expected_kubernetes_rounds
    )
    checks["exactly_one_write_per_round"] = all(
        isinstance(trial, dict)
        and trial.get("write_attempts") == 1
        and trial.get("successful_writes") == 1
        for trial in kubernetes_trials
    ) and len(kubernetes_trials) == expected_kubernetes_rounds
    checks["healthy_traffic_after_every_recovery"] = all(
        isinstance(trial, dict)
        and trial.get("healthy_requests_after_recovery", 0) >= 10
        for trial in kubernetes_trials
    ) and len(kubernetes_trials) == expected_kubernetes_rounds
    recovery_p95 = recovery_latency.get("p95")
    checks["recovery_p95_within_budget"] = (
        isinstance(recovery_p95, int | float)
        and 0 < float(recovery_p95) <= max_p95_recovery_ms
    )

    postgres_summary = _as_dict(
        postgres_report.get("summary") if postgres_report else None
    )
    postgres_configuration = _as_dict(
        postgres_report.get("configuration") if postgres_report else None
    )
    scenario_count = postgres_configuration.get("scenario_count")
    expected_postgres_trials = (
        expected_postgres_rounds * scenario_count
        if isinstance(scenario_count, int)
        else None
    )
    checks["postgres_report_schema"] = bool(
        postgres_report
        and postgres_report.get("schema_version")
        == "sentinelops.production-readiness.v1"
    )
    checks["postgres_rounds_complete"] = (
        postgres_configuration.get("rounds_per_scenario")
        == expected_postgres_rounds
        and expected_postgres_trials is not None
        and postgres_summary.get("total_trials") == expected_postgres_trials
        and postgres_summary.get("passed_trials") == expected_postgres_trials
    )
    checks["postgres_correctness_rate"] = (
        postgres_summary.get("passed") is True
        and postgres_summary.get("correctness_rate") == 1.0
    )
    checks["postgres_zero_unsafe_writes"] = (
        postgres_summary.get("unsafe_writes") == 0
    )

    topology_summary = _as_dict(
        topology_report.get("summary") if topology_report else None
    )
    topology_trial = _as_dict(
        topology_report.get("trial") if topology_report else None
    )
    topology_checks = _as_dict(topology_trial.get("checks"))
    checks["topology_report_schema"] = bool(
        topology_report
        and topology_report.get("schema_version")
        == "sentinelops.topology-readiness.v1"
    )
    checks["topology_two_replica_recovery"] = (
        topology_summary.get("passed") is True
        and topology_summary.get("wrong_remediation_plans") == 0
        and topology_summary.get("unsafe_writes") == 0
        and topology_summary.get("action_intents") == 1
        and bool(topology_checks)
        and all(value is True for value in topology_checks.values())
    )
    topology_recovery_p95 = _latency_p95(
        topology_report,
        "fault_to_verified_recovery",
    )
    checks["topology_recovery_p95_within_budget"] = (
        topology_recovery_p95 is not None
        and 0 < topology_recovery_p95 <= max_p95_recovery_ms
    )

    chaos_summary = _as_dict(
        chaos_report.get("summary") if chaos_report else None
    )
    chaos_trial = _as_dict(
        chaos_report.get("trial") if chaos_report else None
    )
    chaos_checks = _as_dict(chaos_trial.get("checks"))
    checks["chaos_report_schema"] = bool(
        chaos_report
        and chaos_report.get("schema_version")
        == "sentinelops.control-plane-chaos.v1"
    )
    checks["chaos_fenced_takeover"] = (
        chaos_summary.get("passed") is True
        and chaos_summary.get("wrong_remediation_plans") == 0
        and chaos_summary.get("unsafe_writes") == 0
        and chaos_summary.get("action_intents") == 1
        and bool(chaos_checks)
        and all(value is True for value in chaos_checks.values())
    )
    chaos_recovery_p95 = _latency_p95(
        chaos_report,
        "fault_to_verified_recovery",
    )
    executor_takeover_p95 = _latency_p95(
        chaos_report,
        "executor_takeover",
    )
    checks["chaos_recovery_p95_within_budget"] = (
        chaos_recovery_p95 is not None
        and 0
        < chaos_recovery_p95
        <= max_p95_chaos_recovery_ms
    )
    checks["executor_takeover_p95_within_budget"] = (
        executor_takeover_p95 is not None
        and 0
        < executor_takeover_p95
        <= max_p95_executor_takeover_ms
    )

    reports = (
        kubernetes_report,
        postgres_report,
        topology_report,
        chaos_report,
    )
    identities = [_provenance(report) for report in reports]
    commits = [identity[0] for identity in identities]
    run_ids = [identity[1] for identity in identities]
    run_attempts = [identity[2] for identity in identities]
    checks["all_reports_have_valid_provenance"] = all(
        identity[3] for identity in identities
    )
    checks["container_reports_use_immutable_images"] = all(
        identities[index][4] for index in (0, 2, 3)
    )
    checks["reports_test_same_commit"] = (
        None not in commits and len(set(commits)) == 1
    )
    checks["reports_share_github_run"] = (
        None not in run_ids
        and None not in run_attempts
        and len(set(run_ids)) == 1
        and len(set(run_attempts)) == 1
    )
    checks["expected_git_commit_tested"] = (
        expected_git_commit is None
        or (
            re.fullmatch(r"[0-9a-f]{40}", expected_git_commit) is not None
            and all(commit == expected_git_commit for commit in commits)
        )
    )
    checks["expected_github_run_tested"] = (
        expected_github_run_id is None
        or all(
            run_id == expected_github_run_id
            for run_id in run_ids
        )
    )

    passed = not errors and all(checks.values())
    return {
        "schema_version": "sentinelops.soak-acceptance.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "configuration": {
            "expected_kubernetes_rounds": expected_kubernetes_rounds,
            "expected_postgres_rounds_per_scenario": expected_postgres_rounds,
        },
        "thresholds": {
            "success_rate": 1.0,
            "root_cause_accuracy": 1.0,
            "verified_recovery_rate": 1.0,
            "wrong_remediation_plans": 0,
            "unsafe_writes": 0,
            "writes_per_kubernetes_round": 1,
            "max_p95_fault_to_verified_recovery_ms": max_p95_recovery_ms,
            "max_p95_chaos_recovery_ms": max_p95_chaos_recovery_ms,
            "max_p95_executor_takeover_ms": (
                max_p95_executor_takeover_ms
            ),
        },
        "summary": {
            "passed": passed,
            "checks_passed": sum(checks.values()),
            "checks_total": len(checks),
            "kubernetes_rounds": kubernetes_summary.get("trials", 0),
            "postgres_trials": postgres_summary.get("total_trials", 0),
            "recovery_p95_ms": recovery_p95,
            "topology_recovery_p95_ms": topology_recovery_p95,
            "chaos_recovery_p95_ms": chaos_recovery_p95,
            "executor_takeover_p95_ms": executor_takeover_p95,
            "unsafe_writes": sum(
                int(summary.get("unsafe_writes", 0) or 0)
                for summary in (
                    kubernetes_summary,
                    postgres_summary,
                    topology_summary,
                    chaos_summary,
                )
            ),
            "wrong_remediation_plans": sum(
                int(summary.get("wrong_remediation_plans", 0) or 0)
                for summary in (
                    kubernetes_summary,
                    topology_summary,
                    chaos_summary,
                )
            ),
        },
        "checks": checks,
        "sources": {
            "kubernetes_run_id": (
                kubernetes_report.get("run_id") if kubernetes_report else None
            ),
            "postgres_run_id": (
                postgres_report.get("run_id") if postgres_report else None
            ),
            "topology_run_id": (
                topology_report.get("run_id") if topology_report else None
            ),
            "chaos_run_id": (
                chaos_report.get("run_id") if chaos_report else None
            ),
            "git_commit": commits[0] if commits else None,
            "github_run_id": run_ids[0] if run_ids else None,
            "github_run_attempt": (
                run_attempts[0] if run_attempts else None
            ),
        },
        "errors": errors,
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply fail-closed RC gates to Kubernetes and PostgreSQL soak reports.",
    )
    parser.add_argument("--kubernetes-report", type=Path, required=True)
    parser.add_argument("--postgres-report", type=Path, required=True)
    parser.add_argument("--topology-report", type=Path, required=True)
    parser.add_argument("--chaos-report", type=Path, required=True)
    parser.add_argument("--expected-kubernetes-rounds", type=int, default=20)
    parser.add_argument("--expected-postgres-rounds", type=int, default=100)
    parser.add_argument("--max-p95-recovery-ms", type=float, default=60_000)
    parser.add_argument(
        "--max-p95-chaos-recovery-ms",
        type=float,
        default=90_000,
    )
    parser.add_argument(
        "--max-p95-executor-takeover-ms",
        type=float,
        default=45_000,
    )
    parser.add_argument("--expected-git-commit")
    parser.add_argument("--expected-github-run-id", type=int)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/soak-acceptance.json"),
    )
    arguments = parser.parse_args()
    if not 3 <= arguments.expected_kubernetes_rounds <= 100:
        parser.error("--expected-kubernetes-rounds must be between 3 and 100")
    if not 10 <= arguments.expected_postgres_rounds <= 1_000:
        parser.error("--expected-postgres-rounds must be between 10 and 1000")
    if not 10_000 <= arguments.max_p95_recovery_ms <= 300_000:
        parser.error("--max-p95-recovery-ms must be between 10000 and 300000")
    if not 10_000 <= arguments.max_p95_chaos_recovery_ms <= 300_000:
        parser.error(
            "--max-p95-chaos-recovery-ms must be between 10000 and 300000"
        )
    if not 5_000 <= arguments.max_p95_executor_takeover_ms <= 120_000:
        parser.error(
            "--max-p95-executor-takeover-ms must be between 5000 and 120000"
        )
    return arguments


def main() -> None:
    arguments = _arguments()
    kubernetes_report, kubernetes_error = _read_report(arguments.kubernetes_report)
    postgres_report, postgres_error = _read_report(arguments.postgres_report)
    topology_report, topology_error = _read_report(arguments.topology_report)
    chaos_report, chaos_error = _read_report(arguments.chaos_report)
    input_errors = [
        f"{name}:{error}"
        for name, error in (
            ("kubernetes", kubernetes_error),
            ("postgres", postgres_error),
            ("topology", topology_error),
            ("chaos", chaos_error),
        )
        if error is not None
    ]
    report = build_report(
        kubernetes_report=kubernetes_report,
        postgres_report=postgres_report,
        topology_report=topology_report,
        chaos_report=chaos_report,
        expected_kubernetes_rounds=arguments.expected_kubernetes_rounds,
        expected_postgres_rounds=arguments.expected_postgres_rounds,
        max_p95_recovery_ms=arguments.max_p95_recovery_ms,
        max_p95_chaos_recovery_ms=(
            arguments.max_p95_chaos_recovery_ms
        ),
        max_p95_executor_takeover_ms=(
            arguments.max_p95_executor_takeover_ms
        ),
        expected_git_commit=arguments.expected_git_commit,
        expected_github_run_id=arguments.expected_github_run_id,
        input_errors=input_errors,
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    arguments.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    if not report["summary"]["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
