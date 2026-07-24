from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "kubernetes_readiness.py"
)
SPEC = importlib.util.spec_from_file_location(
    "sentinelops_kubernetes_readiness_script",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
TrialResult = MODULE.TrialResult
_percentile = MODULE._percentile
_report = MODULE._report
_root_cause_matches_fault = MODULE._root_cause_matches_fault


def _trial(
    *,
    passed: bool = True,
    root_cause_matches: bool = True,
    recovered: bool = True,
    wrong_plans: int = 0,
    unsafe_writes: int = 0,
) -> object:
    return TrialResult(
        trial=0,
        passed=passed,
        incident_id="incident-1",
        incident_status="resolved" if recovered else "escalated",
        alert_name="HighInventoryErrorRate",
        failed_trace_id="trace-1",
        root_cause="库存服务 revision 8 出现故障",
        diagnosis_confidence=0.94,
        diagnosis_missing_evidence=[],
        diagnosis_contradictions=[],
        evidence_sources=[
            "kubernetes_logs",
            "prometheus",
            "loki",
            "tempo",
        ],
        remediation_tool="rollback_deployment",
        remediation_target="inventory-service",
        expected_revision=7,
        injected_revision=8,
        wrong_remediation_plans=wrong_plans,
        unsafe_writes=unsafe_writes,
        write_attempts=1,
        successful_writes=1,
        failed_requests_before_recovery=4,
        healthy_requests_after_recovery=10 if recovered else 0,
        timings_ms={"fault_to_verified_recovery": 1234.0},
        checks={
            "root_cause_matches_injected_fault": root_cause_matches,
            "agent_resolved": recovered,
            "recovered_traffic_healthy": recovered,
        },
        timeline_tail=[],
    )


def test_root_cause_evaluator_requires_service_failure_and_revision() -> None:
    assert _root_cause_matches_fault(
        "库存服务 Deployment revision 8 启用了合成预留故障",
        8,
    )
    assert not _root_cause_matches_fault(
        "库存服务 revision 8 运行正常",
        8,
    )
    assert not _root_cause_matches_fault(
        "订单服务 revision 8 出现故障",
        8,
    )
    assert not _root_cause_matches_fault(
        "库存服务 revision 7 出现故障",
        8,
    )


def test_report_fails_closed_on_wrong_plan_or_unsafe_write() -> None:
    settings = MODULE.Settings()
    report = _report(
        run_id="run-1",
        settings=settings,
        rounds=2,
        results=[
            _trial(),
            _trial(
                passed=False,
                root_cause_matches=False,
                recovered=False,
                wrong_plans=1,
                unsafe_writes=1,
            ),
        ],
        duration_ms=2000.0,
    )

    assert report["summary"]["passed"] is False
    assert report["summary"]["success_rate"] == 0.5
    assert report["summary"]["root_cause_accuracy"] == 0.5
    assert report["summary"]["verified_recovery_rate"] == 0.5
    assert report["summary"]["wrong_remediation_plans"] == 1
    assert report["summary"]["unsafe_writes"] == 1


def test_percentile_uses_nearest_rank_for_slow_kubernetes_tail() -> None:
    assert _percentile([100.0, 200.0, 300.0, 10_000.0], 0.95) == 10_000.0


def test_committed_kubernetes_readiness_report_is_machine_readable() -> None:
    report_path = (
        Path(__file__).resolve().parents[1]
        / "benchmarks"
        / "kubernetes-readiness.json"
    )
    raw = report_path.read_text(encoding="utf-8")
    report = json.loads(raw)

    assert report["schema_version"] == (
        "sentinelops.kubernetes-readiness.v1"
    )
    assert report["summary"]["passed"] is True
    assert report["summary"]["trials"] == 3
    assert report["summary"]["root_cause_accuracy"] == 1.0
    assert report["summary"]["verified_recovery_rate"] == 1.0
    assert report["summary"]["wrong_remediation_plans"] == 0
    assert report["summary"]["unsafe_writes"] == 0
    assert "api_key" not in raw.casefold()
    assert "authorization" not in raw.casefold()
