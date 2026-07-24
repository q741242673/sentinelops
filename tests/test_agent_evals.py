from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from sentinelops.agent import IncidentAgent
from sentinelops.llm.rule_based import RuleBasedProvider
from sentinelops.tools.registry import ToolRegistry
from sentinelops.tools.simulator import SimulatedKubernetesBackend

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "evals" / "run.py"
SPEC = importlib.util.spec_from_file_location(
    "sentinelops_agent_evaluation_script",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
CASES = MODULE.CASES
_run_case = MODULE._run_case
build_report = MODULE.build_report


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"verification_max_attempts": 0},
            "verification_max_attempts",
        ),
        (
            {"verification_interval_seconds": -0.1},
            "verification_interval_seconds",
        ),
    ],
)
def test_verification_timing_configuration_is_bounded(
    kwargs: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        IncidentAgent(
            provider=RuleBasedProvider(),
            tools=ToolRegistry(SimulatedKubernetesBackend()),
            **kwargs,
        )


@pytest.mark.asyncio
async def test_agent_evaluation_suite_passes_and_fails_closed() -> None:
    results = [await _run_case(case) for case in CASES]
    report = build_report(results, duration_ms=250)

    assert report["summary"]["passed"] is True
    assert report["summary"]["total_cases"] == 11
    assert report["summary"]["passed_cases"] == 11
    assert report["summary"]["unsafe_writes"] == 0
    for metric in (
        "case_pass_rate",
        "root_cause_accuracy",
        "grounding_pass_rate",
        "recovery_rate",
        "safe_stop_rate",
        "guardrail_block_rate",
        "stale_approval_block_rate",
        "failed_recovery_detection_rate",
    ):
        assert report["summary"][metric] == 1.0
    assert report["summary"]["unsafe_action_case_rate"] == 0.0

    unsafe = [
        replace(
            results[0],
            passed=False,
            unsafe_writes=1,
            failed_checks=["no_unsafe_writes"],
        ),
        *results[1:],
    ]
    failed_report = build_report(unsafe, duration_ms=250)
    assert failed_report["summary"]["passed"] is False
    assert failed_report["summary"]["unsafe_action_case_rate"] > 0


def test_committed_agent_evaluation_report_is_machine_readable() -> None:
    path = ROOT / "evals" / "report.json"
    raw = path.read_text(encoding="utf-8")
    report = json.loads(raw)

    assert report["schema_version"] == "sentinelops.agent-evaluation.v2"
    assert report["summary"]["passed"] is True
    assert report["summary"]["total_cases"] == 11
    assert report["summary"]["passed_cases"] == 11
    assert report["summary"]["unsafe_writes"] == 0
    assert report["summary"]["unsafe_action_case_rate"] == 0.0
    assert all(item["passed"] for item in report["cases"])
    assert {item["case_id"] for item in report["cases"]} == {case.case_id for case in CASES}
    assert "authorization" not in raw.casefold()
    assert "password" not in raw.casefold()
    assert "api_key" not in raw.casefold()
