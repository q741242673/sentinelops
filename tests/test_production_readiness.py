from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "production_readiness.py"
)
SPEC = importlib.util.spec_from_file_location(
    "sentinelops_production_readiness_script",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
Observation = MODULE.Observation
_percentile = MODULE._percentile
_summarize = MODULE._summarize
run = MODULE.run


def test_production_readiness_summary_fails_closed_on_unsafe_write() -> None:
    summary = _summarize(
        [
            Observation(
                scenario="contract",
                trial=0,
                passed=True,
                latency_ms=4.0,
                unsafe_writes=0,
                details={},
            ),
            Observation(
                scenario="contract",
                trial=1,
                passed=False,
                latency_ms=12.0,
                unsafe_writes=1,
                details={"stale_writer_blocked": False},
            ),
        ]
    )

    assert summary["correctness_rate"] == 0.5
    assert summary["unsafe_writes"] == 1
    assert summary["latency_ms"] == {
        "p50": 4.0,
        "p95": 12.0,
        "max": 12.0,
    }
    assert len(summary["failures"]) == 1


def test_percentile_uses_nearest_rank_without_hiding_tail() -> None:
    values = [1.0, 2.0, 3.0, 100.0]
    assert _percentile(values, 0.50) == 2.0
    assert _percentile(values, 0.95) == 100.0


@pytest.mark.asyncio
async def test_production_readiness_refuses_sqlite() -> None:
    with pytest.raises(ValueError, match="PostgreSQL"):
        await run(
            database_url="sqlite+aiosqlite:///unsafe.db",
            rounds=1,
            concurrency=2,
        )


def test_committed_production_readiness_report_is_machine_readable() -> None:
    report_path = (
        Path(__file__).resolve().parents[1]
        / "benchmarks"
        / "production-readiness.json"
    )
    raw = report_path.read_text(encoding="utf-8")
    report = json.loads(raw)

    assert report["schema_version"] == (
        "sentinelops.production-readiness.v1"
    )
    assert report["summary"]["passed"] is True
    assert report["summary"]["correctness_rate"] == 1.0
    assert report["summary"]["unsafe_writes"] == 0
    assert report["summary"]["total_trials"] == 50
    assert set(report["scenarios"]) == {
        "publisher_failover",
        "alert_deduplication",
        "executor_single_claim",
        "executor_crash_recovery",
        "worker_lease_fencing",
    }
    assert "postgresql+asyncpg://" not in raw
    assert "password" not in raw.casefold()
