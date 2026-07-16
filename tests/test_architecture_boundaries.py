from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_production_agent_core_contains_no_lab_scenario_branches() -> None:
    core = (ROOT / "src/sentinelops/agent/engine.py").read_text()
    forbidden = {
        "transient_runtime_fault",
        "auto_remediation",
        "reflection_demo",
        "ambiguous_change_fault",
    }

    assert forbidden.isdisjoint(core.split())
    assert all(token not in core for token in forbidden)


def test_production_runtime_does_not_load_demo_configuration() -> None:
    runtime = (ROOT / "src/sentinelops/runtime.py").read_text()

    assert "scenario" not in runtime
    assert "demo_order_url" not in runtime
    assert "lab_profiles" not in runtime


def test_alert_rules_do_not_grant_agent_authority() -> None:
    manifest = (ROOT / "deploy/observability/stack.yaml").read_text()

    assert "auto_remediation:" not in manifest
    assert "reflection_demo:" not in manifest
    assert "scenario:" not in manifest
