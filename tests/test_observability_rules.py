from __future__ import annotations

from pathlib import Path

STACK_MANIFEST = Path(__file__).parents[1] / "deploy" / "observability" / "stack.yaml"


def test_generic_error_alert_has_transient_fault_cooldown() -> None:
    manifest = STACK_MANIFEST.read_text()
    generic_rule = manifest.split("- alert: HighInventoryErrorRate", maxsplit=1)[1].split(
        "- alert: InventoryTransientRuntimeFault", maxsplit=1
    )[0]

    assert "unless on()" in generic_rule
    assert "max_over_time(" in generic_rule
    assert (
        'sentinelops_transient_runtime_fault{service="inventory-service"}[45s]'
        in generic_rule
    )
