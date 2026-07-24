from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_bootstrap_failure_report_is_bounded_and_structured(tmp_path) -> None:
    output = tmp_path / "artifacts" / "security-readiness.json"
    script = (
        Path(__file__).parents[1]
        / "scripts"
        / "e2e_bootstrap_failure.py"
    )

    subprocess.run(
        [
            sys.executable,
            str(script),
            "--output",
            str(output),
            "--phase",
            "anchor-publisher-rollout",
            "--mode",
            "security",
            "--exit-status",
            "1",
        ],
        check=True,
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema"] == "sentinelops.topology-bootstrap-failure.v1"
    assert report["passed"] is False
    assert report["safe_failure"] is True
    assert report["mode"] == "security"
    assert report["phase"] == "anchor-publisher-rollout"
    assert report["exit_status"] == 1
    assert set(report) == {
        "schema",
        "passed",
        "mode",
        "phase",
        "exit_status",
        "generated_at",
        "safe_failure",
        "details",
    }
