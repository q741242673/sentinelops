from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path


def write_failure_report(
    output: Path,
    *,
    phase: str,
    mode: str,
    exit_status: int,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "sentinelops.topology-bootstrap-failure.v1",
        "passed": False,
        "mode": mode,
        "phase": phase,
        "exit_status": exit_status,
        "generated_at": datetime.now(UTC).isoformat(),
        "safe_failure": True,
        "details": (
            "The topology stopped before the benchmark could produce its "
            "normal readiness report. Inspect the bounded Kubernetes "
            "diagnostics in the corresponding CI job."
        ),
    }
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--exit-status", type=int, required=True)
    arguments = parser.parse_args()
    write_failure_report(
        arguments.output,
        phase=arguments.phase,
        mode=arguments.mode,
        exit_status=arguments.exit_status,
    )


if __name__ == "__main__":
    main()
