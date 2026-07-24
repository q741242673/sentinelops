from __future__ import annotations

import argparse
import os
import time
from pathlib import Path


def check_heartbeat(file_path: str, *, max_age_seconds: float) -> None:
    """Fail unless a worker heartbeat exists and is recent."""
    try:
        age_seconds = time.time() - Path(file_path).stat().st_mtime
    except OSError as exc:
        raise SystemExit("Worker health heartbeat is missing") from exc
    if age_seconds < 0 or age_seconds > max_age_seconds:
        raise SystemExit("Worker health heartbeat is stale")


def _main(*, environment_variable: str, worker_name: str) -> None:
    parser = argparse.ArgumentParser(
        description=f"Check the {worker_name} heartbeat file",
    )
    parser.add_argument("--file")
    parser.add_argument("--max-age-seconds", type=float, default=120)
    args = parser.parse_args()
    file_path = args.file or os.getenv(environment_variable)
    if not file_path:
        raise SystemExit(f"Set {environment_variable} or pass --file")
    check_heartbeat(file_path, max_age_seconds=args.max_age_seconds)


def executor_main() -> None:
    _main(
        environment_variable="SENTINELOPS_EXECUTOR_HEALTH_FILE",
        worker_name="Executor",
    )


def anchor_main() -> None:
    _main(
        environment_variable="SENTINELOPS_AUDIT_ANCHOR_HEALTH_FILE",
        worker_name="Audit Anchor Publisher",
    )

