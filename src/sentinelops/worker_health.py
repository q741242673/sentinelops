from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from typing import Any


async def run_with_health_pulse(
    work_loop: Coroutine[Any, Any, None],
    *,
    callback: Callable[[], None] | None,
    interval_seconds: float,
) -> None:
    """Keep process liveness independent from one slow control-loop iteration."""
    if callback is None:
        await work_loop
        return
    if interval_seconds <= 0:
        raise ValueError("health pulse interval must be positive")

    async def pulse() -> None:
        while True:
            callback()
            await asyncio.sleep(interval_seconds)

    async with asyncio.TaskGroup() as tasks:
        tasks.create_task(pulse())
        tasks.create_task(work_loop)
