from __future__ import annotations

from pathlib import Path

LIVE_CONSOLE_SCRIPT = Path(__file__).parents[1] / "scripts" / "live-console.sh"


def test_port_forwards_are_supervised_and_restarted() -> None:
    script = LIVE_CONSOLE_SCRIPT.read_text()
    start_port_forward = script.split("start_port_forward() {", maxsplit=1)[1].split(
        '"${ROOT_DIR}/scripts/observability-up.sh"', maxsplit=1
    )[0]

    assert "while true; do" in start_port_forward
    assert 'wait "${child_pid}" || true' in start_port_forward
    assert "trap stop_port_forward EXIT INT TERM" in start_port_forward
