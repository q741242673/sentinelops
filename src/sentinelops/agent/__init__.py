from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sentinelops.agent.engine import IncidentAgent

__all__ = ["IncidentAgent"]


def __getattr__(name: str) -> Any:
    if name == "IncidentAgent":
        from sentinelops.agent.engine import IncidentAgent

        return IncidentAgent
    raise AttributeError(name)
