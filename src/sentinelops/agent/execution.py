from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from sentinelops.domain import RemediationAction, ToolResult


class ActionExecutionRejected(RuntimeError):
    """The executor proved that no external write was dispatched."""


class ActionOutcomeUnknown(RuntimeError):
    """An external write may have been dispatched but has no trusted result."""


@dataclass(frozen=True)
class ActionJournalEntry:
    idempotency_key: str
    status: Literal[
        "prepared",
        "dispatched",
        "succeeded",
        "failed",
        "unknown",
        "cancelled",
    ]


class ActionJournal(Protocol):
    async def prepare(
        self,
        incident_id: str,
        *,
        action: RemediationAction,
        precondition: dict[str, object],
    ) -> ActionJournalEntry: ...

    async def cancel(
        self,
        idempotency_key: str,
        *,
        reason: str,
    ) -> ActionJournalEntry: ...

class ActionExecutor(Protocol):
    async def execute(
        self,
        incident_id: str,
        *,
        idempotency_key: str | None,
        action: RemediationAction,
        precondition: dict[str, object],
    ) -> ToolResult: ...
