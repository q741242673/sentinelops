from __future__ import annotations

import hashlib
import json

from sentinelops.agent.execution import ActionJournalEntry
from sentinelops.domain import RemediationAction
from sentinelops.storage.base import IncidentStore, LeaseToken, StoredActionIntent


class DurableActionJournal:
    """Binds every external write to a fenced, durable action intent."""

    def __init__(self, store: IncidentStore, token: LeaseToken) -> None:
        self.store = store
        self.token = token

    async def prepare(
        self,
        incident_id: str,
        *,
        action: RemediationAction,
        precondition: dict[str, object],
    ) -> ActionJournalEntry:
        if incident_id != self.token.incident_id:
            raise RuntimeError("操作意图与 Worker Lease 的事故标识不一致")
        key = _idempotency_key(incident_id, action, precondition)
        stored = await self.store.prepare_action(
            self.token,
            idempotency_key=key,
            action=action,
            precondition=precondition,
        )
        return _entry(stored)

    async def cancel(
        self,
        idempotency_key: str,
        *,
        reason: str,
    ) -> ActionJournalEntry:
        return _entry(
            await self.store.cancel_action(
                self.token,
                idempotency_key=idempotency_key,
                reason=reason,
            )
        )

def _idempotency_key(
    incident_id: str,
    action: RemediationAction,
    precondition: dict[str, object],
) -> str:
    canonical = json.dumps(
        {
            "incident_id": incident_id,
            "action": action.model_dump(mode="json"),
            "precondition": precondition,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _entry(stored: StoredActionIntent) -> ActionJournalEntry:
    return ActionJournalEntry(
        idempotency_key=stored.idempotency_key,
        status=stored.status,
    )
