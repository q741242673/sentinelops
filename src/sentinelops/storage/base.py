from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from sentinelops.domain import IncidentRecord, RemediationAction, ToolResult
from sentinelops.storage.anchor import (
    AuditAnchor,
    AuditAnchorClaim,
    AuditAnchorMetrics,
    AuditAnchorSecurityState,
    AuditAnchorUnlockClaim,
    AuditAnchorUnlockDecision,
    AuditAnchorUnlockRequest,
)
from sentinelops.storage.audit import AuditEvent, AuditVerification


class StoreConflictError(RuntimeError):
    """A stale writer attempted to overwrite a newer incident revision."""


class ApprovalConflictError(RuntimeError):
    """An approval was already consumed, invalidated, or expired."""


class LeaseConflictError(RuntimeError):
    """Another live worker owns the incident lease."""


class ActionIntentConflictError(RuntimeError):
    """An action intent cannot move to the requested durable state."""


class AuditAnchorConflictError(RuntimeError):
    """An audit anchor claim is stale or cannot move to the requested state."""


class AuditAnchorUnlockConflictError(RuntimeError):
    """An audit-anchor unlock request is stale, invalid, or unsafe."""


@dataclass(frozen=True)
class StoredIncident:
    record: IncidentRecord
    version: int
    graph_state: dict[str, object] | None


@dataclass(frozen=True)
class LeaseToken:
    incident_id: str
    owner_id: str
    generation: int
    expires_at: datetime


@dataclass(frozen=True)
class ExecutorClaim:
    idempotency_key: str
    incident_id: str
    owner_id: str
    generation: int
    attempt_id: str
    expires_at: datetime


ActionIntentStatus = Literal[
    "prepared",
    "queued",
    "claimed",
    "dispatched",
    "succeeded",
    "failed",
    "unknown",
    "cancelled",
]

AlertFiringOutcome = Literal["accepted", "deduplicated", "stale"]
AlertResolutionOutcome = Literal["resolved", "duplicate", "stale", "unknown"]


@dataclass(frozen=True)
class StoredActionIntent:
    idempotency_key: str
    incident_id: str
    lease_generation: int
    approval_id: str | None
    approval_version: int | None
    action: RemediationAction
    precondition: dict[str, object]
    status: ActionIntentStatus
    result: ToolResult | None
    error: str | None
    executor_id: str | None
    executor_generation: int
    executor_lease_until: datetime | None
    attempt_id: str | None


@dataclass(frozen=True)
class AlertFiringClaim:
    outcome: AlertFiringOutcome
    fingerprint: str
    incident_id: str | None
    generation: int
    incident: StoredIncident | None


@dataclass(frozen=True)
class AlertResolution:
    outcome: AlertResolutionOutcome
    fingerprint: str
    incident_id: str | None
    generation: int
    incident: StoredIncident | None


class IncidentStore(Protocol):
    async def setup(self) -> None: ...

    async def close(self) -> None: ...

    async def schema_revisions(self) -> tuple[str, ...]: ...

    async def list_audit_events(self, incident_id: str) -> list[AuditEvent]: ...

    async def verify_audit_chain(self, incident_id: str) -> AuditVerification: ...

    async def list_audit_incident_ids(self) -> list[str]: ...

    async def list_audit_anchor_heads(
        self,
        *,
        delivered_only: bool = False,
    ) -> list[AuditAnchor]: ...

    async def audit_anchor_security_state(
        self,
    ) -> AuditAnchorSecurityState | None: ...

    async def audit_anchor_metrics(self) -> AuditAnchorMetrics: ...

    async def audit_anchor_inventory_revision(self) -> int: ...

    async def set_audit_anchor_security_state(
        self,
        *,
        status: str,
        write_blocked: bool,
        reason: str,
        successful: bool,
    ) -> AuditAnchorSecurityState: ...

    async def get_audit_anchor_unlock_request(
        self,
        request_id: str,
    ) -> AuditAnchorUnlockRequest | None: ...

    async def list_audit_anchor_unlock_decisions(
        self,
        request_id: str,
    ) -> list[AuditAnchorUnlockDecision]: ...

    async def request_audit_anchor_unlock(
        self,
        *,
        expected_security_generation: int,
        requester_principal_hash: str,
        requester_issuer: str,
        change_ticket: str,
        justification: str,
        ttl_seconds: float,
        operation_id: str,
        actor_assurance: str,
    ) -> AuditAnchorUnlockRequest: ...

    async def decide_audit_anchor_unlock(
        self,
        *,
        request_id: str,
        expected_request_version: int,
        expected_security_generation: int,
        approver_principal_hash: str,
        approver_issuer: str,
        approved: bool,
        note: str,
        operation_id: str,
        actor_assurance: str,
    ) -> AuditAnchorUnlockRequest: ...

    async def claim_audit_anchor_unlock_reconciliation(
        self,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> AuditAnchorUnlockClaim | None: ...

    async def complete_audit_anchor_unlock_reconciliation(
        self,
        claim: AuditAnchorUnlockClaim,
        *,
        inventory_revision: int,
        local_snapshot_hash: str,
        remote_snapshot_id: str,
        remote_snapshot_root: str,
        challenge: str,
        attested_at: datetime,
    ) -> AuditAnchorUnlockRequest: ...

    async def fail_audit_anchor_unlock_reconciliation(
        self,
        claim: AuditAnchorUnlockClaim,
        *,
        reason: str,
    ) -> AuditAnchorUnlockRequest: ...

    async def claim_audit_anchor(
        self,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> AuditAnchorClaim | None: ...

    async def complete_audit_anchor(
        self,
        claim: AuditAnchorClaim,
        *,
        receipt: dict[str, object],
    ) -> AuditAnchor: ...

    async def retry_audit_anchor(
        self,
        claim: AuditAnchorClaim,
        *,
        error: str,
        retry_after_seconds: float,
    ) -> AuditAnchor: ...

    async def dead_letter_audit_anchor(
        self,
        claim: AuditAnchorClaim,
        *,
        error: str,
    ) -> AuditAnchor: ...

    async def save(
        self,
        record: IncidentRecord,
        *,
        expected_version: int | None,
        graph_state: dict[str, object] | None,
        lease_token: LeaseToken | None = None,
    ) -> StoredIncident: ...

    async def get(self, incident_id: str) -> StoredIncident | None: ...

    async def list(self, *, limit: int = 200) -> list[StoredIncident]: ...

    async def list_recoverable(self) -> list[StoredIncident]: ...

    async def claim_approval(
        self,
        incident_id: str,
        *,
        approval_id: str,
        approval_version: int,
        approved: bool,
        note: str,
        actor_id: str = "unattributed-api-client",
        actor_assurance: str = "unverified",
    ) -> None: ...

    async def approval_status(self, approval_id: str) -> str | None: ...

    async def record_alert_resolved(
        self,
        incident_id: str,
        *,
        fingerprint: str,
    ) -> StoredIncident | None: ...

    async def claim_alert_firing(
        self,
        record: IncidentRecord,
        *,
        source_id: str,
        fingerprint: str,
        starts_at: datetime | None,
    ) -> AlertFiringClaim: ...

    async def resolve_alert(
        self,
        *,
        source_id: str,
        fingerprint: str,
        starts_at: datetime | None,
        resolved_at: datetime | None,
    ) -> AlertResolution: ...

    async def release_alert_bindings(self, incident_ids: set[str]) -> None: ...

    async def active_alert_incident(
        self,
        *,
        source_id: str,
        fingerprint: str,
    ) -> str | None: ...

    async def acquire_lease(
        self,
        incident_id: str,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> LeaseToken: ...

    async def heartbeat_lease(
        self,
        token: LeaseToken,
        *,
        ttl_seconds: float,
    ) -> LeaseToken: ...

    async def release_lease(self, token: LeaseToken) -> None: ...

    async def active_lease(self, incident_id: str) -> LeaseToken | None: ...

    async def prepare_action(
        self,
        token: LeaseToken,
        *,
        idempotency_key: str,
        action: RemediationAction,
        precondition: dict[str, object],
    ) -> StoredActionIntent: ...

    async def claim_action_execution(
        self,
        *,
        owner_id: str,
        attempt_id: str,
        ttl_seconds: float,
    ) -> ExecutorClaim | None: ...

    async def enqueue_action(
        self,
        token: LeaseToken,
        *,
        idempotency_key: str,
    ) -> StoredActionIntent: ...

    async def heartbeat_action_claim(
        self,
        claim: ExecutorClaim,
        *,
        ttl_seconds: float,
    ) -> ExecutorClaim: ...

    async def mark_action_dispatched(
        self,
        claim: ExecutorClaim,
    ) -> StoredActionIntent: ...

    async def complete_action(
        self,
        *,
        claim: ExecutorClaim,
        result: ToolResult,
    ) -> StoredActionIntent: ...

    async def cancel_action(
        self,
        token: LeaseToken,
        *,
        idempotency_key: str,
        reason: str,
    ) -> StoredActionIntent: ...

    async def mark_action_unknown(
        self,
        *,
        claim: ExecutorClaim,
        reason: str,
    ) -> StoredActionIntent: ...

    async def latest_action_intent(
        self,
        incident_id: str,
    ) -> StoredActionIntent | None: ...

    async def mark_abandoned_action_unknown(
        self,
        incident_id: str,
        *,
        reason: str,
    ) -> StoredActionIntent | None: ...
