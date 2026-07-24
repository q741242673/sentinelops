from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

ANCHOR_DOMAIN = b"sentinelops.audit.anchor.v1\0"
AUDIT_ANCHOR_SECURITY_STREAM_ID = "system:audit-anchor-security"


def anchor_id(incident_id: str, sequence: int, head_hash: str) -> str:
    material = f"{incident_id}\0{sequence}\0{head_hash}".encode()
    return hashlib.sha256(ANCHOR_DOMAIN + material).hexdigest()


@dataclass(frozen=True)
class AuditAnchor:
    anchor_id: str
    incident_id: str
    sequence: int
    head_hash: str
    previous_anchor_id: str | None
    audit_key_id: str
    audit_auth_algorithm: str
    audit_auth_tag: str | None
    audit_committed_at: datetime
    status: str
    attempt_count: int
    next_attempt_at: datetime
    last_error_sha256: str | None
    receipt: dict[str, Any] | None


@dataclass(frozen=True)
class AuditAnchorClaim:
    anchor: AuditAnchor
    owner_id: str
    generation: int
    attempt_id: str
    expires_at: datetime


@dataclass(frozen=True)
class AuditAnchorSecurityState:
    status: str
    generation: int
    write_blocked: bool
    reason_sha256: str | None
    last_attempt_at: datetime
    last_success_at: datetime | None
    updated_at: datetime


@dataclass(frozen=True)
class AuditAnchorUnlockRequest:
    request_id: str
    scope_id: str
    blocked_generation: int
    unlock_generation: int | None
    status: str
    version: int
    requester_principal_hash: str
    requester_issuer_hash: str
    change_ticket_sha256: str
    justification_sha256: str
    created_at: datetime
    expires_at: datetime
    approved_at: datetime | None
    lease_owner: str | None
    lease_generation: int
    lease_until: datetime | None
    local_snapshot_hash: str | None
    remote_snapshot_id: str | None
    remote_snapshot_root: str | None
    challenge_sha256: str | None
    attested_at: datetime | None
    completed_at: datetime | None
    terminal_reason_sha256: str | None


@dataclass(frozen=True)
class AuditAnchorUnlockDecision:
    decision_id: str
    request_id: str
    request_version: int
    principal_hash: str
    issuer_hash: str
    role: str
    decision: str
    assurance: str
    note_sha256: str
    decided_at: datetime


@dataclass(frozen=True)
class AuditAnchorUnlockClaim:
    request: AuditAnchorUnlockRequest
    owner_id: str
    generation: int
    expires_at: datetime


@dataclass(frozen=True)
class AuditAnchorMetrics:
    status_counts: dict[str, int]
    oldest_undelivered_age_seconds: float
    last_delivered_at: datetime | None
    security_state: AuditAnchorSecurityState | None
