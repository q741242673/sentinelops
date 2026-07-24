from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    event,
    exists,
    func,
    insert,
    inspect,
    select,
    text,
    update,
)
from sqlalchemy.engine import Connection, Engine, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from sentinelops.domain import IncidentRecord, IncidentStatus, TimelineEvent
from sentinelops.storage.anchor import (
    AUDIT_ANCHOR_SECURITY_STREAM_ID,
    AuditAnchor,
    AuditAnchorClaim,
    AuditAnchorMetrics,
    AuditAnchorSecurityState,
    AuditAnchorUnlockClaim,
    AuditAnchorUnlockDecision,
    AuditAnchorUnlockRequest,
    anchor_id,
)
from sentinelops.storage.audit import (
    CANONICALIZATION,
    SCHEMA_VERSION,
    AuditEvent,
    AuditVerification,
    audit_auth_tag,
    audit_entry_hash,
    canonical_audit_document,
    canonical_payload_hash,
    genesis_hash,
)
from sentinelops.storage.base import (
    ActionIntentConflictError,
    AlertFiringClaim,
    AlertResolution,
    ApprovalConflictError,
    AuditAnchorConflictError,
    AuditAnchorUnlockConflictError,
    ExecutorClaim,
    LeaseConflictError,
    LeaseToken,
    StoreConflictError,
    StoredActionIntent,
    StoredIncident,
)

metadata = MetaData()


def _has_table(connection: Connection, table_name: str) -> bool:
    return inspect(connection).has_table(table_name)


incidents = Table(
    "sentinelops_incidents",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("version", BigInteger, nullable=False),
    Column("status", String(32), nullable=False, index=True),
    Column("execution_profile_id", String(160), nullable=False),
    Column("record", JSON, nullable=False),
    Column("graph_state", JSON, nullable=True),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
)

incident_events = Table(
    "sentinelops_incident_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("sequence", Integer, nullable=False),
    Column("event_type", String(100), nullable=False),
    Column("message", Text, nullable=False),
    Column("data", JSON, nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint("incident_id", "sequence", name="uq_incident_event_sequence"),
)

audit_heads = Table(
    "sentinelops_audit_heads",
    metadata,
    Column("incident_id", String(64), primary_key=True),
    Column("last_sequence", BigInteger, nullable=False),
    Column("last_hash", String(64), nullable=False),
    Column("updated_at", String(40), nullable=False),
)

audit_events = Table(
    "sentinelops_audit_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("sequence", BigInteger, nullable=False),
    Column("operation_id", String(200), nullable=False),
    Column("event_type", String(100), nullable=False),
    Column("source_component", String(32), nullable=False),
    Column("actor_type", String(32), nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("actor_assurance", String(24), nullable=False),
    Column("subject_type", String(32), nullable=False),
    Column("subject_id", String(200), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("occurred_at", String(40), nullable=False),
    Column("committed_at", String(40), nullable=False),
    Column("previous_hash", String(64), nullable=False),
    Column("entry_hash", String(64), nullable=False),
    Column("auth_tag", String(64), nullable=True),
    Column("auth_algorithm", String(24), nullable=False),
    Column("key_id", String(64), nullable=False),
    Column("canonicalization", String(24), nullable=False),
    Column("schema_version", Integer, nullable=False),
    UniqueConstraint("incident_id", "sequence", name="uq_audit_event_sequence"),
    UniqueConstraint("incident_id", "operation_id", name="uq_audit_event_operation"),
)

audit_anchor_outbox = Table(
    "sentinelops_audit_anchor_outbox",
    metadata,
    Column("anchor_id", String(64), primary_key=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("sequence", BigInteger, nullable=False),
    Column("head_hash", String(64), nullable=False),
    Column("previous_anchor_id", String(64), nullable=True),
    Column("audit_key_id", String(64), nullable=False),
    Column("audit_auth_algorithm", String(24), nullable=False),
    Column("audit_auth_tag", String(64), nullable=True),
    Column("audit_committed_at", String(40), nullable=False),
    Column("status", String(24), nullable=False, index=True),
    Column("attempt_count", Integer, nullable=False),
    Column("next_attempt_at", String(40), nullable=False),
    Column("claimed_by", String(200), nullable=True),
    Column("claim_generation", BigInteger, nullable=False),
    Column("attempt_id", String(64), nullable=True, unique=True),
    Column("claim_until", String(40), nullable=True),
    Column("last_error_sha256", String(64), nullable=True),
    Column("receipt", JSON, nullable=True),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    Column("delivered_at", String(40), nullable=True),
    UniqueConstraint(
        "incident_id",
        "sequence",
        name="uq_audit_anchor_incident_sequence",
    ),
)
Index(
    "ix_sentinelops_audit_anchor_outbox_status_created_at",
    audit_anchor_outbox.c.status,
    audit_anchor_outbox.c.created_at,
)

audit_anchor_security_state = Table(
    "sentinelops_audit_anchor_security_state",
    metadata,
    Column("scope_id", String(64), primary_key=True),
    Column("status", String(32), nullable=False),
    Column("generation", BigInteger, nullable=False),
    Column("write_blocked", Integer, nullable=False),
    Column("reason_sha256", String(64), nullable=True),
    Column("last_attempt_at", String(40), nullable=False),
    Column("last_success_at", String(40), nullable=True),
    Column("updated_at", String(40), nullable=False),
)

audit_anchor_inventory_epoch = Table(
    "sentinelops_audit_anchor_inventory_epoch",
    metadata,
    Column("scope_id", String(64), primary_key=True),
    Column("revision", BigInteger, nullable=False),
    Column("updated_at", String(40), nullable=False),
)

audit_anchor_unlock_requests = Table(
    "sentinelops_audit_anchor_unlock_requests",
    metadata,
    Column("request_id", String(64), primary_key=True),
    Column("scope_id", String(64), nullable=False),
    Column("active_scope_id", String(64), nullable=True, unique=True),
    Column("blocked_generation", BigInteger, nullable=False),
    Column("unlock_generation", BigInteger, nullable=True),
    Column("status", String(32), nullable=False),
    Column("version", BigInteger, nullable=False),
    Column("requester_principal_hash", String(64), nullable=False),
    Column("requester_issuer_hash", String(64), nullable=False),
    Column("change_ticket_sha256", String(64), nullable=False),
    Column("justification_sha256", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("approved_at", String(40), nullable=True),
    Column("lease_owner", String(200), nullable=True),
    Column("lease_generation", BigInteger, nullable=False),
    Column("lease_until", String(40), nullable=True),
    Column("local_snapshot_hash", String(64), nullable=True),
    Column("remote_snapshot_id", String(64), nullable=True),
    Column("remote_snapshot_root", String(64), nullable=True),
    Column("challenge_sha256", String(64), nullable=True),
    Column("attested_at", String(40), nullable=True),
    Column("completed_at", String(40), nullable=True),
    Column("terminal_reason_sha256", String(64), nullable=True),
)
Index(
    "ix_sentinelops_anchor_unlock_scope_status_expires",
    audit_anchor_unlock_requests.c.scope_id,
    audit_anchor_unlock_requests.c.status,
    audit_anchor_unlock_requests.c.expires_at,
)

audit_anchor_unlock_decisions = Table(
    "sentinelops_audit_anchor_unlock_decisions",
    metadata,
    Column("decision_id", String(200), primary_key=True),
    Column("request_id", String(64), nullable=False, index=True),
    Column("request_version", BigInteger, nullable=False),
    Column("principal_hash", String(64), nullable=False),
    Column("issuer_hash", String(64), nullable=False),
    Column("role", String(24), nullable=False),
    Column("decision", String(24), nullable=False),
    Column("assurance", String(24), nullable=False),
    Column("note_sha256", String(64), nullable=False),
    Column("decided_at", String(40), nullable=False),
    UniqueConstraint(
        "request_id",
        "principal_hash",
        name="uq_anchor_unlock_request_principal",
    ),
)

approvals = Table(
    "sentinelops_approvals",
    metadata,
    Column("approval_id", String(64), primary_key=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("version", Integer, nullable=False),
    Column("status", String(24), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("decided_at", String(40), nullable=True),
    Column("decision_note", Text, nullable=False, default=""),
    UniqueConstraint("incident_id", "version", name="uq_incident_approval_version"),
)

worker_leases = Table(
    "sentinelops_worker_leases",
    metadata,
    Column("incident_id", String(64), primary_key=True),
    Column("owner_id", String(200), nullable=False),
    Column("generation", BigInteger, nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
)

action_intents = Table(
    "sentinelops_action_intents",
    metadata,
    Column("idempotency_key", String(64), primary_key=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("lease_generation", BigInteger, nullable=False),
    Column("approval_id", String(64), nullable=True),
    Column("approval_version", Integer, nullable=True),
    Column("action", JSON, nullable=False),
    Column("precondition", JSON, nullable=False),
    Column("status", String(24), nullable=False, index=True),
    Column("executor_id", String(200), nullable=True),
    Column("executor_generation", BigInteger, nullable=False, default=0),
    Column("executor_lease_until", String(40), nullable=True),
    Column("attempt_id", String(64), nullable=True, unique=True),
    Column("result", JSON, nullable=True),
    Column("error", Text, nullable=True),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    Column("queued_at", String(40), nullable=True),
    Column("claimed_at", String(40), nullable=True),
    Column("dispatched_at", String(40), nullable=True),
    Column("finished_at", String(40), nullable=True),
)

alert_bindings = Table(
    "sentinelops_alert_bindings",
    metadata,
    Column("source_id", String(128), primary_key=True),
    Column("fingerprint", String(128), primary_key=True),
    Column("incident_id", String(64), nullable=True, unique=True),
    Column("status", String(16), nullable=False, index=True),
    Column("generation", BigInteger, nullable=False),
    Column("version", BigInteger, nullable=False),
    Column("starts_at", String(40), nullable=True),
    Column("resolved_at", String(40), nullable=True),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
)


@event.listens_for(Engine, "connect")
def _configure_sqlite(connection: Any, _record: Any) -> None:
    if connection.__class__.__module__.startswith("aiosqlite"):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


class SqlIncidentStore:
    """Durable incident snapshots with portable optimistic concurrency control."""

    def __init__(
        self,
        database_url: str,
        *,
        audit_hmac_key: str | None = None,
        audit_key_id: str = "development-unkeyed",
        operation_timeout_seconds: float = 15,
    ) -> None:
        if operation_timeout_seconds <= 0:
            raise ValueError("database operation timeout must be positive")
        engine_options: dict[str, Any] = {"pool_pre_ping": True}
        url = make_url(database_url)
        if (
            url.get_backend_name() == "postgresql"
            and url.get_driver_name() == "asyncpg"
        ):
            timeout_ms = max(1, int(operation_timeout_seconds * 1000))
            engine_options.update(
                {
                    "pool_timeout": operation_timeout_seconds,
                    "connect_args": {
                        "command_timeout": operation_timeout_seconds,
                        "server_settings": {
                            "statement_timeout": str(timeout_ms),
                            "lock_timeout": str(timeout_ms),
                        },
                    },
                }
            )
        self.engine = create_async_engine(database_url, **engine_options)
        self.audit_hmac_key = audit_hmac_key.encode() if audit_hmac_key else None
        self.audit_key_id = audit_key_id
        self.audit_auth_algorithm = (
            "hmac-sha256" if self.audit_hmac_key is not None else "none"
        )

    async def setup(self) -> None:
        async with self.engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
            existing_epoch = (
                await connection.execute(
                    select(audit_anchor_inventory_epoch.c.revision).where(
                        audit_anchor_inventory_epoch.c.scope_id
                        == "external-audit-anchor"
                    )
                )
            ).scalar_one_or_none()
            if existing_epoch is None:
                await connection.execute(
                    insert(audit_anchor_inventory_epoch).values(
                        scope_id="external-audit-anchor",
                        revision=1,
                        updated_at=datetime.now(UTC).isoformat(),
                    )
                )

    async def close(self) -> None:
        await self.engine.dispose()

    async def schema_revisions(self) -> tuple[str, ...]:
        async with self.engine.connect() as connection:
            has_version_table = await connection.run_sync(
                lambda sync_connection: _has_table(
                    sync_connection,
                    "alembic_version",
                )
            )
            if not has_version_table:
                return ()
            revisions = (
                await connection.execute(
                    text("SELECT version_num FROM alembic_version")
                )
            ).scalars()
            return tuple(sorted(revisions))

    async def list_audit_events(self, incident_id: str) -> list[AuditEvent]:
        async with self.engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(audit_events)
                    .where(audit_events.c.incident_id == incident_id)
                    .order_by(audit_events.c.sequence.asc())
                )
            ).mappings()
            return [self._stored_audit_event(row) for row in rows]

    async def list_audit_incident_ids(self) -> list[str]:
        async with self.engine.connect() as connection:
            values = (
                await connection.execute(
                    select(audit_heads.c.incident_id).order_by(
                        audit_heads.c.incident_id.asc()
                    )
                )
            ).scalars()
            return [str(value) for value in values]

    async def verify_audit_chain(self, incident_id: str) -> AuditVerification:
        async with self.engine.connect() as connection:
            head = (
                await connection.execute(
                    select(audit_heads).where(
                        audit_heads.c.incident_id == incident_id
                    )
                )
            ).mappings().one_or_none()
            rows = list(
                (
                    await connection.execute(
                        select(audit_events)
                        .where(audit_events.c.incident_id == incident_id)
                        .order_by(audit_events.c.sequence.asc())
                    )
                ).mappings()
            )

        errors: list[str] = []
        first_invalid: int | None = None
        previous_hash = genesis_hash(incident_id)
        for expected_sequence, row in enumerate(rows, start=1):
            sequence = int(row["sequence"])

            def invalidate(
                message: str,
                invalid_sequence: int = sequence,
            ) -> None:
                nonlocal first_invalid
                errors.append(message)
                if first_invalid is None:
                    first_invalid = invalid_sequence

            if sequence != expected_sequence:
                invalidate(
                    f"sequence 不连续：期望 {expected_sequence}，实际 {sequence}"
                )
            if row["previous_hash"] != previous_hash:
                invalidate(f"sequence {sequence} 的 previous_hash 不匹配")
            if row["canonicalization"] != CANONICALIZATION:
                invalidate(f"sequence {sequence} 使用未知 canonicalization")
            if int(row["schema_version"]) != SCHEMA_VERSION:
                invalidate(f"sequence {sequence} 使用未知 schema_version")

            try:
                document = canonical_audit_document(
                    incident_id=row["incident_id"],
                    sequence=sequence,
                    operation_id=row["operation_id"],
                    event_type=row["event_type"],
                    source_component=row["source_component"],
                    actor_type=row["actor_type"],
                    actor_id=row["actor_id"],
                    actor_assurance=row["actor_assurance"],
                    subject_type=row["subject_type"],
                    subject_id=row["subject_id"],
                    payload=row["payload"],
                    occurred_at=row["occurred_at"],
                    committed_at=row["committed_at"],
                    previous_hash=row["previous_hash"],
                    auth_algorithm=row["auth_algorithm"],
                    key_id=row["key_id"],
                )
                expected_hash = audit_entry_hash(document)
            except (TypeError, ValueError) as exc:
                invalidate(f"sequence {sequence} 无法规范化：{exc}")
                expected_hash = ""
            if not hmac.compare_digest(row["entry_hash"], expected_hash):
                invalidate(f"sequence {sequence} 的 entry_hash 不匹配")

            if row["auth_algorithm"] == "hmac-sha256":
                if (
                    self.audit_hmac_key is None
                    or row["key_id"] != self.audit_key_id
                ):
                    invalidate(f"sequence {sequence} 缺少对应的审计验证密钥")
                else:
                    expected_tag = audit_auth_tag(
                        row["entry_hash"],
                        hmac_key=self.audit_hmac_key,
                    )
                    if not hmac.compare_digest(
                        row["auth_tag"] or "",
                        expected_tag or "",
                    ):
                        invalidate(f"sequence {sequence} 的 HMAC 不匹配")
            elif row["auth_algorithm"] == "none":
                if row["auth_tag"] is not None:
                    invalidate(f"sequence {sequence} 的无密钥事件带有异常 HMAC")
            else:
                invalidate(f"sequence {sequence} 使用未知认证算法")
            previous_hash = row["entry_hash"]

        if head is None:
            errors.append("审计 head 不存在")
        else:
            if int(head["last_sequence"]) != len(rows):
                errors.append("审计 head 的事件数量不匹配")
            if head["last_hash"] != previous_hash:
                errors.append("审计 head hash 与事件尾部不匹配")

        return AuditVerification(
            incident_id=incident_id,
            valid=not errors,
            event_count=len(rows),
            head_sequence=int(head["last_sequence"]) if head is not None else 0,
            head_hash=head["last_hash"] if head is not None else None,
            auth_algorithm=(rows[-1]["auth_algorithm"] if rows else None),
            key_id=(rows[-1]["key_id"] if rows else None),
            first_invalid_sequence=first_invalid,
            errors=tuple(errors),
        )

    async def list_audit_anchor_heads(
        self,
        *,
        delivered_only: bool = False,
    ) -> list[AuditAnchor]:
        candidates = select(
            audit_anchor_outbox.c.incident_id,
            func.max(audit_anchor_outbox.c.sequence).label("latest_sequence"),
        )
        if delivered_only:
            candidates = candidates.where(
                audit_anchor_outbox.c.status == "delivered"
            )
        latest = candidates.group_by(
            audit_anchor_outbox.c.incident_id
        ).subquery()
        async with self.engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(audit_anchor_outbox)
                    .join(
                        latest,
                        (
                            audit_anchor_outbox.c.incident_id
                            == latest.c.incident_id
                        )
                        & (
                            audit_anchor_outbox.c.sequence
                            == latest.c.latest_sequence
                        ),
                    )
                    .order_by(audit_anchor_outbox.c.incident_id.asc())
                )
            ).mappings()
            return [self._stored_anchor(row) for row in rows]

    async def audit_anchor_security_state(
        self,
    ) -> AuditAnchorSecurityState | None:
        async with self.engine.connect() as connection:
            row = (
                await connection.execute(
                    select(audit_anchor_security_state).where(
                        audit_anchor_security_state.c.scope_id
                        == "external-audit-anchor"
                    )
                )
            ).mappings().one_or_none()
        return self._stored_anchor_security_state(row) if row else None

    async def audit_anchor_metrics(self) -> AuditAnchorMetrics:
        async with self.engine.connect() as connection:
            now = await self._database_now(connection)
            counts = {
                str(status): int(count)
                for status, count in (
                    await connection.execute(
                        select(
                            audit_anchor_outbox.c.status,
                            func.count(),
                        ).group_by(audit_anchor_outbox.c.status)
                    )
                ).all()
            }
            oldest = (
                await connection.execute(
                    select(func.min(audit_anchor_outbox.c.created_at)).where(
                        audit_anchor_outbox.c.status.in_(
                            ("pending", "claimed")
                        )
                    )
                )
            ).scalar_one_or_none()
            last_delivered = (
                await connection.execute(
                    select(func.max(audit_anchor_outbox.c.delivered_at))
                )
            ).scalar_one_or_none()
            state_row = (
                await connection.execute(
                    select(audit_anchor_security_state).where(
                        audit_anchor_security_state.c.scope_id
                        == "external-audit-anchor"
                    )
                )
            ).mappings().one_or_none()
        oldest_age = 0.0
        if oldest:
            oldest_at = datetime.fromisoformat(str(oldest))
            if oldest_at.tzinfo is None:
                oldest_at = oldest_at.replace(tzinfo=UTC)
            oldest_age = max(
                0.0,
                (now - oldest_at.astimezone(UTC)).total_seconds(),
            )
        return AuditAnchorMetrics(
            status_counts=counts,
            oldest_undelivered_age_seconds=oldest_age,
            last_delivered_at=(
                datetime.fromisoformat(str(last_delivered))
                if last_delivered
                else None
            ),
            security_state=(
                self._stored_anchor_security_state(state_row)
                if state_row
                else None
            ),
        )

    async def audit_anchor_inventory_revision(self) -> int:
        async with self.engine.connect() as connection:
            revision = (
                await connection.execute(
                    select(audit_anchor_inventory_epoch.c.revision).where(
                        audit_anchor_inventory_epoch.c.scope_id
                        == "external-audit-anchor"
                    )
                )
            ).scalar_one_or_none()
        if revision is None:
            raise AuditAnchorConflictError(
                "审计清单代次不存在，拒绝执行严格对账"
            )
        return int(revision)

    async def set_audit_anchor_security_state(
        self,
        *,
        status: str,
        write_blocked: bool,
        reason: str,
        successful: bool,
    ) -> AuditAnchorSecurityState:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            row = (
                await connection.execute(
                    select(audit_anchor_security_state)
                    .where(
                        audit_anchor_security_state.c.scope_id
                        == "external-audit-anchor"
                    )
                    .with_for_update()
                )
            ).mappings().one_or_none()
            if row is not None and row["status"] in {
                "integrity_blocked",
                "unlock_pending",
            }:
                return self._stored_anchor_security_state(row)
            generation = int(row["generation"]) + 1 if row else 1
            values = {
                "status": status,
                "generation": generation,
                "write_blocked": 1 if write_blocked else 0,
                "reason_sha256": canonical_payload_hash(reason),
                "last_attempt_at": now.isoformat(),
                "last_success_at": (
                    now.isoformat()
                    if successful
                    else (row["last_success_at"] if row else None)
                ),
                "updated_at": now.isoformat(),
            }
            if row is None:
                await connection.execute(
                    insert(audit_anchor_security_state).values(
                        scope_id="external-audit-anchor",
                        **values,
                    )
                )
            else:
                changed = await connection.execute(
                    update(audit_anchor_security_state)
                    .where(
                        audit_anchor_security_state.c.scope_id
                        == "external-audit-anchor",
                        audit_anchor_security_state.c.generation
                        == row["generation"],
                    )
                    .values(**values)
                )
                if changed.rowcount != 1:
                    raise AuditAnchorConflictError(
                        "外部审计锚定安全状态已被并发更新"
                    )
        state = await self.audit_anchor_security_state()
        assert state is not None
        return state

    async def get_audit_anchor_unlock_request(
        self,
        request_id: str,
    ) -> AuditAnchorUnlockRequest | None:
        async with self.engine.connect() as connection:
            row = (
                await connection.execute(
                    select(audit_anchor_unlock_requests).where(
                        audit_anchor_unlock_requests.c.request_id == request_id
                    )
                )
            ).mappings().one_or_none()
        return self._stored_anchor_unlock_request(row) if row else None

    async def list_audit_anchor_unlock_decisions(
        self,
        request_id: str,
    ) -> list[AuditAnchorUnlockDecision]:
        async with self.engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(audit_anchor_unlock_decisions)
                    .where(
                        audit_anchor_unlock_decisions.c.request_id == request_id
                    )
                    .order_by(
                        audit_anchor_unlock_decisions.c.decided_at.asc(),
                        audit_anchor_unlock_decisions.c.decision_id.asc(),
                    )
                )
            ).mappings()
            return [self._stored_anchor_unlock_decision(row) for row in rows]

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
    ) -> AuditAnchorUnlockRequest:
        self._assert_unlock_actor(
            principal_hash=requester_principal_hash,
            issuer=requester_issuer,
            operation_id=operation_id,
            actor_assurance=actor_assurance,
        )
        if not 60 <= ttl_seconds <= 86_400:
            raise AuditAnchorUnlockConflictError(
                "解锁申请有效期必须在 60 秒到 24 小时之间"
            )
        if not change_ticket.strip() or not justification.strip():
            raise AuditAnchorUnlockConflictError(
                "解锁申请必须提供变更单号和原因"
            )
        if self.audit_hmac_key is None:
            raise AuditAnchorUnlockConflictError(
                "未配置审计 HMAC 密钥，禁止创建解锁申请"
            )

        try:
            async with self.engine.begin() as connection:
                replay = (
                    await connection.execute(
                        select(audit_anchor_unlock_decisions).where(
                            audit_anchor_unlock_decisions.c.decision_id
                            == operation_id
                        )
                    )
                ).mappings().one_or_none()
                if replay is not None:
                    request_row = (
                        await connection.execute(
                            select(audit_anchor_unlock_requests).where(
                                audit_anchor_unlock_requests.c.request_id
                                == replay["request_id"]
                            )
                        )
                    ).mappings().one()
                    original_ttl = (
                        datetime.fromisoformat(request_row["expires_at"])
                        - datetime.fromisoformat(request_row["created_at"])
                    ).total_seconds()
                    if (
                        replay["role"] != "requester"
                        or replay["decision"] != "requested"
                        or replay["principal_hash"]
                        != requester_principal_hash
                        or replay["issuer_hash"]
                        != canonical_payload_hash(requester_issuer)
                        or int(request_row["blocked_generation"])
                        != expected_security_generation
                        or request_row["change_ticket_sha256"]
                        != canonical_payload_hash(change_ticket)
                        or request_row["justification_sha256"]
                        != canonical_payload_hash(justification)
                        or original_ttl != ttl_seconds
                    ):
                        raise AuditAnchorUnlockConflictError(
                            "幂等键已绑定到不同的解锁操作"
                        )
                    return self._stored_anchor_unlock_request(request_row)

                now = await self._database_now(connection)
                security = (
                    await connection.execute(
                        select(audit_anchor_security_state)
                        .where(
                            audit_anchor_security_state.c.scope_id
                            == "external-audit-anchor"
                        )
                        .with_for_update()
                    )
                ).mappings().one_or_none()
                if (
                    security is None
                    or security["status"] != "integrity_blocked"
                    or not bool(security["write_blocked"])
                    or int(security["generation"])
                    != expected_security_generation
                ):
                    raise AuditAnchorUnlockConflictError(
                        "安全状态不是匹配代次的 integrity_blocked，拒绝申请"
                    )

                active = (
                    await connection.execute(
                        select(audit_anchor_unlock_requests)
                        .where(
                            audit_anchor_unlock_requests.c.active_scope_id
                            == "external-audit-anchor"
                        )
                        .with_for_update()
                    )
                ).mappings().one_or_none()
                if active is not None:
                    if datetime.fromisoformat(active["expires_at"]) > now:
                        raise AuditAnchorUnlockConflictError(
                            "当前安全代次已有未完成的解锁申请"
                        )
                    expired_version = int(active["version"]) + 1
                    await connection.execute(
                        update(audit_anchor_unlock_requests)
                        .where(
                            audit_anchor_unlock_requests.c.request_id
                            == active["request_id"],
                            audit_anchor_unlock_requests.c.version
                            == active["version"],
                        )
                        .values(
                            active_scope_id=None,
                            status="expired",
                            version=expired_version,
                            terminal_reason_sha256=canonical_payload_hash(
                                "request_expired"
                            ),
                        )
                    )
                    await self._append_audit_event(
                        connection,
                        incident_id=AUDIT_ANCHOR_SECURITY_STREAM_ID,
                        operation_id=(
                            f"unlock-expired:{active['request_id']}:"
                            f"{expired_version}"
                        ),
                        event_type="audit_anchor.unlock_expired",
                        source_component="storage",
                        actor_type="system",
                        actor_id="audit-anchor-security-gate",
                        actor_assurance="internal",
                        subject_type="unlock_request",
                        subject_id=active["request_id"],
                        payload={
                            "request_id": active["request_id"],
                            "request_version": expired_version,
                            "blocked_generation": int(
                                active["blocked_generation"]
                            ),
                        },
                        allow_chain_create=True,
                    )

                request_id = str(uuid4())
                expires_at = now + timedelta(seconds=ttl_seconds)
                issuer_hash = canonical_payload_hash(requester_issuer)
                values = {
                    "request_id": request_id,
                    "scope_id": "external-audit-anchor",
                    "active_scope_id": "external-audit-anchor",
                    "blocked_generation": expected_security_generation,
                    "unlock_generation": None,
                    "status": "awaiting_second_approval",
                    "version": 1,
                    "requester_principal_hash": requester_principal_hash,
                    "requester_issuer_hash": issuer_hash,
                    "change_ticket_sha256": canonical_payload_hash(
                        change_ticket
                    ),
                    "justification_sha256": canonical_payload_hash(
                        justification
                    ),
                    "created_at": now.isoformat(),
                    "expires_at": expires_at.isoformat(),
                    "approved_at": None,
                    "lease_owner": None,
                    "lease_generation": 0,
                    "lease_until": None,
                    "local_snapshot_hash": None,
                    "remote_snapshot_id": None,
                    "remote_snapshot_root": None,
                    "challenge_sha256": None,
                    "attested_at": None,
                    "completed_at": None,
                    "terminal_reason_sha256": None,
                }
                await connection.execute(
                    insert(audit_anchor_unlock_requests).values(**values)
                )
                await connection.execute(
                    insert(audit_anchor_unlock_decisions).values(
                        decision_id=operation_id,
                        request_id=request_id,
                        request_version=1,
                        principal_hash=requester_principal_hash,
                        issuer_hash=issuer_hash,
                        role="requester",
                        decision="requested",
                        assurance=actor_assurance,
                        note_sha256=canonical_payload_hash(""),
                        decided_at=now.isoformat(),
                    )
                )
                await self._append_audit_event(
                    connection,
                    incident_id=AUDIT_ANCHOR_SECURITY_STREAM_ID,
                    operation_id=operation_id,
                    event_type="audit_anchor.unlock_requested",
                    source_component="api",
                    actor_type="human",
                    actor_id=requester_principal_hash,
                    actor_assurance=actor_assurance,
                    subject_type="unlock_request",
                    subject_id=request_id,
                    payload={
                        "request_id": request_id,
                        "request_version": 1,
                        "blocked_generation": expected_security_generation,
                        "requester_principal_hash": requester_principal_hash,
                        "requester_issuer_hash": issuer_hash,
                        "change_ticket_sha256": values[
                            "change_ticket_sha256"
                        ],
                        "justification_sha256": values[
                            "justification_sha256"
                        ],
                        "expires_at": expires_at.isoformat(),
                    },
                    allow_chain_create=True,
                )
                return self._stored_anchor_unlock_request(values)
        except IntegrityError as exc:
            raise AuditAnchorUnlockConflictError(
                "已有并发解锁申请或重复决策"
            ) from exc

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
    ) -> AuditAnchorUnlockRequest:
        self._assert_unlock_actor(
            principal_hash=approver_principal_hash,
            issuer=approver_issuer,
            operation_id=operation_id,
            actor_assurance=actor_assurance,
        )
        if self.audit_hmac_key is None:
            raise AuditAnchorUnlockConflictError(
                "未配置审计 HMAC 密钥，禁止审批解锁"
            )

        expired = False
        result: AuditAnchorUnlockRequest | None = None
        try:
            async with self.engine.begin() as connection:
                replay = (
                    await connection.execute(
                        select(audit_anchor_unlock_decisions).where(
                            audit_anchor_unlock_decisions.c.decision_id
                            == operation_id
                        )
                    )
                ).mappings().one_or_none()
                if replay is not None:
                    expected_decision = "approved" if approved else "rejected"
                    request_row = (
                        await connection.execute(
                            select(audit_anchor_unlock_requests).where(
                                audit_anchor_unlock_requests.c.request_id
                                == request_id
                            )
                        )
                    ).mappings().one()
                    if (
                        replay["request_id"] != request_id
                        or replay["principal_hash"]
                        != approver_principal_hash
                        or replay["issuer_hash"]
                        != canonical_payload_hash(approver_issuer)
                        or replay["decision"] != expected_decision
                        or int(replay["request_version"])
                        != expected_request_version
                        or int(request_row["blocked_generation"])
                        != expected_security_generation
                        or replay["note_sha256"]
                        != canonical_payload_hash(note)
                    ):
                        raise AuditAnchorUnlockConflictError(
                            "幂等键已绑定到不同的解锁决策"
                        )
                    return self._stored_anchor_unlock_request(request_row)

                now = await self._database_now(connection)
                security = (
                    await connection.execute(
                        select(audit_anchor_security_state)
                        .where(
                            audit_anchor_security_state.c.scope_id
                            == "external-audit-anchor"
                        )
                        .with_for_update()
                    )
                ).mappings().one_or_none()
                request_row = (
                    await connection.execute(
                        select(audit_anchor_unlock_requests)
                        .where(
                            audit_anchor_unlock_requests.c.request_id
                            == request_id
                        )
                        .with_for_update()
                    )
                ).mappings().one_or_none()
                if request_row is None:
                    raise AuditAnchorUnlockConflictError("解锁申请不存在")
                if (
                    security is None
                    or security["status"] != "integrity_blocked"
                    or not bool(security["write_blocked"])
                    or int(security["generation"])
                    != expected_security_generation
                    or int(request_row["blocked_generation"])
                    != expected_security_generation
                ):
                    raise AuditAnchorUnlockConflictError(
                        "安全状态代次已变化，旧解锁申请失效"
                    )
                if (
                    request_row["status"] != "awaiting_second_approval"
                    or int(request_row["version"]) != expected_request_version
                ):
                    raise AuditAnchorUnlockConflictError(
                        "解锁申请状态或版本已变化"
                    )
                if (
                    request_row["requester_principal_hash"]
                    == approver_principal_hash
                ):
                    raise AuditAnchorUnlockConflictError(
                        "申请人与批准人必须是两个不同的人类身份"
                    )

                issuer_hash = canonical_payload_hash(approver_issuer)
                if datetime.fromisoformat(request_row["expires_at"]) <= now:
                    new_version = int(request_row["version"]) + 1
                    await connection.execute(
                        update(audit_anchor_unlock_requests)
                        .where(
                            audit_anchor_unlock_requests.c.request_id
                            == request_id,
                            audit_anchor_unlock_requests.c.version
                            == request_row["version"],
                        )
                        .values(
                            active_scope_id=None,
                            status="expired",
                            version=new_version,
                            terminal_reason_sha256=canonical_payload_hash(
                                "request_expired"
                            ),
                        )
                    )
                    await self._append_audit_event(
                        connection,
                        incident_id=AUDIT_ANCHOR_SECURITY_STREAM_ID,
                        operation_id=operation_id,
                        event_type="audit_anchor.unlock_expired",
                        source_component="api",
                        actor_type="human",
                        actor_id=approver_principal_hash,
                        actor_assurance=actor_assurance,
                        subject_type="unlock_request",
                        subject_id=request_id,
                        payload={
                            "request_id": request_id,
                            "request_version": new_version,
                            "blocked_generation": expected_security_generation,
                        },
                        allow_chain_create=True,
                    )
                    result = self._stored_anchor_unlock_request(
                        {
                            **request_row,
                            "active_scope_id": None,
                            "status": "expired",
                            "version": new_version,
                            "terminal_reason_sha256": canonical_payload_hash(
                                "request_expired"
                            ),
                        }
                    )
                    expired = True
                else:
                    decision = "approved" if approved else "rejected"
                    new_version = int(request_row["version"]) + 1
                    unlock_generation = (
                        expected_security_generation + 1
                        if approved
                        else None
                    )
                    changed = await connection.execute(
                        update(audit_anchor_unlock_requests)
                        .where(
                            audit_anchor_unlock_requests.c.request_id
                            == request_id,
                            audit_anchor_unlock_requests.c.version
                            == request_row["version"],
                        )
                        .values(
                            active_scope_id=(
                                "external-audit-anchor" if approved else None
                            ),
                            status=(
                                "approved"
                                if approved
                                else "rejected"
                            ),
                            version=new_version,
                            unlock_generation=unlock_generation,
                            approved_at=(
                                now.isoformat() if approved else None
                            ),
                            terminal_reason_sha256=(
                                None
                                if approved
                                else canonical_payload_hash("rejected")
                            ),
                        )
                    )
                    if changed.rowcount != 1:
                        raise AuditAnchorUnlockConflictError(
                            "解锁申请已被并发修改"
                        )
                    await connection.execute(
                        insert(audit_anchor_unlock_decisions).values(
                            decision_id=operation_id,
                            request_id=request_id,
                            request_version=expected_request_version,
                            principal_hash=approver_principal_hash,
                            issuer_hash=issuer_hash,
                            role="approver",
                            decision=decision,
                            assurance=actor_assurance,
                            note_sha256=canonical_payload_hash(note),
                            decided_at=now.isoformat(),
                        )
                    )
                    if approved:
                        state_changed = await connection.execute(
                            update(audit_anchor_security_state)
                            .where(
                                audit_anchor_security_state.c.scope_id
                                == "external-audit-anchor",
                                audit_anchor_security_state.c.status
                                == "integrity_blocked",
                                audit_anchor_security_state.c.generation
                                == expected_security_generation,
                                audit_anchor_security_state.c.write_blocked
                                == 1,
                            )
                            .values(
                                status="unlock_pending",
                                generation=unlock_generation,
                                write_blocked=1,
                                reason_sha256=canonical_payload_hash(
                                    "approved_unlock_requires_strict_reconciliation"
                                ),
                                last_attempt_at=now.isoformat(),
                                updated_at=now.isoformat(),
                            )
                        )
                        if state_changed.rowcount != 1:
                            raise AuditAnchorUnlockConflictError(
                                "安全状态已被并发修改，拒绝批准旧申请"
                            )
                    await self._append_audit_event(
                        connection,
                        incident_id=AUDIT_ANCHOR_SECURITY_STREAM_ID,
                        operation_id=operation_id,
                        event_type=f"audit_anchor.unlock_{decision}",
                        source_component="api",
                        actor_type="human",
                        actor_id=approver_principal_hash,
                        actor_assurance=actor_assurance,
                        subject_type="unlock_request",
                        subject_id=request_id,
                        payload={
                            "request_id": request_id,
                            "request_version": new_version,
                            "blocked_generation": expected_security_generation,
                            "unlock_generation": unlock_generation,
                            "approver_principal_hash": approver_principal_hash,
                            "approver_issuer_hash": issuer_hash,
                            "decision": decision,
                            "note_sha256": canonical_payload_hash(note),
                            "write_blocked": True,
                        },
                        allow_chain_create=True,
                    )
                    result = self._stored_anchor_unlock_request(
                        {
                            **request_row,
                            "active_scope_id": (
                                "external-audit-anchor"
                                if approved
                                else None
                            ),
                            "status": (
                                "approved"
                                if approved
                                else "rejected"
                            ),
                            "version": new_version,
                            "unlock_generation": unlock_generation,
                            "approved_at": (
                                now.isoformat() if approved else None
                            ),
                            "terminal_reason_sha256": (
                                None
                                if approved
                                else canonical_payload_hash("rejected")
                            ),
                        }
                    )
        except IntegrityError as exc:
            raise AuditAnchorUnlockConflictError(
                "该身份已经参与过此申请，或决策幂等键重复"
            ) from exc
        if expired:
            raise AuditAnchorUnlockConflictError("解锁申请已过期")
        assert result is not None
        return result

    async def claim_audit_anchor_unlock_reconciliation(
        self,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> AuditAnchorUnlockClaim | None:
        if not owner_id.strip() or not 10 <= ttl_seconds <= 600:
            raise AuditAnchorUnlockConflictError(
                "解锁对账 Worker 或租约有效期无效"
            )
        if self.audit_hmac_key is None:
            raise AuditAnchorUnlockConflictError(
                "未配置审计 HMAC 密钥，禁止领取解锁对账"
            )
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            security = (
                await connection.execute(
                    select(audit_anchor_security_state)
                    .where(
                        audit_anchor_security_state.c.scope_id
                        == "external-audit-anchor"
                    )
                    .with_for_update()
                )
            ).mappings().one_or_none()
            request_row = (
                await connection.execute(
                    select(audit_anchor_unlock_requests)
                    .where(
                        audit_anchor_unlock_requests.c.active_scope_id
                        == "external-audit-anchor"
                    )
                    .with_for_update()
                )
            ).mappings().one_or_none()
            if (
                security is None
                or security["status"] != "unlock_pending"
                or not bool(security["write_blocked"])
                or request_row is None
                or request_row["status"] not in {"approved", "reconciling"}
                or request_row["unlock_generation"] is None
                or int(request_row["unlock_generation"])
                != int(security["generation"])
            ):
                return None

            if datetime.fromisoformat(request_row["expires_at"]) <= now:
                new_request_version = int(request_row["version"]) + 1
                new_security_generation = int(security["generation"]) + 1
                await self._append_audit_event(
                    connection,
                    incident_id=AUDIT_ANCHOR_SECURITY_STREAM_ID,
                    operation_id=(
                        f"unlock-reconciliation-expired:"
                        f"{request_row['request_id']}:"
                        f"{new_request_version}"
                    ),
                    event_type="audit_anchor.unlock_reconciliation_expired",
                    source_component="reconciler",
                    actor_type="system",
                    actor_id=owner_id,
                    actor_assurance="internal",
                    subject_type="unlock_request",
                    subject_id=request_row["request_id"],
                    payload={
                        "request_id": request_row["request_id"],
                        "request_version": new_request_version,
                        "security_generation": new_security_generation,
                        "write_blocked": True,
                    },
                    allow_chain_create=True,
                )
                await connection.execute(
                    update(audit_anchor_unlock_requests)
                    .where(
                        audit_anchor_unlock_requests.c.request_id
                        == request_row["request_id"],
                        audit_anchor_unlock_requests.c.version
                        == request_row["version"],
                    )
                    .values(
                        active_scope_id=None,
                        status="expired",
                        version=new_request_version,
                        lease_owner=None,
                        lease_until=None,
                        terminal_reason_sha256=canonical_payload_hash(
                            "reconciliation_request_expired"
                        ),
                    )
                )
                await connection.execute(
                    update(audit_anchor_security_state)
                    .where(
                        audit_anchor_security_state.c.scope_id
                        == "external-audit-anchor",
                        audit_anchor_security_state.c.generation
                        == security["generation"],
                    )
                    .values(
                        status="integrity_blocked",
                        generation=new_security_generation,
                        write_blocked=1,
                        reason_sha256=canonical_payload_hash(
                            "unlock_request_expired"
                        ),
                        last_attempt_at=now.isoformat(),
                        updated_at=now.isoformat(),
                    )
                )
                return None

            lease_until = _stored_time(request_row["lease_until"])
            if (
                request_row["status"] == "reconciling"
                and lease_until is not None
                and lease_until > now
            ):
                if request_row["lease_owner"] != owner_id:
                    return None
                return AuditAnchorUnlockClaim(
                    request=self._stored_anchor_unlock_request(request_row),
                    owner_id=owner_id,
                    generation=int(request_row["lease_generation"]),
                    expires_at=lease_until,
                )

            generation = int(request_row["lease_generation"]) + 1
            expires_at = now + timedelta(seconds=ttl_seconds)
            new_version = int(request_row["version"]) + 1
            changed = await connection.execute(
                update(audit_anchor_unlock_requests)
                .where(
                    audit_anchor_unlock_requests.c.request_id
                    == request_row["request_id"],
                    audit_anchor_unlock_requests.c.version
                    == request_row["version"],
                )
                .values(
                    status="reconciling",
                    version=new_version,
                    lease_owner=owner_id,
                    lease_generation=generation,
                    lease_until=expires_at.isoformat(),
                )
            )
            if changed.rowcount != 1:
                raise AuditAnchorUnlockConflictError(
                    "解锁对账申请已被并发领取"
                )
            await self._append_audit_event(
                connection,
                incident_id=AUDIT_ANCHOR_SECURITY_STREAM_ID,
                operation_id=(
                    f"unlock-reconciliation-claimed:"
                    f"{request_row['request_id']}:{generation}"
                ),
                event_type="audit_anchor.unlock_reconciliation_claimed",
                source_component="reconciler",
                actor_type="system",
                actor_id=owner_id,
                actor_assurance="internal",
                subject_type="unlock_request",
                subject_id=request_row["request_id"],
                payload={
                    "request_id": request_row["request_id"],
                    "request_version": new_version,
                    "security_generation": int(security["generation"]),
                    "lease_generation": generation,
                    "lease_until": expires_at.isoformat(),
                    "write_blocked": True,
                },
                allow_chain_create=True,
            )
            claimed_request = self._stored_anchor_unlock_request(
                {
                    **request_row,
                    "status": "reconciling",
                    "version": new_version,
                    "lease_owner": owner_id,
                    "lease_generation": generation,
                    "lease_until": expires_at.isoformat(),
                }
            )
            return AuditAnchorUnlockClaim(
                request=claimed_request,
                owner_id=owner_id,
                generation=generation,
                expires_at=expires_at,
            )

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
    ) -> AuditAnchorUnlockRequest:
        if (
            inventory_revision < 1
            or any(
                len(value) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in value
                )
                for value in (
                    local_snapshot_hash,
                    remote_snapshot_id,
                    remote_snapshot_root,
                )
            )
            or not 32 <= len(challenge) <= 128
        ):
            raise AuditAnchorUnlockConflictError(
                "严格对账证明格式无效"
            )
        normalized_attested_at = _normalized_datetime(attested_at)
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            attestation_age = (now - normalized_attested_at).total_seconds()
            if attestation_age < -10 or attestation_age > 60:
                raise AuditAnchorUnlockConflictError(
                    "严格对账证明已经过期"
                )
            security = (
                await connection.execute(
                    select(audit_anchor_security_state)
                    .where(
                        audit_anchor_security_state.c.scope_id
                        == "external-audit-anchor"
                    )
                    .with_for_update()
                )
            ).mappings().one_or_none()
            request_row = (
                await connection.execute(
                    select(audit_anchor_unlock_requests)
                    .where(
                        audit_anchor_unlock_requests.c.request_id
                        == claim.request.request_id
                    )
                    .with_for_update()
                )
            ).mappings().one_or_none()
            if (
                security is None
                or security["status"] != "unlock_pending"
                or not bool(security["write_blocked"])
                or request_row is None
                or request_row["status"] != "reconciling"
                or int(request_row["version"]) != claim.request.version
                or int(request_row["lease_generation"]) != claim.generation
                or request_row["lease_owner"] != claim.owner_id
                or _stored_time(request_row["lease_until"]) is None
                or _stored_time(request_row["lease_until"]) <= now
                or datetime.fromisoformat(request_row["expires_at"]) <= now
                or request_row["unlock_generation"] is None
                or int(request_row["unlock_generation"])
                != int(security["generation"])
            ):
                raise AuditAnchorUnlockConflictError(
                    "解锁对账租约或安全代次已失效"
                )
            current_revision = (
                await connection.execute(
                    select(audit_anchor_inventory_epoch.c.revision).where(
                        audit_anchor_inventory_epoch.c.scope_id
                        == "external-audit-anchor"
                    )
                )
            ).scalar_one_or_none()
            if (
                current_revision is None
                or int(current_revision) != inventory_revision
            ):
                raise AuditAnchorUnlockConflictError(
                    "严格对账后本地审计清单已经变化"
                )

            completed_version = int(request_row["version"]) + 1
            healthy_generation = int(security["generation"]) + 1
            challenge_sha256 = canonical_payload_hash(challenge)
            operation_id = (
                f"unlock-reconciliation-completed:"
                f"{request_row['request_id']}:{claim.generation}"
            )
            await self._append_audit_event(
                connection,
                incident_id=AUDIT_ANCHOR_SECURITY_STREAM_ID,
                operation_id=operation_id,
                event_type="audit_anchor.unlock_reconciliation_completed",
                source_component="reconciler",
                actor_type="system",
                actor_id=claim.owner_id,
                actor_assurance="internal",
                subject_type="unlock_request",
                subject_id=request_row["request_id"],
                payload={
                    "request_id": request_row["request_id"],
                    "request_version": completed_version,
                    "unlock_generation": int(security["generation"]),
                    "healthy_generation": healthy_generation,
                    "inventory_revision": inventory_revision,
                    "local_snapshot_hash": local_snapshot_hash,
                    "remote_snapshot_id": remote_snapshot_id,
                    "remote_snapshot_root": remote_snapshot_root,
                    "challenge_sha256": challenge_sha256,
                    "attested_at": normalized_attested_at.isoformat(),
                    "write_blocked": False,
                },
                allow_chain_create=True,
            )
            revision_after_own_event = (
                await connection.execute(
                    select(audit_anchor_inventory_epoch.c.revision).where(
                        audit_anchor_inventory_epoch.c.scope_id
                        == "external-audit-anchor"
                    )
                )
            ).scalar_one()
            if int(revision_after_own_event) != inventory_revision + 1:
                raise AuditAnchorUnlockConflictError(
                    "最终 CAS 前审计清单发生并发变化"
                )
            changed_request = await connection.execute(
                update(audit_anchor_unlock_requests)
                .where(
                    audit_anchor_unlock_requests.c.request_id
                    == request_row["request_id"],
                    audit_anchor_unlock_requests.c.version
                    == request_row["version"],
                    audit_anchor_unlock_requests.c.lease_generation
                    == claim.generation,
                )
                .values(
                    active_scope_id=None,
                    status="completed",
                    version=completed_version,
                    lease_owner=None,
                    lease_until=None,
                    local_snapshot_hash=local_snapshot_hash,
                    remote_snapshot_id=remote_snapshot_id,
                    remote_snapshot_root=remote_snapshot_root,
                    challenge_sha256=challenge_sha256,
                    attested_at=normalized_attested_at.isoformat(),
                    completed_at=now.isoformat(),
                    terminal_reason_sha256=None,
                )
            )
            changed_security = await connection.execute(
                update(audit_anchor_security_state)
                .where(
                    audit_anchor_security_state.c.scope_id
                    == "external-audit-anchor",
                    audit_anchor_security_state.c.status
                    == "unlock_pending",
                    audit_anchor_security_state.c.generation
                    == security["generation"],
                    audit_anchor_security_state.c.write_blocked == 1,
                )
                .values(
                    status="healthy",
                    generation=healthy_generation,
                    write_blocked=0,
                    reason_sha256=canonical_payload_hash(
                        "strict_unlock_reconciliation_completed"
                    ),
                    last_attempt_at=now.isoformat(),
                    last_success_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if changed_request.rowcount != 1 or changed_security.rowcount != 1:
                raise AuditAnchorUnlockConflictError(
                    "最终解锁 CAS 失败"
                )
            return self._stored_anchor_unlock_request(
                {
                    **request_row,
                    "active_scope_id": None,
                    "status": "completed",
                    "version": completed_version,
                    "lease_owner": None,
                    "lease_until": None,
                    "local_snapshot_hash": local_snapshot_hash,
                    "remote_snapshot_id": remote_snapshot_id,
                    "remote_snapshot_root": remote_snapshot_root,
                    "challenge_sha256": challenge_sha256,
                    "attested_at": normalized_attested_at.isoformat(),
                    "completed_at": now.isoformat(),
                    "terminal_reason_sha256": None,
                }
            )

    async def fail_audit_anchor_unlock_reconciliation(
        self,
        claim: AuditAnchorUnlockClaim,
        *,
        reason: str,
    ) -> AuditAnchorUnlockRequest:
        if not reason.strip():
            raise AuditAnchorUnlockConflictError("解锁对账失败原因不能为空")
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            security = (
                await connection.execute(
                    select(audit_anchor_security_state)
                    .where(
                        audit_anchor_security_state.c.scope_id
                        == "external-audit-anchor"
                    )
                    .with_for_update()
                )
            ).mappings().one_or_none()
            request_row = (
                await connection.execute(
                    select(audit_anchor_unlock_requests)
                    .where(
                        audit_anchor_unlock_requests.c.request_id
                        == claim.request.request_id
                    )
                    .with_for_update()
                )
            ).mappings().one_or_none()
            if (
                security is None
                or security["status"] != "unlock_pending"
                or request_row is None
                or request_row["status"] != "reconciling"
                or int(request_row["version"]) != claim.request.version
                or int(request_row["lease_generation"]) != claim.generation
                or request_row["lease_owner"] != claim.owner_id
                or _stored_time(request_row["lease_until"]) is None
                or _stored_time(request_row["lease_until"]) <= now
            ):
                raise AuditAnchorUnlockConflictError(
                    "解锁对账租约已经失效"
                )
            failed_version = int(request_row["version"]) + 1
            blocked_generation = int(security["generation"]) + 1
            reason_sha256 = canonical_payload_hash(reason)
            await self._append_audit_event(
                connection,
                incident_id=AUDIT_ANCHOR_SECURITY_STREAM_ID,
                operation_id=(
                    f"unlock-reconciliation-failed:"
                    f"{request_row['request_id']}:{claim.generation}"
                ),
                event_type="audit_anchor.unlock_reconciliation_failed",
                source_component="reconciler",
                actor_type="system",
                actor_id=claim.owner_id,
                actor_assurance="internal",
                subject_type="unlock_request",
                subject_id=request_row["request_id"],
                payload={
                    "request_id": request_row["request_id"],
                    "request_version": failed_version,
                    "security_generation": blocked_generation,
                    "reason_sha256": reason_sha256,
                    "write_blocked": True,
                },
                allow_chain_create=True,
            )
            await connection.execute(
                update(audit_anchor_unlock_requests)
                .where(
                    audit_anchor_unlock_requests.c.request_id
                    == request_row["request_id"],
                    audit_anchor_unlock_requests.c.version
                    == request_row["version"],
                )
                .values(
                    active_scope_id=None,
                    status="failed",
                    version=failed_version,
                    lease_owner=None,
                    lease_until=None,
                    terminal_reason_sha256=reason_sha256,
                )
            )
            await connection.execute(
                update(audit_anchor_security_state)
                .where(
                    audit_anchor_security_state.c.scope_id
                    == "external-audit-anchor",
                    audit_anchor_security_state.c.generation
                    == security["generation"],
                )
                .values(
                    status="integrity_blocked",
                    generation=blocked_generation,
                    write_blocked=1,
                    reason_sha256=reason_sha256,
                    last_attempt_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            return self._stored_anchor_unlock_request(
                {
                    **request_row,
                    "active_scope_id": None,
                    "status": "failed",
                    "version": failed_version,
                    "lease_owner": None,
                    "lease_until": None,
                    "terminal_reason_sha256": reason_sha256,
                }
            )

    async def claim_audit_anchor(
        self,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> AuditAnchorClaim | None:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            expired = await connection.execute(
                update(audit_anchor_outbox)
                .where(
                    audit_anchor_outbox.c.status == "claimed",
                    audit_anchor_outbox.c.claim_until <= now.isoformat(),
                )
                .values(
                    status="pending",
                    claimed_by=None,
                    attempt_id=None,
                    claim_until=None,
                    updated_at=now.isoformat(),
                )
            )
            if expired.rowcount:
                await self._bump_anchor_inventory_epoch(
                    connection,
                    now=now,
                )
            earlier = audit_anchor_outbox.alias("earlier_anchor")
            row = (
                await connection.execute(
                    select(audit_anchor_outbox)
                    .where(
                        audit_anchor_outbox.c.status == "pending",
                        audit_anchor_outbox.c.next_attempt_at <= now.isoformat(),
                        ~exists(
                            select(1).where(
                                earlier.c.incident_id
                                == audit_anchor_outbox.c.incident_id,
                                earlier.c.sequence
                                < audit_anchor_outbox.c.sequence,
                                earlier.c.status != "delivered",
                            )
                        ),
                    )
                    .order_by(
                        audit_anchor_outbox.c.next_attempt_at.asc(),
                        audit_anchor_outbox.c.created_at.asc(),
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
            ).mappings().one_or_none()
            if row is None:
                return None
            generation = int(row["claim_generation"]) + 1
            attempt_id = str(uuid4())
            expires_at = now + timedelta(seconds=ttl_seconds)
            claimed = await connection.execute(
                update(audit_anchor_outbox)
                .where(
                    audit_anchor_outbox.c.anchor_id == row["anchor_id"],
                    audit_anchor_outbox.c.status == "pending",
                )
                .values(
                    status="claimed",
                    attempt_count=int(row["attempt_count"]) + 1,
                    claimed_by=owner_id,
                    claim_generation=generation,
                    attempt_id=attempt_id,
                    claim_until=expires_at.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if claimed.rowcount != 1:
                raise AuditAnchorConflictError("审计锚点已被其他 Publisher 领取")
            await self._bump_anchor_inventory_epoch(
                connection,
                now=now,
            )
            anchor = self._stored_anchor(
                {
                    **row,
                    "status": "claimed",
                    "attempt_count": int(row["attempt_count"]) + 1,
                    "claimed_by": owner_id,
                    "claim_generation": generation,
                    "attempt_id": attempt_id,
                    "claim_until": expires_at.isoformat(),
                }
            )
            return AuditAnchorClaim(
                anchor=anchor,
                owner_id=owner_id,
                generation=generation,
                attempt_id=attempt_id,
                expires_at=expires_at,
            )

    async def complete_audit_anchor(
        self,
        claim: AuditAnchorClaim,
        *,
        receipt: dict[str, object],
    ) -> AuditAnchor:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            completed = await connection.execute(
                update(audit_anchor_outbox)
                .where(
                    audit_anchor_outbox.c.anchor_id == claim.anchor.anchor_id,
                    audit_anchor_outbox.c.status == "claimed",
                    audit_anchor_outbox.c.claimed_by == claim.owner_id,
                    audit_anchor_outbox.c.claim_generation == claim.generation,
                    audit_anchor_outbox.c.attempt_id == claim.attempt_id,
                    audit_anchor_outbox.c.claim_until > now.isoformat(),
                )
                .values(
                    status="delivered",
                    receipt=receipt,
                    delivered_at=now.isoformat(),
                    claimed_by=None,
                    attempt_id=None,
                    claim_until=None,
                    last_error_sha256=None,
                    updated_at=now.isoformat(),
                )
            )
            if completed.rowcount != 1:
                raise AuditAnchorConflictError("审计锚点领取已失效，拒绝确认送达")
            await self._bump_anchor_inventory_epoch(
                connection,
                now=now,
            )
        return await self._require_anchor(claim.anchor.anchor_id)

    async def retry_audit_anchor(
        self,
        claim: AuditAnchorClaim,
        *,
        error: str,
        retry_after_seconds: float,
    ) -> AuditAnchor:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            next_attempt_at = now + timedelta(
                seconds=max(0.1, retry_after_seconds)
            )
            retried = await connection.execute(
                update(audit_anchor_outbox)
                .where(
                    audit_anchor_outbox.c.anchor_id == claim.anchor.anchor_id,
                    audit_anchor_outbox.c.status == "claimed",
                    audit_anchor_outbox.c.claimed_by == claim.owner_id,
                    audit_anchor_outbox.c.claim_generation == claim.generation,
                    audit_anchor_outbox.c.attempt_id == claim.attempt_id,
                    audit_anchor_outbox.c.claim_until > now.isoformat(),
                )
                .values(
                    status="pending",
                    next_attempt_at=next_attempt_at.isoformat(),
                    claimed_by=None,
                    attempt_id=None,
                    claim_until=None,
                    last_error_sha256=canonical_payload_hash(error),
                    updated_at=now.isoformat(),
                )
            )
            if retried.rowcount != 1:
                raise AuditAnchorConflictError("审计锚点领取已失效，拒绝覆盖重试状态")
            await self._bump_anchor_inventory_epoch(
                connection,
                now=now,
            )
        return await self._require_anchor(claim.anchor.anchor_id)

    async def dead_letter_audit_anchor(
        self,
        claim: AuditAnchorClaim,
        *,
        error: str,
    ) -> AuditAnchor:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            dead_lettered = await connection.execute(
                update(audit_anchor_outbox)
                .where(
                    audit_anchor_outbox.c.anchor_id == claim.anchor.anchor_id,
                    audit_anchor_outbox.c.status == "claimed",
                    audit_anchor_outbox.c.claimed_by == claim.owner_id,
                    audit_anchor_outbox.c.claim_generation == claim.generation,
                    audit_anchor_outbox.c.attempt_id == claim.attempt_id,
                    audit_anchor_outbox.c.claim_until > now.isoformat(),
                )
                .values(
                    status="dead_letter",
                    claimed_by=None,
                    attempt_id=None,
                    claim_until=None,
                    last_error_sha256=canonical_payload_hash(error),
                    updated_at=now.isoformat(),
                )
            )
            if dead_lettered.rowcount != 1:
                raise AuditAnchorConflictError(
                    "审计锚点领取已失效，拒绝写入 dead-letter"
                )
            await self._bump_anchor_inventory_epoch(
                connection,
                now=now,
            )
        return await self._require_anchor(claim.anchor.anchor_id)

    async def save(
        self,
        record: IncidentRecord,
        *,
        expected_version: int | None,
        graph_state: dict[str, object] | None,
        lease_token: LeaseToken | None = None,
    ) -> StoredIncident:
        now = datetime.now(UTC).isoformat()
        payload = record.model_dump(mode="json")
        payload["updated_at"] = now
        new_version = 1 if expected_version is None else expected_version + 1
        values = {
            "id": record.id,
            "version": new_version,
            "status": record.status.value,
            "execution_profile_id": record.execution_profile_id,
            "record": payload,
            "graph_state": graph_state,
            "created_at": record.created_at.isoformat(),
            "updated_at": now,
        }
        try:
            async with self.engine.begin() as connection:
                if lease_token is not None:
                    lease_now = await self._database_now(connection)
                    await self._fence_active_lease(
                        connection,
                        lease_token,
                        now=lease_now,
                    )
                if expected_version is None:
                    await connection.execute(insert(incidents).values(**values))
                else:
                    result = await connection.execute(
                        update(incidents)
                        .where(
                            incidents.c.id == record.id,
                            incidents.c.version == expected_version,
                        )
                        .values(**{key: value for key, value in values.items() if key != "id"})
                    )
                    if result.rowcount != 1:
                        raise StoreConflictError(
                            f"incident {record.id} changed after version {expected_version}"
                        )
                await self._append_audit_event(
                    connection,
                    incident_id=record.id,
                    operation_id=f"incident:{record.id}:snapshot:{new_version}",
                    event_type=(
                        "incident.created"
                        if expected_version is None
                        else "incident.snapshot_committed"
                    ),
                    source_component="api",
                    actor_type="system",
                    actor_id="incident-store",
                    actor_assurance="internal",
                    subject_type="incident",
                    subject_id=record.id,
                    payload={
                        "version": new_version,
                        "status": record.status.value,
                        "record_sha256": canonical_payload_hash(payload),
                        "graph_state_sha256": canonical_payload_hash(graph_state),
                    },
                    allow_chain_create=expected_version is None,
                )
                await self._append_events(connection, record)
                await self._sync_approval(connection, record)
        except IntegrityError as exc:
            raise StoreConflictError(f"incident {record.id} already exists") from exc
        stored_record = record.model_copy(deep=True)
        stored_record.updated_at = datetime.fromisoformat(now)
        return StoredIncident(
            record=stored_record,
            version=new_version,
            graph_state=graph_state,
        )

    async def get(self, incident_id: str) -> StoredIncident | None:
        async with self.engine.connect() as connection:
            row = (
                await connection.execute(
                    select(
                        incidents.c.record,
                        incidents.c.version,
                        incidents.c.graph_state,
                    ).where(incidents.c.id == incident_id)
                )
            ).mappings().one_or_none()
        return self._stored(row) if row else None

    async def list(self, *, limit: int = 200) -> list[StoredIncident]:
        async with self.engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(
                        incidents.c.record,
                        incidents.c.version,
                        incidents.c.graph_state,
                    )
                    .order_by(incidents.c.created_at.desc())
                    .limit(limit)
                )
            ).mappings()
            return [self._stored(row) for row in rows]

    async def list_recoverable(self) -> list[StoredIncident]:
        async with self.engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(
                        incidents.c.record,
                        incidents.c.version,
                        incidents.c.graph_state,
                    )
                    .where(
                        incidents.c.status.in_(
                            [
                                "received",
                                "investigating",
                                "awaiting_approval",
                                "remediating",
                                "escalated",
                            ]
                        )
                    )
                    .order_by(incidents.c.created_at.asc())
                )
            ).mappings()
            return [self._stored(row) for row in rows]

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
    ) -> None:
        async with self.engine.begin() as connection:
            now = (await self._database_now(connection)).isoformat()
            result = await connection.execute(
                update(approvals)
                .where(
                    approvals.c.approval_id == approval_id,
                    approvals.c.incident_id == incident_id,
                    approvals.c.version == approval_version,
                    approvals.c.status == "pending",
                    approvals.c.expires_at > now,
                )
                .values(
                    status="approved" if approved else "rejected",
                    decided_at=now,
                    decision_note=note,
                )
            )
            if result.rowcount != 1:
                raise ApprovalConflictError("审批已处理、已失效或已经过期")
            await self._append_audit_event(
                connection,
                incident_id=incident_id,
                operation_id=(
                    f"approval:{approval_id}:{approval_version}:decision"
                ),
                event_type=(
                    "approval.approved" if approved else "approval.rejected"
                ),
                source_component="api",
                actor_type="operator",
                actor_id=actor_id,
                actor_assurance=actor_assurance,
                subject_type="approval",
                subject_id=approval_id,
                payload={
                    "approval_version": approval_version,
                    "approved": approved,
                    "note_sha256": canonical_payload_hash(note),
                },
                occurred_at=now,
            )

    async def approval_status(self, approval_id: str) -> str | None:
        async with self.engine.begin() as connection:
            now = (await self._database_now(connection)).isoformat()
            approval = (
                await connection.execute(
                    select(approvals)
                    .where(approvals.c.approval_id == approval_id)
                    .with_for_update()
                )
            ).mappings().one_or_none()
            if (
                approval is not None
                and approval["status"] == "pending"
                and approval["expires_at"] <= now
            ):
                expired = await connection.execute(
                    update(approvals)
                    .where(
                        approvals.c.approval_id == approval_id,
                        approvals.c.status == "pending",
                    )
                    .values(
                        status="expired",
                        decided_at=now,
                        decision_note="审批窗口已到期，系统自动失效",
                    )
                )
                if expired.rowcount == 1:
                    await self._append_audit_event(
                        connection,
                        incident_id=approval["incident_id"],
                        operation_id=(
                            f"approval:{approval_id}:"
                            f"{approval['version']}:expired"
                        ),
                        event_type="approval.expired",
                        source_component="api",
                        actor_type="system",
                        actor_id="approval-expiry",
                        actor_assurance="internal",
                        subject_type="approval",
                        subject_id=approval_id,
                        payload={"approval_version": int(approval["version"])},
                        occurred_at=now,
                    )
                    return "expired"
            return (
                await connection.execute(
                    select(approvals.c.status).where(
                        approvals.c.approval_id == approval_id
                    )
                )
            ).scalar_one_or_none()

    async def record_alert_resolved(
        self,
        incident_id: str,
        *,
        fingerprint: str,
    ) -> StoredIncident | None:
        """Serialize Alertmanager resolution against action dispatch."""

        async with self.engine.begin() as connection:
            return await self._record_alert_resolved_tx(
                connection,
                incident_id,
                fingerprint=fingerprint,
            )

    async def claim_alert_firing(
        self,
        record: IncidentRecord,
        *,
        source_id: str,
        fingerprint: str,
        starts_at: datetime | None,
    ) -> AlertFiringClaim:
        """Atomically bind one alert occurrence to exactly one incident."""

        normalized_start = _normalized_time(starts_at)
        for _ in range(3):
            try:
                async with self.engine.begin() as connection:
                    binding = (
                        await connection.execute(
                            select(alert_bindings)
                            .where(
                                alert_bindings.c.source_id == source_id,
                                alert_bindings.c.fingerprint == fingerprint,
                            )
                            .with_for_update()
                        )
                    ).mappings().one_or_none()
                    now = await self._database_now(connection)
                    if binding is None:
                        await connection.execute(
                            insert(alert_bindings).values(
                                source_id=source_id,
                                fingerprint=fingerprint,
                                incident_id=record.id,
                                status="active",
                                generation=1,
                                version=1,
                                starts_at=normalized_start,
                                resolved_at=None,
                                created_at=now.isoformat(),
                                updated_at=now.isoformat(),
                            )
                        )
                        stored = await self._insert_incident_tx(
                            connection,
                            record,
                            now=now,
                        )
                        return AlertFiringClaim(
                            outcome="accepted",
                            fingerprint=fingerprint,
                            incident_id=record.id,
                            generation=1,
                            incident=stored,
                        )

                    generation = int(binding["generation"])
                    if binding["status"] == "active":
                        stored = await self._require_incident_tx(
                            connection,
                            binding["incident_id"],
                        )
                        return AlertFiringClaim(
                            outcome="deduplicated",
                            fingerprint=fingerprint,
                            incident_id=binding["incident_id"],
                            generation=generation,
                            incident=stored,
                        )

                    existing_start = _stored_time(binding["starts_at"])
                    resolved_watermark = _stored_time(binding["resolved_at"])
                    reopen_after = max(
                        (
                            item
                            for item in (existing_start, resolved_watermark)
                            if item is not None
                        ),
                        default=None,
                    )
                    if starts_at is None or (
                        reopen_after is not None
                        and _normalized_datetime(starts_at) <= reopen_after
                    ):
                        stored = await self._optional_incident_tx(
                            connection,
                            binding["incident_id"],
                        )
                        return AlertFiringClaim(
                            outcome="stale",
                            fingerprint=fingerprint,
                            incident_id=binding["incident_id"],
                            generation=generation,
                            incident=stored,
                        )

                    result = await connection.execute(
                        update(alert_bindings)
                        .where(
                            alert_bindings.c.source_id == source_id,
                            alert_bindings.c.fingerprint == fingerprint,
                            alert_bindings.c.status == "resolved",
                            alert_bindings.c.version == binding["version"],
                        )
                        .values(
                            incident_id=record.id,
                            status="active",
                            generation=generation + 1,
                            version=int(binding["version"]) + 1,
                            starts_at=normalized_start,
                            resolved_at=None,
                            updated_at=now.isoformat(),
                        )
                    )
                    if result.rowcount != 1:
                        continue
                    stored = await self._insert_incident_tx(
                        connection,
                        record,
                        now=now,
                    )
                    return AlertFiringClaim(
                        outcome="accepted",
                        fingerprint=fingerprint,
                        incident_id=record.id,
                        generation=generation + 1,
                        incident=stored,
                    )
            except IntegrityError:
                # PostgreSQL aborts the failed transaction. Retry in a fresh one
                # and read the winner selected by the unique primary key.
                continue
        raise StoreConflictError(
            f"alert {source_id}/{fingerprint} could not be claimed safely"
        )

    async def resolve_alert(
        self,
        *,
        source_id: str,
        fingerprint: str,
        starts_at: datetime | None,
        resolved_at: datetime | None,
    ) -> AlertResolution:
        """Resolve an alert occurrence by its durable fingerprint binding."""

        normalized_start = _normalized_time(starts_at)
        for _ in range(3):
            try:
                async with self.engine.begin() as connection:
                    binding = (
                        await connection.execute(
                            select(alert_bindings)
                            .where(
                                alert_bindings.c.source_id == source_id,
                                alert_bindings.c.fingerprint == fingerprint,
                            )
                            .with_for_update()
                        )
                    ).mappings().one_or_none()
                    now = await self._database_now(connection)
                    resolution_time = _normalized_time(resolved_at) or now.isoformat()
                    if binding is None:
                        await connection.execute(
                            insert(alert_bindings).values(
                                source_id=source_id,
                                fingerprint=fingerprint,
                                incident_id=None,
                                status="resolved",
                                generation=1,
                                version=1,
                                starts_at=normalized_start,
                                resolved_at=resolution_time,
                                created_at=now.isoformat(),
                                updated_at=now.isoformat(),
                            )
                        )
                        return AlertResolution(
                            outcome="unknown",
                            fingerprint=fingerprint,
                            incident_id=None,
                            generation=1,
                            incident=None,
                        )

                    generation = int(binding["generation"])
                    existing_start = _stored_time(binding["starts_at"])
                    incoming_start = (
                        _normalized_datetime(starts_at)
                        if starts_at is not None
                        else None
                    )
                    if binding["status"] == "resolved":
                        resolved_watermark = _stored_time(binding["resolved_at"])
                        advance_after = max(
                            (
                                item
                                for item in (existing_start, resolved_watermark)
                                if item is not None
                            ),
                            default=None,
                        )
                        if incoming_start is not None and (
                            advance_after is None or incoming_start > advance_after
                        ):
                            result = await connection.execute(
                                update(alert_bindings)
                                .where(
                                    alert_bindings.c.source_id == source_id,
                                    alert_bindings.c.fingerprint == fingerprint,
                                    alert_bindings.c.status == "resolved",
                                    alert_bindings.c.version == binding["version"],
                                )
                                .values(
                                    incident_id=None,
                                    generation=generation + 1,
                                    version=int(binding["version"]) + 1,
                                    starts_at=normalized_start,
                                    resolved_at=resolution_time,
                                    updated_at=now.isoformat(),
                                )
                            )
                            if result.rowcount != 1:
                                continue
                            return AlertResolution(
                                outcome="unknown",
                                fingerprint=fingerprint,
                                incident_id=None,
                                generation=generation + 1,
                                incident=None,
                            )
                        stored = await self._optional_incident_tx(
                            connection,
                            binding["incident_id"],
                        )
                        return AlertResolution(
                            outcome="duplicate",
                            fingerprint=fingerprint,
                            incident_id=binding["incident_id"],
                            generation=generation,
                            incident=stored,
                        )

                    if incoming_start != existing_start and (
                        incoming_start is not None or existing_start is not None
                    ):
                        stored = await self._require_incident_tx(
                            connection,
                            binding["incident_id"],
                        )
                        return AlertResolution(
                            outcome="stale",
                            fingerprint=fingerprint,
                            incident_id=binding["incident_id"],
                            generation=generation,
                            incident=stored,
                        )

                    result = await connection.execute(
                        update(alert_bindings)
                        .where(
                            alert_bindings.c.source_id == source_id,
                            alert_bindings.c.fingerprint == fingerprint,
                            alert_bindings.c.status == "active",
                            alert_bindings.c.version == binding["version"],
                        )
                        .values(
                            status="resolved",
                            version=int(binding["version"]) + 1,
                            resolved_at=resolution_time,
                            updated_at=now.isoformat(),
                        )
                    )
                    if result.rowcount != 1:
                        continue
                    stored = await self._record_alert_resolved_tx(
                        connection,
                        binding["incident_id"],
                        fingerprint=fingerprint,
                    )
                    if stored is None:
                        raise StoreConflictError(
                            "Alertmanager fingerprint points to a missing incident"
                        )
                    return AlertResolution(
                        outcome="resolved",
                        fingerprint=fingerprint,
                        incident_id=binding["incident_id"],
                        generation=generation,
                        incident=stored,
                    )
            except IntegrityError:
                continue
        raise StoreConflictError(
            f"alert {source_id}/{fingerprint} could not be resolved safely"
        )

    async def release_alert_bindings(self, incident_ids: set[str]) -> None:
        if not incident_ids:
            return
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            await connection.execute(
                update(alert_bindings)
                .where(
                    alert_bindings.c.incident_id.in_(incident_ids),
                    alert_bindings.c.status == "active",
                )
                .values(
                    status="resolved",
                    version=alert_bindings.c.version + 1,
                    resolved_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )

    async def active_alert_incident(
        self,
        *,
        source_id: str,
        fingerprint: str,
    ) -> str | None:
        async with self.engine.connect() as connection:
            return (
                await connection.execute(
                    select(alert_bindings.c.incident_id).where(
                        alert_bindings.c.source_id == source_id,
                        alert_bindings.c.fingerprint == fingerprint,
                        alert_bindings.c.status == "active",
                    )
                )
            ).scalar_one_or_none()

    async def _record_alert_resolved_tx(
        self,
        connection: Any,
        incident_id: str,
        *,
        fingerprint: str,
    ) -> StoredIncident | None:
        row = (
            await connection.execute(
                select(incidents)
                .where(incidents.c.id == incident_id)
                .with_for_update()
            )
        ).mappings().one_or_none()
        if row is None:
            return None
        record = IncidentRecord.model_validate(row["record"])
        existing_resolution = next(
            (
                item
                for item in reversed(record.timeline)
                if item.type == "alertmanager.resolved"
                and item.data.get("fingerprint") == fingerprint
            ),
            None,
        )
        if existing_resolution is not None:
            return StoredIncident(
                record=record,
                version=int(row["version"]),
                graph_state=row["graph_state"],
            )

        intent_row = (
            await connection.execute(
                select(action_intents)
                .where(action_intents.c.incident_id == incident_id)
                .order_by(action_intents.c.created_at.desc())
                .limit(1)
            )
        ).mappings().one_or_none()
        intent = self._stored_action(intent_row) if intent_row else None
        intent_status = intent.status if intent is not None else None
        no_write_dispatched = intent_status in {
            None,
            "prepared",
            "queued",
            "claimed",
            "cancelled",
        }
        if intent_status in {"prepared", "queued", "claimed"}:
            now = await self._database_now(connection)
            await connection.execute(
                update(action_intents)
                .where(
                    action_intents.c.idempotency_key == intent.idempotency_key,
                    action_intents.c.status.in_(["prepared", "queued", "claimed"]),
                )
                .values(
                    status="cancelled",
                    error="Alertmanager resolved before dispatch",
                    finished_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            intent_status = "cancelled"

        if intent is not None and intent.result is not None:
            if intent.result not in record.execution_results:
                record.execution_results.append(intent.result)

        if no_write_dispatched and not record.execution_results:
            record.status = IncidentStatus.RESOLVED
            record.approval = None
            record.active_step_id = None
            for step in record.execution_trace:
                if step.status == "running":
                    step.status = "skipped"
                    step.completed_at = datetime.now(UTC)
                    step.detail = "上游告警已恢复，尚未派发集群写操作"
            message = "Alertmanager 已确认告警恢复，旧操作已撤销且未执行集群写入"
            execution_outcome = "not_dispatched"
        else:
            if record.status not in {
                IncidentStatus.FAILED,
                IncidentStatus.REJECTED,
                IncidentStatus.RESOLVED,
            }:
                record.status = IncidentStatus.ESCALATED
            record.approval = None
            message = (
                "Alertmanager 已发送 resolved，但集群写操作已经派发；"
                "最终状态仍由持久化执行结果和恢复验证决定"
            )
            execution_outcome = (
                "known"
                if intent_status in {"succeeded", "failed"}
                else "unknown"
            )
        record.timeline.append(
            TimelineEvent(
                type="alertmanager.resolved",
                message=message,
                data={
                    "fingerprint": fingerprint,
                    "execution_outcome": execution_outcome,
                    **(
                        {"action_intent_status": intent_status}
                        if intent_status is not None
                        else {}
                    ),
                },
            )
        )
        now = await self._database_now(connection)
        record.updated_at = now
        new_version = int(row["version"]) + 1
        payload = record.model_dump(mode="json")
        result = await connection.execute(
            update(incidents)
            .where(
                incidents.c.id == incident_id,
                incidents.c.version == row["version"],
            )
            .values(
                version=new_version,
                status=record.status.value,
                record=payload,
                graph_state=None,
                updated_at=now.isoformat(),
            )
        )
        if result.rowcount != 1:
            raise StoreConflictError(
                f"incident {incident_id} changed while resolving alert"
            )
        await self._append_events(connection, record)
        await self._sync_approval(connection, record)
        return StoredIncident(
            record=record,
            version=new_version,
            graph_state=None,
        )

    async def acquire_lease(
        self,
        incident_id: str,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> LeaseToken:
        try:
            async with self.engine.begin() as connection:
                now = await self._database_now(connection)
                expires_at = now + timedelta(seconds=ttl_seconds)
                row = (
                    await connection.execute(
                        select(worker_leases).where(
                            worker_leases.c.incident_id == incident_id
                        )
                    )
                ).mappings().one_or_none()
                if row is None:
                    generation = 1
                    await connection.execute(
                        insert(worker_leases).values(
                            incident_id=incident_id,
                            owner_id=owner_id,
                            generation=generation,
                            expires_at=expires_at.isoformat(),
                            updated_at=now.isoformat(),
                        )
                    )
                else:
                    current_expiry = datetime.fromisoformat(row["expires_at"])
                    if current_expiry > now:
                        raise LeaseConflictError(
                            f"incident {incident_id} is leased by another worker"
                        )
                    previous_generation = int(row["generation"])
                    generation = previous_generation + 1
                    result = await connection.execute(
                        update(worker_leases)
                        .where(
                            worker_leases.c.incident_id == incident_id,
                            worker_leases.c.generation == previous_generation,
                            worker_leases.c.owner_id == row["owner_id"],
                            worker_leases.c.expires_at == row["expires_at"],
                        )
                        .values(
                            owner_id=owner_id,
                            generation=generation,
                            expires_at=expires_at.isoformat(),
                            updated_at=now.isoformat(),
                        )
                    )
                    if result.rowcount != 1:
                        raise LeaseConflictError(
                            f"incident {incident_id} lease changed concurrently"
                        )
        except IntegrityError as exc:
            raise LeaseConflictError(
                f"incident {incident_id} lease changed concurrently"
            ) from exc
        return LeaseToken(
            incident_id=incident_id,
            owner_id=owner_id,
            generation=generation,
            expires_at=expires_at,
        )

    async def heartbeat_lease(
        self,
        token: LeaseToken,
        *,
        ttl_seconds: float,
    ) -> LeaseToken:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            expires_at = now + timedelta(seconds=ttl_seconds)
            result = await connection.execute(
                update(worker_leases)
                .where(
                    worker_leases.c.incident_id == token.incident_id,
                    worker_leases.c.owner_id == token.owner_id,
                    worker_leases.c.generation == token.generation,
                    worker_leases.c.expires_at > now.isoformat(),
                )
                .values(
                    expires_at=expires_at.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if result.rowcount != 1:
                raise LeaseConflictError(
                    f"incident {token.incident_id} lease expired or was fenced"
                )
        return LeaseToken(
            incident_id=token.incident_id,
            owner_id=token.owner_id,
            generation=token.generation,
            expires_at=expires_at,
        )

    async def release_lease(self, token: LeaseToken) -> None:
        async with self.engine.begin() as connection:
            now = (await self._database_now(connection)).isoformat()
            await connection.execute(
                update(worker_leases)
                .where(
                    worker_leases.c.incident_id == token.incident_id,
                    worker_leases.c.owner_id == token.owner_id,
                    worker_leases.c.generation == token.generation,
                )
                .values(expires_at=now, updated_at=now)
            )

    async def active_lease(self, incident_id: str) -> LeaseToken | None:
        async with self.engine.connect() as connection:
            now = await self._database_now(connection)
            row = (
                await connection.execute(
                    select(worker_leases).where(
                        worker_leases.c.incident_id == incident_id,
                        worker_leases.c.expires_at > now.isoformat(),
                    )
                )
            ).mappings().one_or_none()
        if row is None:
            return None
        return LeaseToken(
            incident_id=incident_id,
            owner_id=row["owner_id"],
            generation=int(row["generation"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
        )

    async def prepare_action(
        self,
        token: LeaseToken,
        *,
        idempotency_key: str,
        action: Any,
        precondition: dict[str, object],
    ) -> StoredActionIntent:
        action_payload = action.model_dump(mode="json")
        try:
            async with self.engine.begin() as connection:
                now = await self._database_now(connection)
                await self._assert_active_lease(connection, token, now=now)
                await self._assert_dispatch_allowed(connection, token.incident_id)
                approval_row = (
                    await connection.execute(
                        select(
                            approvals.c.approval_id,
                            approvals.c.version,
                            approvals.c.status,
                        )
                        .where(approvals.c.incident_id == token.incident_id)
                        .order_by(approvals.c.version.desc())
                        .limit(1)
                    )
                ).mappings().one_or_none()
                existing = (
                    await connection.execute(
                        select(action_intents).where(
                            action_intents.c.idempotency_key == idempotency_key
                        )
                    )
                ).mappings().one_or_none()
                if existing is not None:
                    stored = self._stored_action(existing)
                    if (
                        stored.incident_id != token.incident_id
                        or stored.action.model_dump(mode="json") != action_payload
                        or stored.precondition != precondition
                    ):
                        raise ActionIntentConflictError(
                            "幂等键已绑定到不同的集群操作"
                        )
                    if (
                        stored.status == "prepared"
                        and stored.lease_generation != token.generation
                    ):
                        reassigned = await connection.execute(
                            update(action_intents)
                            .where(
                                action_intents.c.idempotency_key == idempotency_key,
                                action_intents.c.status == "prepared",
                                action_intents.c.lease_generation
                                == stored.lease_generation,
                            )
                            .values(
                                lease_generation=token.generation,
                                updated_at=now.isoformat(),
                            )
                        )
                        if reassigned.rowcount != 1:
                            raise ActionIntentConflictError(
                                "操作意图已被其他 Worker 接管"
                            )
                        await self._append_audit_event(
                            connection,
                            incident_id=token.incident_id,
                            operation_id=(
                                f"action:{idempotency_key}:prepared:"
                                f"lease-{token.generation}"
                            ),
                            event_type="action.prepared_reassigned",
                            source_component="api",
                            actor_type="worker",
                            actor_id=token.owner_id,
                            actor_assurance="internal",
                            subject_type="action_intent",
                            subject_id=idempotency_key,
                            payload={
                                "lease_generation": token.generation,
                                "previous_lease_generation": stored.lease_generation,
                            },
                        )
                        return StoredActionIntent(
                            idempotency_key=stored.idempotency_key,
                            incident_id=stored.incident_id,
                            lease_generation=token.generation,
                            approval_id=stored.approval_id,
                            approval_version=stored.approval_version,
                            action=stored.action,
                            precondition=stored.precondition,
                            status=stored.status,
                            result=stored.result,
                            error=stored.error,
                            executor_id=stored.executor_id,
                            executor_generation=stored.executor_generation,
                            executor_lease_until=stored.executor_lease_until,
                            attempt_id=stored.attempt_id,
                        )
                    return stored
                await connection.execute(
                    insert(action_intents).values(
                        idempotency_key=idempotency_key,
                        incident_id=token.incident_id,
                        lease_generation=token.generation,
                        approval_id=(
                            approval_row["approval_id"] if approval_row is not None else None
                        ),
                        approval_version=(
                            int(approval_row["version"]) if approval_row is not None else None
                        ),
                        action=action_payload,
                        precondition=precondition,
                        status="prepared",
                        executor_id=None,
                        executor_generation=0,
                        executor_lease_until=None,
                        attempt_id=None,
                        result=None,
                        error=None,
                        created_at=now.isoformat(),
                        updated_at=now.isoformat(),
                        queued_at=None,
                        claimed_at=None,
                    )
                )
                await self._append_audit_event(
                    connection,
                    incident_id=token.incident_id,
                    operation_id=f"action:{idempotency_key}:prepared",
                    event_type="action.prepared",
                    source_component="api",
                    actor_type="worker",
                    actor_id=token.owner_id,
                    actor_assurance="internal",
                    subject_type="action_intent",
                    subject_id=idempotency_key,
                    payload={
                        "lease_generation": token.generation,
                        "approval_id": (
                            approval_row["approval_id"]
                            if approval_row is not None
                            else None
                        ),
                        "approval_version": (
                            int(approval_row["version"])
                            if approval_row is not None
                            else None
                        ),
                        "action": action_payload,
                        "precondition_sha256": canonical_payload_hash(precondition),
                    },
                    occurred_at=now.isoformat(),
                )
        except IntegrityError as exc:
            raise ActionIntentConflictError("操作意图已被并发创建") from exc
        return await self._require_action(idempotency_key)

    async def enqueue_action(
        self,
        token: LeaseToken,
        *,
        idempotency_key: str,
    ) -> StoredActionIntent:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            await self._fence_active_lease(connection, token, now=now)
            await self._assert_dispatch_allowed(connection, token.incident_id)
            result = await connection.execute(
                update(action_intents)
                .where(
                    action_intents.c.idempotency_key == idempotency_key,
                    action_intents.c.incident_id == token.incident_id,
                    action_intents.c.lease_generation == token.generation,
                    action_intents.c.status == "prepared",
                )
                .values(
                    status="queued",
                    queued_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if result.rowcount != 1:
                raise ActionIntentConflictError(
                    "操作意图不是可入队状态，禁止重复派发"
                )
            await self._append_audit_event(
                connection,
                incident_id=token.incident_id,
                operation_id=f"action:{idempotency_key}:queued",
                event_type="action.queued",
                source_component="api",
                actor_type="worker",
                actor_id=token.owner_id,
                actor_assurance="internal",
                subject_type="action_intent",
                subject_id=idempotency_key,
                payload={"lease_generation": token.generation},
                occurred_at=now.isoformat(),
            )
        return await self._require_action(idempotency_key)

    async def claim_action_execution(
        self,
        *,
        owner_id: str,
        attempt_id: str,
        ttl_seconds: float,
    ) -> ExecutorClaim | None:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            expired_claims = list(
                (
                    await connection.execute(
                        select(action_intents)
                        .where(
                            action_intents.c.status == "claimed",
                            action_intents.c.executor_lease_until
                            <= now.isoformat(),
                        )
                        .with_for_update(skip_locked=True)
                    )
                ).mappings()
            )
            for expired in expired_claims:
                requeued = await connection.execute(
                    update(action_intents)
                    .where(
                        action_intents.c.idempotency_key
                        == expired["idempotency_key"],
                        action_intents.c.status == "claimed",
                    )
                    .values(
                        status="queued",
                        executor_id=None,
                        executor_lease_until=None,
                        attempt_id=None,
                        updated_at=now.isoformat(),
                    )
                )
                if requeued.rowcount == 1:
                    await self._append_audit_event(
                        connection,
                        incident_id=expired["incident_id"],
                        operation_id=(
                            f"action:{expired['idempotency_key']}:"
                            f"claim-expired:{expired['attempt_id']}"
                        ),
                        event_type="action.requeued",
                        source_component="executor",
                        actor_type="system",
                        actor_id="executor-claim-reaper",
                        actor_assurance="internal",
                        subject_type="action_intent",
                        subject_id=expired["idempotency_key"],
                        payload={
                            "previous_executor_id": expired["executor_id"],
                            "previous_generation": int(
                                expired["executor_generation"]
                            ),
                            "reason": "claim_expired_before_dispatch",
                        },
                        occurred_at=now.isoformat(),
                    )

            expired_dispatches = list(
                (
                    await connection.execute(
                        select(action_intents)
                        .where(
                            action_intents.c.status == "dispatched",
                            action_intents.c.executor_lease_until
                            <= now.isoformat(),
                        )
                        .with_for_update(skip_locked=True)
                    )
                ).mappings()
            )
            for expired in expired_dispatches:
                unknown = await connection.execute(
                    update(action_intents)
                    .where(
                        action_intents.c.idempotency_key
                        == expired["idempotency_key"],
                        action_intents.c.status == "dispatched",
                    )
                    .values(
                        status="unknown",
                        error="Executor 在外部写入派发后失联，禁止自动重放",
                        finished_at=now.isoformat(),
                        updated_at=now.isoformat(),
                    )
                )
                if unknown.rowcount == 1:
                    await self._append_audit_event(
                        connection,
                        incident_id=expired["incident_id"],
                        operation_id=(
                            f"action:{expired['idempotency_key']}:"
                            f"dispatch-expired:{expired['attempt_id']}"
                        ),
                        event_type="action.unknown",
                        source_component="executor",
                        actor_type="system",
                        actor_id="executor-claim-reaper",
                        actor_assurance="internal",
                        subject_type="action_intent",
                        subject_id=expired["idempotency_key"],
                        payload={
                            "executor_id": expired["executor_id"],
                            "executor_generation": int(
                                expired["executor_generation"]
                            ),
                            "attempt_id": expired["attempt_id"],
                            "reason": "dispatch_lease_expired",
                        },
                        occurred_at=now.isoformat(),
                    )
            row = (
                await connection.execute(
                    select(action_intents)
                    .where(action_intents.c.status == "queued")
                    .order_by(action_intents.c.queued_at.asc())
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
            ).mappings().one_or_none()
            if row is None:
                return None
            generation = int(row["executor_generation"]) + 1
            expires_at = now + timedelta(seconds=ttl_seconds)
            result = await connection.execute(
                update(action_intents)
                .where(
                    action_intents.c.idempotency_key == row["idempotency_key"],
                    action_intents.c.status == "queued",
                )
                .values(
                    status="claimed",
                    executor_id=owner_id,
                    executor_generation=generation,
                    executor_lease_until=expires_at.isoformat(),
                    attempt_id=attempt_id,
                    claimed_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if result.rowcount != 1:
                raise ActionIntentConflictError(
                    "操作意图已被其他 Executor 领取"
                )
            await self._append_audit_event(
                connection,
                incident_id=row["incident_id"],
                operation_id=(
                    f"action:{row['idempotency_key']}:claimed:"
                    f"{generation}:{attempt_id}"
                ),
                event_type="action.claimed",
                source_component="executor",
                actor_type="executor",
                actor_id=owner_id,
                actor_assurance="service-account",
                subject_type="action_intent",
                subject_id=row["idempotency_key"],
                payload={
                    "executor_generation": generation,
                    "attempt_id": attempt_id,
                    "lease_expires_at": expires_at.isoformat(),
                },
                occurred_at=now.isoformat(),
            )
        return ExecutorClaim(
            idempotency_key=row["idempotency_key"],
            incident_id=row["incident_id"],
            owner_id=owner_id,
            generation=generation,
            attempt_id=attempt_id,
            expires_at=expires_at,
        )

    async def heartbeat_action_claim(
        self,
        claim: ExecutorClaim,
        *,
        ttl_seconds: float,
    ) -> ExecutorClaim:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            expires_at = now + timedelta(seconds=ttl_seconds)
            result = await connection.execute(
                update(action_intents)
                .where(
                    action_intents.c.idempotency_key == claim.idempotency_key,
                    action_intents.c.incident_id == claim.incident_id,
                    action_intents.c.executor_id == claim.owner_id,
                    action_intents.c.executor_generation == claim.generation,
                    action_intents.c.attempt_id == claim.attempt_id,
                    action_intents.c.executor_lease_until > now.isoformat(),
                    action_intents.c.status.in_(["claimed", "dispatched"]),
                )
                .values(
                    executor_lease_until=expires_at.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if result.rowcount != 1:
                raise LeaseConflictError("Executor 领取已过期或被回收")
        return ExecutorClaim(
            idempotency_key=claim.idempotency_key,
            incident_id=claim.incident_id,
            owner_id=claim.owner_id,
            generation=claim.generation,
            attempt_id=claim.attempt_id,
            expires_at=expires_at,
        )

    async def mark_action_dispatched(
        self,
        claim: ExecutorClaim,
    ) -> StoredActionIntent:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            await self._assert_dispatch_allowed(
                connection,
                claim.incident_id,
                idempotency_key=claim.idempotency_key,
            )
            result = await connection.execute(
                update(action_intents)
                .where(
                    action_intents.c.idempotency_key == claim.idempotency_key,
                    action_intents.c.incident_id == claim.incident_id,
                    action_intents.c.executor_id == claim.owner_id,
                    action_intents.c.executor_generation == claim.generation,
                    action_intents.c.attempt_id == claim.attempt_id,
                    action_intents.c.executor_lease_until > now.isoformat(),
                    action_intents.c.status == "claimed",
                )
                .values(
                    status="dispatched",
                    dispatched_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if result.rowcount != 1:
                raise ActionIntentConflictError(
                    "Executor 领取已失效，禁止派发集群写操作"
                )
            await self._append_audit_event(
                connection,
                incident_id=claim.incident_id,
                operation_id=(
                    f"action:{claim.idempotency_key}:dispatched:"
                    f"{claim.generation}:{claim.attempt_id}"
                ),
                event_type="action.dispatched",
                source_component="executor",
                actor_type="executor",
                actor_id=claim.owner_id,
                actor_assurance="service-account",
                subject_type="action_intent",
                subject_id=claim.idempotency_key,
                payload={
                    "executor_generation": claim.generation,
                    "attempt_id": claim.attempt_id,
                },
                occurred_at=now.isoformat(),
            )
        return await self._require_action(claim.idempotency_key)

    async def complete_action(
        self,
        *,
        claim: ExecutorClaim,
        result: Any,
    ) -> StoredActionIntent:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            updated = await connection.execute(
                update(action_intents)
                .where(
                    action_intents.c.idempotency_key == claim.idempotency_key,
                    action_intents.c.incident_id == claim.incident_id,
                    action_intents.c.executor_id == claim.owner_id,
                    action_intents.c.executor_generation == claim.generation,
                    action_intents.c.attempt_id == claim.attempt_id,
                    action_intents.c.status.in_(["dispatched", "unknown"]),
                )
                .values(
                    status="succeeded" if result.success else "failed",
                    result=result.model_dump(mode="json"),
                    error=result.error,
                    finished_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if updated.rowcount != 1:
                existing = (
                    await connection.execute(
                        select(action_intents).where(
                            action_intents.c.idempotency_key == claim.idempotency_key
                        )
                    )
                ).mappings().one_or_none()
                if (
                    existing is None
                    or existing["attempt_id"] != claim.attempt_id
                    or existing["status"] not in {"succeeded", "failed"}
                    or existing["result"] != result.model_dump(mode="json")
                ):
                    raise ActionIntentConflictError(
                        "操作结果无法绑定到同一次 Executor 尝试"
                    )
            else:
                result_payload = result.model_dump(mode="json")
                await self._append_audit_event(
                    connection,
                    incident_id=claim.incident_id,
                    operation_id=(
                        f"action:{claim.idempotency_key}:completed:"
                        f"{claim.attempt_id}"
                    ),
                    event_type=(
                        "action.succeeded" if result.success else "action.failed"
                    ),
                    source_component="executor",
                    actor_type="executor",
                    actor_id=claim.owner_id,
                    actor_assurance="service-account",
                    subject_type="action_intent",
                    subject_id=claim.idempotency_key,
                    payload={
                        "executor_generation": claim.generation,
                        "attempt_id": claim.attempt_id,
                        "tool_name": result.tool_name,
                        "result_sha256": canonical_payload_hash(result_payload),
                        "success": result.success,
                    },
                    occurred_at=now.isoformat(),
                )
        return await self._require_action(claim.idempotency_key)

    async def cancel_action(
        self,
        token: LeaseToken,
        *,
        idempotency_key: str,
        reason: str,
    ) -> StoredActionIntent:
        return await self._finish_action_without_result(
            token,
            idempotency_key=idempotency_key,
            status="cancelled",
            reason=reason,
            allowed_statuses=["prepared", "queued", "claimed"],
        )

    async def mark_action_unknown(
        self,
        *,
        claim: ExecutorClaim,
        reason: str,
    ) -> StoredActionIntent:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            result = await connection.execute(
                update(action_intents)
                .where(
                    action_intents.c.idempotency_key == claim.idempotency_key,
                    action_intents.c.incident_id == claim.incident_id,
                    action_intents.c.executor_id == claim.owner_id,
                    action_intents.c.executor_generation == claim.generation,
                    action_intents.c.attempt_id == claim.attempt_id,
                    action_intents.c.status == "dispatched",
                )
                .values(
                    status="unknown",
                    error=reason,
                    finished_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if result.rowcount != 1:
                raise ActionIntentConflictError("操作意图无法转换为 unknown")
            await self._append_audit_event(
                connection,
                incident_id=claim.incident_id,
                operation_id=(
                    f"action:{claim.idempotency_key}:unknown:{claim.attempt_id}"
                ),
                event_type="action.unknown",
                source_component="executor",
                actor_type="executor",
                actor_id=claim.owner_id,
                actor_assurance="service-account",
                subject_type="action_intent",
                subject_id=claim.idempotency_key,
                payload={
                    "executor_generation": claim.generation,
                    "attempt_id": claim.attempt_id,
                    "reason_sha256": canonical_payload_hash(reason),
                },
                occurred_at=now.isoformat(),
            )
        return await self._require_action(claim.idempotency_key)

    async def latest_action_intent(
        self,
        incident_id: str,
    ) -> StoredActionIntent | None:
        async with self.engine.connect() as connection:
            row = (
                await connection.execute(
                    select(action_intents)
                    .where(action_intents.c.incident_id == incident_id)
                    .order_by(action_intents.c.created_at.desc())
                    .limit(1)
                )
            ).mappings().one_or_none()
        return self._stored_action(row) if row else None

    async def mark_abandoned_action_unknown(
        self,
        incident_id: str,
        *,
        reason: str,
    ) -> StoredActionIntent | None:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            active = (
                await connection.execute(
                    select(worker_leases.c.incident_id).where(
                        worker_leases.c.incident_id == incident_id,
                        worker_leases.c.expires_at > now.isoformat(),
                    )
                )
            ).scalar_one_or_none()
            if active is not None:
                raise LeaseConflictError(
                    f"incident {incident_id} still has an active worker"
                )
            row = (
                await connection.execute(
                    select(action_intents)
                    .where(action_intents.c.incident_id == incident_id)
                    .order_by(action_intents.c.created_at.desc())
                    .limit(1)
                )
            ).mappings().one_or_none()
            if row is None:
                return None
            if row["status"] in {"claimed", "dispatched"}:
                lease_until = (
                    datetime.fromisoformat(row["executor_lease_until"])
                    if row["executor_lease_until"]
                    else None
                )
                if lease_until is not None and lease_until > now:
                    raise LeaseConflictError(
                        f"incident {incident_id} still has an active executor"
                    )
            if row["status"] == "claimed":
                await connection.execute(
                    update(action_intents)
                    .where(
                        action_intents.c.idempotency_key == row["idempotency_key"],
                        action_intents.c.status == "claimed",
                    )
                    .values(
                        status="queued",
                        executor_id=None,
                        executor_lease_until=None,
                        attempt_id=None,
                        updated_at=now.isoformat(),
                    )
                )
                row = {
                    **row,
                    "status": "queued",
                    "executor_id": None,
                    "executor_lease_until": None,
                    "attempt_id": None,
                }
                await self._append_audit_event(
                    connection,
                    incident_id=incident_id,
                    operation_id=(
                        f"action:{row['idempotency_key']}:requeued:"
                        f"{now.isoformat()}"
                    ),
                    event_type="action.requeued",
                    source_component="api",
                    actor_type="system",
                    actor_id="startup-reconciler",
                    actor_assurance="internal",
                    subject_type="action_intent",
                    subject_id=row["idempotency_key"],
                    payload={"reason": "expired_before_dispatch"},
                    occurred_at=now.isoformat(),
                )
            elif row["status"] == "dispatched":
                await connection.execute(
                    update(action_intents)
                    .where(
                        action_intents.c.idempotency_key == row["idempotency_key"],
                        action_intents.c.status == "dispatched",
                    )
                    .values(
                        status="unknown",
                        error=reason,
                        finished_at=now.isoformat(),
                        updated_at=now.isoformat(),
                    )
                )
                row = {**row, "status": "unknown", "error": reason}
                await self._append_audit_event(
                    connection,
                    incident_id=incident_id,
                    operation_id=(
                        f"action:{row['idempotency_key']}:reconciled-unknown:"
                        f"{row.get('attempt_id') or 'missing-attempt'}"
                    ),
                    event_type="action.unknown",
                    source_component="api",
                    actor_type="system",
                    actor_id="startup-reconciler",
                    actor_assurance="internal",
                    subject_type="action_intent",
                    subject_id=row["idempotency_key"],
                    payload={"reason_sha256": canonical_payload_hash(reason)},
                    occurred_at=now.isoformat(),
                )
            return self._stored_action(row)

    async def _finish_action_without_result(
        self,
        token: LeaseToken,
        *,
        idempotency_key: str,
        status: str,
        reason: str,
        allowed_statuses: list[str],
    ) -> StoredActionIntent:
        async with self.engine.begin() as connection:
            now = await self._database_now(connection)
            result = await connection.execute(
                update(action_intents)
                .where(
                    action_intents.c.idempotency_key == idempotency_key,
                    action_intents.c.incident_id == token.incident_id,
                    action_intents.c.lease_generation == token.generation,
                    action_intents.c.status.in_(allowed_statuses),
                )
                .values(
                    status=status,
                    error=reason,
                    finished_at=now.isoformat(),
                    updated_at=now.isoformat(),
                )
            )
            if result.rowcount != 1:
                raise ActionIntentConflictError(
                    f"操作意图无法转换为 {status}"
                )
            await self._append_audit_event(
                connection,
                incident_id=token.incident_id,
                operation_id=f"action:{idempotency_key}:{status}",
                event_type=f"action.{status}",
                source_component="api",
                actor_type="worker",
                actor_id=token.owner_id,
                actor_assurance="internal",
                subject_type="action_intent",
                subject_id=idempotency_key,
                payload={"reason_sha256": canonical_payload_hash(reason)},
                occurred_at=now.isoformat(),
            )
        return await self._require_action(idempotency_key)

    async def _require_action(self, idempotency_key: str) -> StoredActionIntent:
        async with self.engine.connect() as connection:
            row = (
                await connection.execute(
                    select(action_intents).where(
                        action_intents.c.idempotency_key == idempotency_key
                    )
                )
            ).mappings().one_or_none()
        if row is None:
            raise ActionIntentConflictError("操作意图不存在")
        return self._stored_action(row)

    @staticmethod
    async def _assert_active_lease(
        connection: Any,
        token: LeaseToken,
        *,
        now: datetime,
    ) -> None:
        active = (
            await connection.execute(
                select(worker_leases.c.incident_id).where(
                    worker_leases.c.incident_id == token.incident_id,
                    worker_leases.c.owner_id == token.owner_id,
                    worker_leases.c.generation == token.generation,
                    worker_leases.c.expires_at > now.isoformat(),
                )
            )
        ).scalar_one_or_none()
        if active is None:
            raise LeaseConflictError(
                f"incident {token.incident_id} lease expired or was fenced"
            )

    @staticmethod
    async def _fence_active_lease(
        connection: Any,
        token: LeaseToken,
        *,
        now: datetime,
    ) -> None:
        result = await connection.execute(
            update(worker_leases)
            .where(
                worker_leases.c.incident_id == token.incident_id,
                worker_leases.c.owner_id == token.owner_id,
                worker_leases.c.generation == token.generation,
                worker_leases.c.expires_at > now.isoformat(),
            )
            .values(updated_at=now.isoformat())
        )
        if result.rowcount != 1:
            raise LeaseConflictError(
                f"incident {token.incident_id} lease expired or was fenced"
            )

    @staticmethod
    async def _database_now(connection: Any) -> datetime:
        value = (
            await connection.execute(select(func.current_timestamp()))
        ).scalar_one()
        if isinstance(value, str):
            value = datetime.fromisoformat(value)
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    async def _bump_anchor_inventory_epoch(
        connection: Any,
        *,
        now: datetime | None = None,
    ) -> int:
        timestamp = now or await SqlIncidentStore._database_now(connection)
        row = (
            await connection.execute(
                select(audit_anchor_inventory_epoch)
                .where(
                    audit_anchor_inventory_epoch.c.scope_id
                    == "external-audit-anchor"
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if row is None:
            await connection.execute(
                insert(audit_anchor_inventory_epoch).values(
                    scope_id="external-audit-anchor",
                    revision=1,
                    updated_at=timestamp.isoformat(),
                )
            )
            return 1
        revision = int(row["revision"]) + 1
        changed = await connection.execute(
            update(audit_anchor_inventory_epoch)
            .where(
                audit_anchor_inventory_epoch.c.scope_id
                == "external-audit-anchor",
                audit_anchor_inventory_epoch.c.revision
                == row["revision"],
            )
            .values(
                revision=revision,
                updated_at=timestamp.isoformat(),
            )
        )
        if changed.rowcount != 1:
            raise AuditAnchorConflictError(
                "审计清单代次已被并发更新"
            )
        return revision

    @staticmethod
    async def _assert_dispatch_allowed(
        connection: Any,
        incident_id: str,
        *,
        idempotency_key: str | None = None,
    ) -> None:
        anchor_security = (
            await connection.execute(
                select(audit_anchor_security_state)
                .where(
                    audit_anchor_security_state.c.scope_id
                    == "external-audit-anchor"
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if anchor_security is not None and bool(
            anchor_security["write_blocked"]
        ):
            raise ActionIntentConflictError(
                "外部审计锚定安全闸门已关闭，禁止派发集群写操作"
            )
        status = (
            await connection.execute(
                select(incidents.c.status)
                .where(incidents.c.id == incident_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if status is None:
            raise ActionIntentConflictError("持久化事故不存在")
        if status in {"resolved", "failed", "rejected", "escalated"}:
            raise ActionIntentConflictError(
                f"事故已处于 {status}，禁止派发集群写操作"
            )
        approval_row = (
            await connection.execute(
                select(
                    approvals.c.approval_id,
                    approvals.c.version,
                    approvals.c.status,
                    approvals.c.payload,
                )
                .where(approvals.c.incident_id == incident_id)
                .order_by(approvals.c.version.desc())
                .limit(1)
            )
        ).mappings().one_or_none()
        if approval_row is not None and approval_row["status"] != "approved":
            raise ActionIntentConflictError(
                f"审批状态为 {approval_row['status']}，禁止派发集群写操作"
            )
        if idempotency_key is not None:
            intent_row = (
                await connection.execute(
                    select(
                        action_intents.c.action,
                        action_intents.c.approval_id,
                        action_intents.c.approval_version,
                    ).where(action_intents.c.idempotency_key == idempotency_key)
                )
            ).mappings().one_or_none()
            if intent_row is None:
                raise ActionIntentConflictError("Action Intent 不存在")
            if approval_row is not None:
                approved_action = approval_row["payload"].get("action")
                if (
                    intent_row["approval_id"] != approval_row["approval_id"]
                    or intent_row["approval_version"] != approval_row["version"]
                    or intent_row["action"] != approved_action
                ):
                    raise ActionIntentConflictError(
                        "Action Intent 与已批准的动作或审批版本不一致"
                    )

    async def _insert_incident_tx(
        self,
        connection: Any,
        record: IncidentRecord,
        *,
        now: datetime,
    ) -> StoredIncident:
        stored_record = record.model_copy(deep=True)
        stored_record.updated_at = now
        record_payload = stored_record.model_dump(mode="json")
        await connection.execute(
            insert(incidents).values(
                id=record.id,
                version=1,
                status=record.status.value,
                execution_profile_id=record.execution_profile_id,
                record=record_payload,
                graph_state=None,
                created_at=record.created_at.isoformat(),
                updated_at=now.isoformat(),
            )
        )
        await self._append_audit_event(
            connection,
            incident_id=record.id,
            operation_id=f"incident:{record.id}:snapshot:1",
            event_type="incident.created",
            source_component="api",
            actor_type="system",
            actor_id="alert-ingestion",
            actor_assurance="internal",
            subject_type="incident",
            subject_id=record.id,
            payload={
                "version": 1,
                "status": record.status.value,
                "record_sha256": canonical_payload_hash(record_payload),
                "graph_state_sha256": canonical_payload_hash(None),
            },
            occurred_at=now.isoformat(),
            allow_chain_create=True,
        )
        await self._append_events(connection, stored_record)
        await self._sync_approval(connection, stored_record)
        return StoredIncident(
            record=stored_record,
            version=1,
            graph_state=None,
        )

    async def _require_incident_tx(
        self,
        connection: Any,
        incident_id: str | None,
    ) -> StoredIncident:
        stored = await self._optional_incident_tx(connection, incident_id)
        if stored is None:
            raise StoreConflictError(
                "Alertmanager fingerprint points to a missing incident"
            )
        return stored

    @staticmethod
    async def _optional_incident_tx(
        connection: Any,
        incident_id: str | None,
    ) -> StoredIncident | None:
        if incident_id is None:
            return None
        row = (
            await connection.execute(
                select(
                    incidents.c.record,
                    incidents.c.version,
                    incidents.c.graph_state,
                ).where(incidents.c.id == incident_id)
            )
        ).mappings().one_or_none()
        return SqlIncidentStore._stored(row) if row is not None else None

    @staticmethod
    def _stored_action(row: Any) -> StoredActionIntent:
        from sentinelops.domain import RemediationAction, ToolResult

        return StoredActionIntent(
            idempotency_key=row["idempotency_key"],
            incident_id=row["incident_id"],
            lease_generation=int(row["lease_generation"]),
            approval_id=row["approval_id"],
            approval_version=(
                int(row["approval_version"])
                if row["approval_version"] is not None
                else None
            ),
            action=RemediationAction.model_validate(row["action"]),
            precondition=row["precondition"],
            status=row["status"],
            result=ToolResult.model_validate(row["result"]) if row["result"] else None,
            error=row["error"],
            executor_id=row["executor_id"],
            executor_generation=int(row["executor_generation"]),
            executor_lease_until=(
                datetime.fromisoformat(row["executor_lease_until"])
                if row["executor_lease_until"]
                else None
            ),
            attempt_id=row["attempt_id"],
        )

    @staticmethod
    def _stored_audit_event(row: Any) -> AuditEvent:
        return AuditEvent(
            incident_id=row["incident_id"],
            sequence=int(row["sequence"]),
            operation_id=row["operation_id"],
            event_type=row["event_type"],
            source_component=row["source_component"],
            actor_type=row["actor_type"],
            actor_id=row["actor_id"],
            actor_assurance=row["actor_assurance"],
            subject_type=row["subject_type"],
            subject_id=row["subject_id"],
            payload=row["payload"],
            occurred_at=row["occurred_at"],
            committed_at=row["committed_at"],
            previous_hash=row["previous_hash"],
            entry_hash=row["entry_hash"],
            auth_tag=row["auth_tag"],
            auth_algorithm=row["auth_algorithm"],
            key_id=row["key_id"],
            canonicalization=row["canonicalization"],
            schema_version=int(row["schema_version"]),
        )

    @staticmethod
    def _stored_anchor(row: Any) -> AuditAnchor:
        return AuditAnchor(
            anchor_id=row["anchor_id"],
            incident_id=row["incident_id"],
            sequence=int(row["sequence"]),
            head_hash=row["head_hash"],
            previous_anchor_id=row["previous_anchor_id"],
            audit_key_id=row["audit_key_id"],
            audit_auth_algorithm=row["audit_auth_algorithm"],
            audit_auth_tag=row["audit_auth_tag"],
            audit_committed_at=datetime.fromisoformat(
                row["audit_committed_at"]
            ),
            status=row["status"],
            attempt_count=int(row["attempt_count"]),
            next_attempt_at=datetime.fromisoformat(row["next_attempt_at"]),
            last_error_sha256=row["last_error_sha256"],
            receipt=row["receipt"],
        )

    @staticmethod
    def _stored_anchor_security_state(
        row: Any,
    ) -> AuditAnchorSecurityState:
        return AuditAnchorSecurityState(
            status=row["status"],
            generation=int(row["generation"]),
            write_blocked=bool(row["write_blocked"]),
            reason_sha256=row["reason_sha256"],
            last_attempt_at=datetime.fromisoformat(row["last_attempt_at"]),
            last_success_at=(
                datetime.fromisoformat(row["last_success_at"])
                if row["last_success_at"]
                else None
            ),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _stored_anchor_unlock_request(
        row: Any,
    ) -> AuditAnchorUnlockRequest:
        return AuditAnchorUnlockRequest(
            request_id=row["request_id"],
            scope_id=row["scope_id"],
            blocked_generation=int(row["blocked_generation"]),
            unlock_generation=(
                int(row["unlock_generation"])
                if row["unlock_generation"] is not None
                else None
            ),
            status=row["status"],
            version=int(row["version"]),
            requester_principal_hash=row["requester_principal_hash"],
            requester_issuer_hash=row["requester_issuer_hash"],
            change_ticket_sha256=row["change_ticket_sha256"],
            justification_sha256=row["justification_sha256"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            approved_at=_stored_time(row["approved_at"]),
            lease_owner=row["lease_owner"],
            lease_generation=int(row["lease_generation"]),
            lease_until=_stored_time(row["lease_until"]),
            local_snapshot_hash=row["local_snapshot_hash"],
            remote_snapshot_id=row["remote_snapshot_id"],
            remote_snapshot_root=row["remote_snapshot_root"],
            challenge_sha256=row["challenge_sha256"],
            attested_at=_stored_time(row["attested_at"]),
            completed_at=_stored_time(row["completed_at"]),
            terminal_reason_sha256=row["terminal_reason_sha256"],
        )

    @staticmethod
    def _stored_anchor_unlock_decision(
        row: Any,
    ) -> AuditAnchorUnlockDecision:
        return AuditAnchorUnlockDecision(
            decision_id=row["decision_id"],
            request_id=row["request_id"],
            request_version=int(row["request_version"]),
            principal_hash=row["principal_hash"],
            issuer_hash=row["issuer_hash"],
            role=row["role"],
            decision=row["decision"],
            assurance=row["assurance"],
            note_sha256=row["note_sha256"],
            decided_at=datetime.fromisoformat(row["decided_at"]),
        )

    @staticmethod
    def _assert_unlock_actor(
        *,
        principal_hash: str,
        issuer: str,
        operation_id: str,
        actor_assurance: str,
    ) -> None:
        if (
            len(principal_hash) != 64
            or any(character not in "0123456789abcdef" for character in principal_hash)
        ):
            raise AuditAnchorUnlockConflictError(
                "解锁操作者必须使用不可逆的 OIDC principal hash"
            )
        if (
            not issuer.strip()
            or not operation_id.strip()
            or actor_assurance != "oidc-human"
        ):
            raise AuditAnchorUnlockConflictError(
                "解锁操作只接受已验证的 OIDC 人类身份"
            )

    async def _require_anchor(self, anchor_identifier: str) -> AuditAnchor:
        async with self.engine.connect() as connection:
            row = (
                await connection.execute(
                    select(audit_anchor_outbox).where(
                        audit_anchor_outbox.c.anchor_id == anchor_identifier
                    )
                )
            ).mappings().one_or_none()
        if row is None:
            raise AuditAnchorConflictError("审计锚点不存在")
        return self._stored_anchor(row)

    async def _append_audit_event(
        self,
        connection: Any,
        *,
        incident_id: str,
        operation_id: str,
        event_type: str,
        source_component: str,
        actor_type: str,
        actor_id: str,
        actor_assurance: str,
        subject_type: str,
        subject_id: str,
        payload: dict[str, Any],
        occurred_at: str | None = None,
        allow_chain_create: bool = False,
    ) -> None:
        existing = (
            await connection.execute(
                select(audit_events).where(
                    audit_events.c.incident_id == incident_id,
                    audit_events.c.operation_id == operation_id,
                )
            )
        ).mappings().one_or_none()
        if existing is not None:
            if (
                existing["event_type"] != event_type
                or existing["payload"] != payload
            ):
                raise StoreConflictError(
                    "审计 operation_id 已绑定到不同事件"
                )
            return

        head = (
            await connection.execute(
                select(audit_heads)
                .where(audit_heads.c.incident_id == incident_id)
                .with_for_update()
            )
        ).mappings().one_or_none()
        committed_at = (await self._database_now(connection)).isoformat()
        if head is None:
            if not allow_chain_create:
                raise StoreConflictError(
                    f"incident {incident_id} 缺少审计 head，拒绝提交业务变更"
                )
            previous_hash = genesis_hash(incident_id)
            previous_sequence = 0
            await connection.execute(
                insert(audit_heads).values(
                    incident_id=incident_id,
                    last_sequence=0,
                    last_hash=previous_hash,
                    updated_at=committed_at,
                )
            )
        else:
            previous_hash = head["last_hash"]
            previous_sequence = int(head["last_sequence"])

        sequence = previous_sequence + 1
        effective_occurred_at = occurred_at or committed_at
        document = canonical_audit_document(
            incident_id=incident_id,
            sequence=sequence,
            operation_id=operation_id,
            event_type=event_type,
            source_component=source_component,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_assurance=actor_assurance,
            subject_type=subject_type,
            subject_id=subject_id,
            payload=payload,
            occurred_at=effective_occurred_at,
            committed_at=committed_at,
            previous_hash=previous_hash,
            auth_algorithm=self.audit_auth_algorithm,
            key_id=self.audit_key_id,
        )
        if len(document) > 262_144:
            raise StoreConflictError("单条审计事件超过 256 KiB")
        entry_hash = audit_entry_hash(document)
        auth_tag = audit_auth_tag(
            entry_hash,
            hmac_key=self.audit_hmac_key,
        )
        await connection.execute(
            insert(audit_events).values(
                incident_id=incident_id,
                sequence=sequence,
                operation_id=operation_id,
                event_type=event_type,
                source_component=source_component,
                actor_type=actor_type,
                actor_id=actor_id,
                actor_assurance=actor_assurance,
                subject_type=subject_type,
                subject_id=subject_id,
                payload=payload,
                occurred_at=effective_occurred_at,
                committed_at=committed_at,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                auth_tag=auth_tag,
                auth_algorithm=self.audit_auth_algorithm,
                key_id=self.audit_key_id,
                canonicalization=CANONICALIZATION,
                schema_version=SCHEMA_VERSION,
            )
        )
        updated = await connection.execute(
            update(audit_heads)
            .where(
                audit_heads.c.incident_id == incident_id,
                audit_heads.c.last_sequence == previous_sequence,
                audit_heads.c.last_hash == previous_hash,
            )
            .values(
                last_sequence=sequence,
                last_hash=entry_hash,
                updated_at=committed_at,
            )
        )
        if updated.rowcount != 1:
            raise StoreConflictError("审计 head 已被并发更新")
        current_anchor_id = anchor_id(incident_id, sequence, entry_hash)
        previous_anchor_id = (
            anchor_id(incident_id, previous_sequence, previous_hash)
            if previous_sequence > 0
            else None
        )
        await connection.execute(
            insert(audit_anchor_outbox).values(
                anchor_id=current_anchor_id,
                incident_id=incident_id,
                sequence=sequence,
                head_hash=entry_hash,
                previous_anchor_id=previous_anchor_id,
                audit_key_id=self.audit_key_id,
                audit_auth_algorithm=self.audit_auth_algorithm,
                audit_auth_tag=auth_tag,
                audit_committed_at=committed_at,
                status="pending",
                attempt_count=0,
                next_attempt_at=committed_at,
                claimed_by=None,
                claim_generation=0,
                attempt_id=None,
                claim_until=None,
                last_error_sha256=None,
                receipt=None,
                created_at=committed_at,
                updated_at=committed_at,
                delivered_at=None,
            )
        )
        await self._bump_anchor_inventory_epoch(connection)

    @staticmethod
    def _stored(row: Any) -> StoredIncident:
        return StoredIncident(
            record=IncidentRecord.model_validate(row["record"]),
            version=int(row["version"]),
            graph_state=row["graph_state"],
        )

    async def _append_events(self, connection: Any, record: IncidentRecord) -> None:
        existing = int(
            (
                await connection.execute(
                    select(func.count())
                    .select_from(incident_events)
                    .where(incident_events.c.incident_id == record.id)
                )
            ).scalar_one()
        )
        for sequence, item in enumerate(record.timeline[existing:], start=existing + 1):
            await connection.execute(
                insert(incident_events).values(
                    incident_id=record.id,
                    sequence=sequence,
                    event_type=item.type,
                    message=item.message,
                    data=item.data,
                    created_at=item.created_at.isoformat(),
                )
            )
            await self._append_audit_event(
                connection,
                incident_id=record.id,
                operation_id=f"timeline:{record.id}:{sequence}",
                event_type=f"timeline.{item.type}",
                source_component="agent",
                actor_type="agent",
                actor_id="incident-agent",
                actor_assurance="internal",
                subject_type="incident",
                subject_id=record.id,
                payload={
                    "message": item.message,
                    "data": item.data,
                },
                occurred_at=item.created_at.isoformat(),
            )

    @staticmethod
    async def _sync_approval(connection: Any, record: IncidentRecord) -> None:
        request = record.approval
        if request is not None:
            existing = (
                await connection.execute(
                    select(approvals.c.approval_id).where(
                        approvals.c.approval_id == request.approval_id
                    )
                )
            ).scalar_one_or_none()
            values = {
                "approval_id": request.approval_id,
                "incident_id": record.id,
                "version": request.version,
                "status": "pending",
                "payload": request.model_dump(mode="json"),
                "expires_at": request.expires_at.isoformat(),
            }
            if existing is None:
                await connection.execute(insert(approvals).values(**values))
            return

        pending_ids = (
            await connection.execute(
                select(approvals.c.approval_id).where(
                    approvals.c.incident_id == record.id,
                    approvals.c.status == "pending",
                )
            )
        ).scalars()
        status = _closed_approval_status(record.timeline)
        for approval_id in pending_ids:
            await connection.execute(
                update(approvals)
                .where(approvals.c.approval_id == approval_id)
                .values(status=status, decided_at=datetime.now(UTC).isoformat())
            )


def _closed_approval_status(timeline: list[TimelineEvent]) -> str:
    for item in reversed(timeline):
        if item.type == "approval.decided":
            return "approved" if item.data.get("approved") else "rejected"
        if item.type == "approval.expired":
            return "expired"
        if item.type in {"approval.invalidated", "alertmanager.resolved"}:
            return "invalidated"
        if item.type in {"approval.resume_cancelled", "approval.resume_failed"}:
            return "consumed"
    return "consumed"


def _normalized_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _normalized_time(value: datetime | None) -> str | None:
    return _normalized_datetime(value).isoformat() if value is not None else None


def _stored_time(value: str | None) -> datetime | None:
    return _normalized_datetime(datetime.fromisoformat(value)) if value else None
