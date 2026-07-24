from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update

from sentinelops.audit_anchor import AuditAnchorReconciler
from sentinelops.storage import (
    ActionIntentConflictError,
    AuditAnchorUnlockConflictError,
    SqlIncidentStore,
)
from sentinelops.storage.anchor import AUDIT_ANCHOR_SECURITY_STREAM_ID
from sentinelops.storage.audit import canonical_payload_hash
from sentinelops.storage.sqlalchemy import (
    audit_anchor_unlock_decisions,
    audit_anchor_unlock_requests,
)

AUDIT_KEY = "unlock-audit-key-000000000000000001"
ISSUER = "https://identity.example.test"
REQUESTER = hashlib.sha256(b"issuer-a\x00requester").hexdigest()
APPROVER = hashlib.sha256(b"issuer-a\x00approver").hexdigest()


async def _store(tmp_path) -> SqlIncidentStore:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'unlock.db'}",
        audit_hmac_key=AUDIT_KEY,
        audit_key_id="unlock-test-v1",
    )
    await store.setup()
    await store.set_audit_anchor_security_state(
        status="integrity_blocked",
        write_blocked=True,
        reason="remote_anchor_fork",
        successful=False,
    )
    return store


async def _request(store: SqlIncidentStore):
    state = await store.audit_anchor_security_state()
    assert state is not None
    return await store.request_audit_anchor_unlock(
        expected_security_generation=state.generation,
        requester_principal_hash=REQUESTER,
        requester_issuer=ISSUER,
        change_ticket="CHG-2026-0042",
        justification="安全团队已确认外部账本恢复",
        ttl_seconds=600,
        operation_id="unlock-request:test-1",
        actor_assurance="oidc-human",
    )


async def _approve(store: SqlIncidentStore):
    request = await _request(store)
    approved = await store.decide_audit_anchor_unlock(
        request_id=request.request_id,
        expected_request_version=request.version,
        expected_security_generation=request.blocked_generation,
        approver_principal_hash=APPROVER,
        approver_issuer=ISSUER,
        approved=True,
        note="严格对账前的第二人批准",
        operation_id=f"unlock-decision:approve:{request.request_id}",
        actor_assurance="oidc-human",
    )
    return request, approved


async def _drain_outbox(store: SqlIncidentStore) -> None:
    while True:
        anchor_claim = await store.claim_audit_anchor(
            owner_id="unlock-test-publisher",
            ttl_seconds=60,
        )
        if anchor_claim is None:
            return
        await store.complete_audit_anchor(
            anchor_claim,
            receipt={"receipt_id": f"receipt-{anchor_claim.anchor.anchor_id}"},
        )


@pytest.mark.asyncio
async def test_unlock_request_is_hashed_audited_and_keeps_gate_closed(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    request = await _request(store)
    state = await store.audit_anchor_security_state()
    decisions = await store.list_audit_anchor_unlock_decisions(
        request.request_id
    )
    audit = await store.list_audit_events(AUDIT_ANCHOR_SECURITY_STREAM_ID)

    assert request.status == "awaiting_second_approval"
    assert request.version == 1
    assert request.change_ticket_sha256 == canonical_payload_hash(
        "CHG-2026-0042"
    )
    assert state is not None
    assert state.status == "integrity_blocked"
    assert state.generation == request.blocked_generation
    assert state.write_blocked is True
    assert [(item.role, item.decision) for item in decisions] == [
        ("requester", "requested")
    ]
    assert [item.event_type for item in audit] == [
        "audit_anchor.unlock_requested"
    ]
    assert audit[0].auth_algorithm == "hmac-sha256"
    assert audit[0].auth_tag

    async with store.engine.connect() as connection:
        raw_request = (
            await connection.execute(
                select(audit_anchor_unlock_requests).where(
                    audit_anchor_unlock_requests.c.request_id
                    == request.request_id
                )
            )
        ).mappings().one()
    serialized = repr(dict(raw_request))
    assert "CHG-2026-0042" not in serialized
    assert "安全团队已确认" not in serialized
    assert ISSUER not in serialized
    await store.close()


@pytest.mark.asyncio
async def test_same_human_cannot_approve_their_own_unlock_request(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    request = await _request(store)

    with pytest.raises(
        AuditAnchorUnlockConflictError,
        match="两个不同的人类身份",
    ):
        await store.decide_audit_anchor_unlock(
            request_id=request.request_id,
            expected_request_version=request.version,
            expected_security_generation=request.blocked_generation,
            approver_principal_hash=REQUESTER,
            approver_issuer=ISSUER,
            approved=True,
            note="self approval",
            operation_id="unlock-decision:self",
            actor_assurance="oidc-human",
        )

    unchanged = await store.get_audit_anchor_unlock_request(
        request.request_id
    )
    state = await store.audit_anchor_security_state()
    assert unchanged == request
    assert state is not None
    assert state.status == "integrity_blocked"
    assert state.write_blocked is True
    await store.close()


@pytest.mark.asyncio
async def test_second_human_approval_only_moves_to_unlock_pending(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    request = await _request(store)

    approved = await store.decide_audit_anchor_unlock(
        request_id=request.request_id,
        expected_request_version=request.version,
        expected_security_generation=request.blocked_generation,
        approver_principal_hash=APPROVER,
        approver_issuer=ISSUER,
        approved=True,
        note="外部账本已由安全团队恢复，等待严格对账",
        operation_id="unlock-decision:approve",
        actor_assurance="oidc-human",
    )
    state = await store.audit_anchor_security_state()
    decisions = await store.list_audit_anchor_unlock_decisions(
        request.request_id
    )

    assert approved.status == "approved"
    assert approved.version == 2
    assert approved.unlock_generation == request.blocked_generation + 1
    assert state is not None
    assert state.status == "unlock_pending"
    assert state.generation == approved.unlock_generation
    assert state.write_blocked is True
    assert {(item.role, item.decision) for item in decisions} == {
        ("requester", "requested"),
        ("approver", "approved"),
    }

    async with store.engine.begin() as connection:
        with pytest.raises(
            ActionIntentConflictError,
            match="安全闸门已关闭",
        ):
            await store._assert_dispatch_allowed(
                connection,
                "nonexistent-incident",
            )

    sticky = await store.set_audit_anchor_security_state(
        status="healthy",
        write_blocked=False,
        reason="ordinary_reconciliation",
        successful=True,
    )
    assert sticky.status == "unlock_pending"
    assert sticky.write_blocked is True

    reconciler = AuditAnchorReconciler(
        store,
        object(),  # type: ignore[arg-type]
        max_staleness_seconds=60,
    )
    assert await reconciler.reconcile_once() == "unlock_pending"
    final_state = await store.audit_anchor_security_state()
    assert final_state == sticky
    await store.close()


@pytest.mark.asyncio
async def test_stale_generation_and_stale_version_cannot_be_approved(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    request = await _request(store)

    with pytest.raises(AuditAnchorUnlockConflictError, match="代次"):
        await store.decide_audit_anchor_unlock(
            request_id=request.request_id,
            expected_request_version=request.version,
            expected_security_generation=request.blocked_generation + 1,
            approver_principal_hash=APPROVER,
            approver_issuer=ISSUER,
            approved=True,
            note="stale generation",
            operation_id="unlock-decision:stale-generation",
            actor_assurance="oidc-human",
        )
    with pytest.raises(AuditAnchorUnlockConflictError, match="版本"):
        await store.decide_audit_anchor_unlock(
            request_id=request.request_id,
            expected_request_version=request.version + 1,
            expected_security_generation=request.blocked_generation,
            approver_principal_hash=APPROVER,
            approver_issuer=ISSUER,
            approved=True,
            note="stale version",
            operation_id="unlock-decision:stale-version",
            actor_assurance="oidc-human",
        )
    await store.close()


@pytest.mark.asyncio
async def test_expired_request_is_terminal_and_cannot_be_approved(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    request = await _request(store)
    expired_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    async with store.engine.begin() as connection:
        await connection.execute(
            update(audit_anchor_unlock_requests)
            .where(
                audit_anchor_unlock_requests.c.request_id
                == request.request_id
            )
            .values(expires_at=expired_at)
        )

    with pytest.raises(AuditAnchorUnlockConflictError, match="已过期"):
        await store.decide_audit_anchor_unlock(
            request_id=request.request_id,
            expected_request_version=request.version,
            expected_security_generation=request.blocked_generation,
            approver_principal_hash=APPROVER,
            approver_issuer=ISSUER,
            approved=True,
            note="too late",
            operation_id="unlock-decision:expired",
            actor_assurance="oidc-human",
        )

    expired = await store.get_audit_anchor_unlock_request(
        request.request_id
    )
    assert expired is not None
    assert expired.status == "expired"
    assert expired.version == 2
    assert expired.terminal_reason_sha256 == canonical_payload_hash(
        "request_expired"
    )
    async with store.engine.connect() as connection:
        active_scope = (
            await connection.execute(
                select(
                    audit_anchor_unlock_requests.c.active_scope_id
                ).where(
                    audit_anchor_unlock_requests.c.request_id
                    == request.request_id
                )
            )
        ).scalar_one()
    assert active_scope is None
    await store.close()


@pytest.mark.asyncio
async def test_unlock_requires_hmac_and_verified_oidc_human(tmp_path) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'unkeyed.db'}"
    )
    await store.setup()
    state = await store.set_audit_anchor_security_state(
        status="integrity_blocked",
        write_blocked=True,
        reason="fork",
        successful=False,
    )
    with pytest.raises(AuditAnchorUnlockConflictError, match="OIDC"):
        await store.request_audit_anchor_unlock(
            expected_security_generation=state.generation,
            requester_principal_hash=REQUESTER,
            requester_issuer=ISSUER,
            change_ticket="CHG-1",
            justification="reason",
            ttl_seconds=600,
            operation_id="unlock-request:unverified",
            actor_assurance="unverified",
        )
    with pytest.raises(AuditAnchorUnlockConflictError, match="HMAC"):
        await store.request_audit_anchor_unlock(
            expected_security_generation=state.generation,
            requester_principal_hash=REQUESTER,
            requester_issuer=ISSUER,
            change_ticket="CHG-1",
            justification="reason",
            ttl_seconds=600,
            operation_id="unlock-request:unkeyed",
            actor_assurance="oidc-human",
        )
    await store.close()


@pytest.mark.asyncio
async def test_decisions_are_append_only_rows(tmp_path) -> None:
    store = await _store(tmp_path)
    request = await _request(store)
    await store.decide_audit_anchor_unlock(
        request_id=request.request_id,
        expected_request_version=request.version,
        expected_security_generation=request.blocked_generation,
        approver_principal_hash=APPROVER,
        approver_issuer=ISSUER,
        approved=False,
        note="evidence is still inconsistent",
        operation_id="unlock-decision:reject",
        actor_assurance="oidc-human",
    )
    async with store.engine.connect() as connection:
        rows = list(
            (
                await connection.execute(
                    select(audit_anchor_unlock_decisions).where(
                        audit_anchor_unlock_decisions.c.request_id
                        == request.request_id
                    )
                )
            ).mappings()
        )
    assert len(rows) == 2
    assert {row["decision"] for row in rows} == {"requested", "rejected"}
    assert all(row["assurance"] == "oidc-human" for row in rows)
    await store.close()


@pytest.mark.asyncio
async def test_unlock_idempotency_key_is_bound_to_the_full_operation(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    request = await _request(store)
    replayed = await _request(store)
    assert replayed == request

    with pytest.raises(AuditAnchorUnlockConflictError, match="幂等键"):
        await store.request_audit_anchor_unlock(
            expected_security_generation=request.blocked_generation,
            requester_principal_hash=REQUESTER,
            requester_issuer=ISSUER,
            change_ticket="CHG-DIFFERENT",
            justification="安全团队已确认外部账本恢复",
            ttl_seconds=600,
            operation_id="unlock-request:test-1",
            actor_assurance="oidc-human",
        )

    decided = await store.decide_audit_anchor_unlock(
        request_id=request.request_id,
        expected_request_version=request.version,
        expected_security_generation=request.blocked_generation,
        approver_principal_hash=APPROVER,
        approver_issuer=ISSUER,
        approved=False,
        note="evidence still inconsistent",
        operation_id="unlock-decision:idempotent",
        actor_assurance="oidc-human",
    )
    replayed_decision = await store.decide_audit_anchor_unlock(
        request_id=request.request_id,
        expected_request_version=request.version,
        expected_security_generation=request.blocked_generation,
        approver_principal_hash=APPROVER,
        approver_issuer=ISSUER,
        approved=False,
        note="evidence still inconsistent",
        operation_id="unlock-decision:idempotent",
        actor_assurance="oidc-human",
    )
    assert replayed_decision == decided
    with pytest.raises(AuditAnchorUnlockConflictError, match="幂等键"):
        await store.decide_audit_anchor_unlock(
            request_id=request.request_id,
            expected_request_version=request.version,
            expected_security_generation=request.blocked_generation,
            approver_principal_hash=APPROVER,
            approver_issuer=ISSUER,
            approved=False,
            note="different note",
            operation_id="unlock-decision:idempotent",
            actor_assurance="oidc-human",
        )
    await store.close()


@pytest.mark.asyncio
async def test_strict_reconciliation_final_cas_is_the_only_unlock_path(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    _, approved = await _approve(store)
    claim = await store.claim_audit_anchor_unlock_reconciliation(
        owner_id="unlock-reconciler-a",
        ttl_seconds=60,
    )
    assert claim is not None
    assert claim.request.status == "reconciling"
    assert claim.request.version == approved.version + 1

    await _drain_outbox(store)
    inventory_revision = await store.audit_anchor_inventory_revision()
    completed = await store.complete_audit_anchor_unlock_reconciliation(
        claim,
        inventory_revision=inventory_revision,
        local_snapshot_hash="a" * 64,
        remote_snapshot_id="b" * 64,
        remote_snapshot_root="c" * 64,
        challenge="challenge-bound-inventory-proof-00000001",
        attested_at=datetime.now(UTC),
    )
    state = await store.audit_anchor_security_state()

    assert completed.status == "completed"
    assert completed.local_snapshot_hash == "a" * 64
    assert completed.challenge_sha256 == canonical_payload_hash(
        "challenge-bound-inventory-proof-00000001"
    )
    assert completed.lease_owner is None
    assert state is not None
    assert state.status == "healthy"
    assert state.write_blocked is False
    assert state.generation == approved.unlock_generation + 1
    audit = await store.list_audit_events(
        AUDIT_ANCHOR_SECURITY_STREAM_ID
    )
    assert audit[-1].event_type == (
        "audit_anchor.unlock_reconciliation_completed"
    )
    assert audit[-1].payload["inventory_revision"] == inventory_revision
    assert (
        await store.audit_anchor_inventory_revision()
        == inventory_revision + 1
    )
    await store.close()


@pytest.mark.asyncio
async def test_inventory_change_after_attestation_rejects_final_unlock(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    _, _ = await _approve(store)
    claim = await store.claim_audit_anchor_unlock_reconciliation(
        owner_id="unlock-reconciler-a",
        ttl_seconds=60,
    )
    assert claim is not None
    await _drain_outbox(store)
    attested_revision = await store.audit_anchor_inventory_revision()

    async with store.engine.begin() as connection:
        await store._append_audit_event(
            connection,
            incident_id=AUDIT_ANCHOR_SECURITY_STREAM_ID,
            operation_id="concurrent-security-audit-event",
            event_type="audit_anchor.concurrent_change",
            source_component="test",
            actor_type="system",
            actor_id="concurrent-test",
            actor_assurance="internal",
            subject_type="unlock_request",
            subject_id=claim.request.request_id,
            payload={"changed": True},
            allow_chain_create=True,
        )

    with pytest.raises(
        AuditAnchorUnlockConflictError,
        match="清单已经变化",
    ):
        await store.complete_audit_anchor_unlock_reconciliation(
            claim,
            inventory_revision=attested_revision,
            local_snapshot_hash="a" * 64,
            remote_snapshot_id="b" * 64,
            remote_snapshot_root="c" * 64,
            challenge="challenge-bound-inventory-proof-00000002",
            attested_at=datetime.now(UTC),
        )
    state = await store.audit_anchor_security_state()
    current = await store.get_audit_anchor_unlock_request(
        claim.request.request_id
    )
    assert state is not None
    assert state.status == "unlock_pending"
    assert state.write_blocked is True
    assert current is not None
    assert current.status == "reconciling"
    assert not any(
        event.event_type == "audit_anchor.unlock_reconciliation_completed"
        for event in await store.list_audit_events(
            AUDIT_ANCHOR_SECURITY_STREAM_ID
        )
    )
    await store.close()


@pytest.mark.asyncio
async def test_unlock_reconciliation_lease_fences_stale_worker(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    _, _ = await _approve(store)
    first = await store.claim_audit_anchor_unlock_reconciliation(
        owner_id="unlock-reconciler-a",
        ttl_seconds=60,
    )
    assert first is not None
    assert (
        await store.claim_audit_anchor_unlock_reconciliation(
            owner_id="unlock-reconciler-b",
            ttl_seconds=60,
        )
        is None
    )
    async with store.engine.begin() as connection:
        await connection.execute(
            update(audit_anchor_unlock_requests)
            .where(
                audit_anchor_unlock_requests.c.request_id
                == first.request.request_id
            )
            .values(
                lease_until=(
                    datetime.now(UTC) - timedelta(seconds=1)
                ).isoformat()
            )
        )
    second = await store.claim_audit_anchor_unlock_reconciliation(
        owner_id="unlock-reconciler-b",
        ttl_seconds=60,
    )
    assert second is not None
    assert second.generation == first.generation + 1

    await _drain_outbox(store)
    revision = await store.audit_anchor_inventory_revision()
    with pytest.raises(
        AuditAnchorUnlockConflictError,
        match="租约或安全代次",
    ):
        await store.complete_audit_anchor_unlock_reconciliation(
            first,
            inventory_revision=revision,
            local_snapshot_hash="a" * 64,
            remote_snapshot_id="b" * 64,
            remote_snapshot_root="c" * 64,
            challenge="challenge-bound-inventory-proof-00000003",
            attested_at=datetime.now(UTC),
        )
    state = await store.audit_anchor_security_state()
    assert state is not None
    assert state.status == "unlock_pending"
    assert state.write_blocked is True
    await store.close()


@pytest.mark.asyncio
async def test_definitive_reconciliation_failure_returns_to_integrity_blocked(
    tmp_path,
) -> None:
    store = await _store(tmp_path)
    _, _ = await _approve(store)
    claim = await store.claim_audit_anchor_unlock_reconciliation(
        owner_id="unlock-reconciler-a",
        ttl_seconds=60,
    )
    assert claim is not None
    failed = await store.fail_audit_anchor_unlock_reconciliation(
        claim,
        reason="strict_head_mismatch",
    )
    state = await store.audit_anchor_security_state()
    assert failed.status == "failed"
    assert failed.terminal_reason_sha256 == canonical_payload_hash(
        "strict_head_mismatch"
    )
    assert state is not None
    assert state.status == "integrity_blocked"
    assert state.write_blocked is True
    await store.close()
