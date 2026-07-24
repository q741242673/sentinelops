from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from sqlalchemy import delete, update

from sentinelops.anchor_crypto import sign_receipt, verify_receipt_signature
from sentinelops.anchor_receiver import (
    AnchorLedger,
    create_anchor_receiver_app,
)
from sentinelops.audit_anchor import (
    AuditAnchorDeliveryError,
    AuditAnchorReconciler,
    HttpAuditAnchorSink,
    StrictAuditAnchorReconciliationError,
)
from sentinelops.domain import Alert, IncidentRecord
from sentinelops.storage import ActionIntentConflictError, SqlIncidentStore
from sentinelops.storage.anchor import anchor_id
from sentinelops.storage.sqlalchemy import (
    audit_anchor_outbox,
    audit_anchor_security_state,
    audit_events,
    audit_heads,
    incidents,
)

AUDIT_KEY = "receiver-audit-key-0000000000000001"
TOKEN = "receiver-bearer-token-00000000000001"
INVENTORY_TOKEN = "receiver-inventory-token-00000000001"
SOURCE_ID = "receiver-test-cluster"
RECEIVER_ID = "receiver-test-ledger"
RECEIPT_KEY_ID = "receiver-signing-v1"


async def _claimed_anchors(tmp_path, count: int = 1):
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'source.db'}",
        audit_hmac_key=AUDIT_KEY,
        audit_key_id="receiver-audit-v1",
    )
    await store.setup()
    record = IncidentRecord(
        alert=Alert(
            name="ReceiverContract",
            namespace="sentinelops-tests",
            service="orders",
            severity="warning",
            summary="signed external anchor receiver",
        )
    )
    await store.save(record, expected_version=None, graph_state=None)
    for sequence in range(2, count + 1):
        async with store.engine.begin() as connection:
            await store._append_audit_event(
                connection,
                incident_id=record.id,
                operation_id=f"receiver-contract:{sequence}",
                event_type="contract.receiver",
                source_component="test",
                actor_type="system",
                actor_id="test",
                actor_assurance="internal",
                subject_type="incident",
                subject_id=record.id,
                payload={"sequence": sequence},
            )
    anchors = []
    for _ in range(count):
        claim = await store.claim_audit_anchor(
            owner_id="receiver-test",
            ttl_seconds=60,
        )
        assert claim is not None
        anchors.append(claim.anchor)
        await store.complete_audit_anchor(
            claim,
            receipt={"test": True},
        )
    await store.close()
    return anchors


async def _receiver(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    ledger = AnchorLedger(
        f"sqlite+aiosqlite:///{tmp_path / 'receiver.db'}",
        receiver_id=RECEIVER_ID,
        signing_key=private_key,
        signing_key_id=RECEIPT_KEY_ID,
    )
    await ledger.setup()
    app = create_anchor_receiver_app(
        ledger,
        bearer_token=TOKEN,
        inventory_bearer_token=INVENTORY_TOKEN,
        allowed_source_id=SOURCE_ID,
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://receiver.test",
    )
    sink = HttpAuditAnchorSink(
        "http://receiver.test/v1/anchors",
        bearer_token=TOKEN,
        source_id=SOURCE_ID,
        timeout_seconds=5,
        require_https=False,
        receipt_public_keys={RECEIPT_KEY_ID: private_key.public_key()},
        trusted_receiver_id=RECEIVER_ID,
        inventory_url="http://receiver.test/v1/anchor-inventory",
        inventory_bearer_token=INVENTORY_TOKEN,
        client=client,
    )
    return ledger, client, sink, private_key


@pytest.mark.asyncio
async def test_reference_receiver_returns_stable_signed_receipt(tmp_path) -> None:
    anchor = (await _claimed_anchors(tmp_path))[0]
    ledger, client, sink, private_key = await _receiver(tmp_path)
    try:
        first = await sink.publish(anchor)
        second = await sink.publish(anchor)
        stored = await ledger.latest(
            source_id=SOURCE_ID,
            incident_id=anchor.incident_id,
        )
    finally:
        await client.aclose()
        await ledger.close()

    assert first == second
    assert stored is not None
    assert stored["receipt_signature"] == first["receipt_signature"]
    assert stored["receipt_key_id"] == RECEIPT_KEY_ID
    assert verify_receipt_signature(
        stored,
        public_key=private_key.public_key(),
    )


@pytest.mark.asyncio
async def test_signed_inventory_detects_deleted_local_stream_and_closes_gate(
    tmp_path,
) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'reconcile-source.db'}",
        audit_hmac_key=AUDIT_KEY,
        audit_key_id="receiver-audit-v1",
    )
    await store.setup()
    record = IncidentRecord(
        alert=Alert(
            name="ReconciliationContract",
            namespace="sentinelops-tests",
            service="checkout",
            severity="critical",
            summary="detect a locally deleted anchored stream",
        )
    )
    await store.save(record, expected_version=None, graph_state=None)
    claim = await store.claim_audit_anchor(
        owner_id="reconcile-publisher",
        ttl_seconds=60,
    )
    assert claim is not None
    ledger, client, sink, _private_key = await _receiver(tmp_path)
    receipt = await sink.publish(claim.anchor)
    await store.complete_audit_anchor(claim, receipt=receipt)
    reconciler = AuditAnchorReconciler(
        store,
        sink,
        max_staleness_seconds=300,
    )

    assert await reconciler.reconcile_once() == "healthy"
    assert len(await sink.fetch_inventory()) == 1
    attestation = await reconciler.verify_strict_inventory()
    assert len(attestation.challenge) == 43
    assert len(attestation.local_snapshot_hash) == 64
    assert len(attestation.remote_snapshot_root) == 64
    async with store.engine.begin() as connection:
        await connection.execute(
            delete(audit_anchor_outbox).where(
                audit_anchor_outbox.c.incident_id == record.id
            )
        )
        await connection.execute(
            delete(audit_events).where(
                audit_events.c.incident_id == record.id
            )
        )
        await connection.execute(
            delete(audit_heads).where(
                audit_heads.c.incident_id == record.id
            )
        )
        await connection.execute(
            delete(incidents).where(incidents.c.id == record.id)
        )

    assert await reconciler.reconcile_once() == "integrity_blocked"
    state = await store.audit_anchor_security_state()
    assert state is not None
    assert state.status == "integrity_blocked"
    assert state.write_blocked is True
    async with store.engine.begin() as connection:
        with pytest.raises(ActionIntentConflictError, match="安全闸门"):
            await store._assert_dispatch_allowed(connection, record.id)
    # The integrity lock is sticky; a later write cannot clear it.
    sticky = await store.set_audit_anchor_security_state(
        status="healthy",
        write_blocked=False,
        reason="must_not_auto_clear",
        successful=True,
    )
    assert sticky.status == "integrity_blocked"
    assert sticky.write_blocked is True

    await client.aclose()
    await ledger.close()
    await store.close()


@pytest.mark.asyncio
async def test_strict_reconciliation_rejects_local_change_during_scan(
    tmp_path,
) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'strict-race-source.db'}",
        audit_hmac_key=AUDIT_KEY,
        audit_key_id="receiver-audit-v1",
    )
    await store.setup()
    record = IncidentRecord(
        alert=Alert(
            name="StrictRace",
            namespace="sentinelops-tests",
            service="checkout",
            severity="critical",
            summary="local audit revision changes during strict scan",
        )
    )
    await store.save(record, expected_version=None, graph_state=None)
    first = await store.claim_audit_anchor(owner_id="strict-race", ttl_seconds=60)
    assert first is not None
    ledger, client, sink, _private_key = await _receiver(tmp_path)
    first_receipt = await sink.publish(first.anchor)
    await store.complete_audit_anchor(first, receipt=first_receipt)

    class MutatingSink:
        async def fetch_inventory_snapshot(self):
            old_snapshot = await sink.fetch_inventory_snapshot()
            async with store.engine.begin() as connection:
                await store._append_audit_event(
                    connection,
                    incident_id=record.id,
                    operation_id="strict-race:second",
                    event_type="contract.strict-race",
                    source_component="test",
                    actor_type="system",
                    actor_id="test",
                    actor_assurance="internal",
                    subject_type="incident",
                    subject_id=record.id,
                    payload={"changed": True},
                )
            second = await store.claim_audit_anchor(
                owner_id="strict-race",
                ttl_seconds=60,
            )
            assert second is not None
            receipt = await sink.publish(second.anchor)
            await store.complete_audit_anchor(second, receipt=receipt)
            return old_snapshot

    reconciler = AuditAnchorReconciler(
        store,
        MutatingSink(),  # type: ignore[arg-type]
        max_staleness_seconds=300,
    )
    try:
        with pytest.raises(
            StrictAuditAnchorReconciliationError,
            match="strict_local_snapshot_changed",
        ):
            await reconciler.verify_strict_inventory()
    finally:
        await client.aclose()
        await ledger.close()
        await store.close()


@pytest.mark.asyncio
async def test_two_person_unlock_requires_fresh_signed_inventory_before_cas(
    tmp_path,
) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'unlock-source.db'}",
        audit_hmac_key=AUDIT_KEY,
        audit_key_id="receiver-audit-v1",
    )
    await store.setup()
    record = IncidentRecord(
        alert=Alert(
            name="UnlockContract",
            namespace="sentinelops-tests",
            service="checkout",
            severity="critical",
            summary="strict two-person unlock contract",
        )
    )
    await store.save(record, expected_version=None, graph_state=None)
    ledger, client, sink, _private_key = await _receiver(tmp_path)

    async def publish_all() -> None:
        while True:
            anchor_claim = await store.claim_audit_anchor(
                owner_id="unlock-publisher",
                ttl_seconds=60,
            )
            if anchor_claim is None:
                return
            receipt = await sink.publish(anchor_claim.anchor)
            await store.complete_audit_anchor(
                anchor_claim,
                receipt=receipt,
            )

    await publish_all()
    blocked = await store.set_audit_anchor_security_state(
        status="integrity_blocked",
        write_blocked=True,
        reason="operator_confirmed_external_recovery_required",
        successful=False,
    )
    requester = hashlib.sha256(b"issuer\0requester").hexdigest()
    approver = hashlib.sha256(b"issuer\0approver").hexdigest()
    unlock_request = await store.request_audit_anchor_unlock(
        expected_security_generation=blocked.generation,
        requester_principal_hash=requester,
        requester_issuer="https://identity.example.test",
        change_ticket="CHG-UNLOCK-1",
        justification="independent ledger has been restored",
        ttl_seconds=600,
        operation_id="strict-unlock-request",
        actor_assurance="oidc-human",
    )
    await store.decide_audit_anchor_unlock(
        request_id=unlock_request.request_id,
        expected_request_version=unlock_request.version,
        expected_security_generation=blocked.generation,
        approver_principal_hash=approver,
        approver_issuer="https://identity.example.test",
        approved=True,
        note="second operator approved strict reconciliation",
        operation_id="strict-unlock-approval",
        actor_assurance="oidc-human",
    )
    reconciler = AuditAnchorReconciler(
        store,
        sink,
        max_staleness_seconds=300,
    )
    try:
        first = await reconciler.reconcile_unlock_once(
            owner_id="unlock-reconciler",
            lease_ttl_seconds=60,
        )
        assert first == "unlock_waiting_for_stable_inventory"
        still_blocked = await store.audit_anchor_security_state()
        assert still_blocked is not None
        assert still_blocked.status == "unlock_pending"
        assert still_blocked.write_blocked is True

        await publish_all()
        second = await reconciler.reconcile_unlock_once(
            owner_id="unlock-reconciler",
            lease_ttl_seconds=60,
        )
        final_state = await store.audit_anchor_security_state()
        completed = await store.get_audit_anchor_unlock_request(
            unlock_request.request_id
        )
    finally:
        await client.aclose()
        await ledger.close()
        await store.close()

    assert second == "healthy"
    assert final_state is not None
    assert final_state.status == "healthy"
    assert final_state.write_blocked is False
    assert completed is not None
    assert completed.status == "completed"
    assert completed.remote_snapshot_id is not None
    assert completed.challenge_sha256 is not None


@pytest.mark.asyncio
async def test_inventory_is_bound_to_a_fresh_client_challenge(tmp_path) -> None:
    anchor = (await _claimed_anchors(tmp_path))[0]
    ledger, receiver_client, sink, private_key = await _receiver(tmp_path)
    await sink.publish(anchor)
    old_challenge = "A" * 43
    captured = await receiver_client.get(
        "/v1/anchor-inventory",
        params={
            "source_id": SOURCE_ID,
            "challenge": old_challenge,
        },
        headers={"Authorization": f"Bearer {INVENTORY_TOKEN}"},
    )
    assert captured.status_code == 200
    assert captured.json()["challenge"] == old_challenge

    def replay(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=captured.content,
            headers={"Content-Type": "application/json"},
        )

    replay_client = httpx.AsyncClient(
        transport=httpx.MockTransport(replay)
    )
    replay_sink = HttpAuditAnchorSink(
        "http://receiver.test/v1/anchors",
        bearer_token=TOKEN,
        source_id=SOURCE_ID,
        timeout_seconds=5,
        require_https=False,
        receipt_public_keys={RECEIPT_KEY_ID: private_key.public_key()},
        trusted_receiver_id=RECEIVER_ID,
        inventory_url="http://receiver.test/v1/anchor-inventory",
        inventory_bearer_token=INVENTORY_TOKEN,
        client=replay_client,
    )
    try:
        with pytest.raises(
            AuditAnchorDeliveryError,
            match="invalid_inventory_contract",
        ):
            await replay_sink.fetch_inventory()
    finally:
        await replay_client.aclose()
        await receiver_client.aclose()
        await ledger.close()


@pytest.mark.asyncio
async def test_reconciliation_network_grace_expires_fail_closed(tmp_path) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'reconcile-grace.db'}"
    )
    await store.setup()

    class Inventory:
        failing = False

        async def fetch_inventory(self):
            if self.failing:
                raise AuditAnchorDeliveryError(
                    "inventory_transport_error",
                    retryable=True,
                )
            return []

    inventory = Inventory()
    reconciler = AuditAnchorReconciler(
        store,
        inventory,  # type: ignore[arg-type]
        max_staleness_seconds=300,
    )
    assert await reconciler.reconcile_once() == "healthy"
    inventory.failing = True
    assert await reconciler.reconcile_once() == "degraded"
    fresh = await store.audit_anchor_security_state()
    assert fresh is not None
    assert fresh.write_blocked is False

    async with store.engine.begin() as connection:
        await connection.execute(
            update(audit_anchor_security_state)
            .where(
                audit_anchor_security_state.c.scope_id
                == "external-audit-anchor"
            )
            .values(last_success_at="1970-01-01T00:00:00+00:00")
        )
    assert await reconciler.reconcile_once() == "degraded"
    stale = await store.audit_anchor_security_state()
    assert stale is not None
    assert stale.write_blocked is True
    await store.close()


@pytest.mark.asyncio
async def test_reconciler_reports_the_actual_sticky_gate_state(tmp_path) -> None:
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'sticky-state.db'}"
    )
    await store.setup()
    await store.set_audit_anchor_security_state(
        status="integrity_blocked",
        write_blocked=True,
        reason="manual_integrity_test",
        successful=False,
    )

    class EmptyInventory:
        async def fetch_inventory(self):
            return []

    reconciler = AuditAnchorReconciler(
        store,
        EmptyInventory(),  # type: ignore[arg-type]
        max_staleness_seconds=300,
    )

    assert await reconciler.reconcile_once() == "integrity_blocked"
    state = await store.audit_anchor_security_state()
    assert state is not None
    assert state.status == "integrity_blocked"
    assert state.write_blocked is True
    await store.close()


@pytest.mark.asyncio
async def test_receiver_enforces_monotonic_predecessor_and_source_binding(
    tmp_path,
) -> None:
    first, second, third = await _claimed_anchors(tmp_path, count=3)
    ledger, client, sink, _private_key = await _receiver(tmp_path)
    try:
        await sink.publish(first)
        with pytest.raises(AuditAnchorDeliveryError, match="http_409"):
            await sink.publish(third)
        forged_hash = "f" * 64
        fork = replace(
            second,
            head_hash=forged_hash,
            anchor_id=anchor_id(
                second.incident_id,
                second.sequence,
                forged_hash,
            ),
        )
        await sink.publish(second)
        with pytest.raises(AuditAnchorDeliveryError, match="http_409"):
            await sink.publish(fork)
        await sink.publish(third)
        response = await client.post(
            "/v1/anchors",
            content=json.dumps(
                {
                    "protocol_version": "sentinelops.audit-anchor.v1",
                    "anchor_id": second.anchor_id,
                    "source_id": "another-cluster",
                    "incident_id": second.incident_id,
                    "sequence": second.sequence,
                    "head_hash": second.head_hash,
                    "head_auth_tag": second.audit_auth_tag,
                    "head_committed_at": second.audit_committed_at.isoformat(),
                    "audit": {
                        "auth_algorithm": second.audit_auth_algorithm,
                        "key_id": second.audit_key_id,
                    },
                    "previous_anchor_id": second.previous_anchor_id,
                    "bootstrap_checkpoint": False,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json",
                "Idempotency-Key": second.anchor_id,
            },
        )
    finally:
        await client.aclose()
        await ledger.close()

    assert response.status_code == 403
    assert response.json()["detail"] == "source_not_allowed"


@pytest.mark.asyncio
async def test_signed_receipt_tampering_is_rejected(tmp_path) -> None:
    anchor = (await _claimed_anchors(tmp_path))[0]
    ledger, receiver_client, _sink, private_key = await _receiver(tmp_path)
    valid_sink = HttpAuditAnchorSink(
        "http://receiver.test/v1/anchors",
        bearer_token=TOKEN,
        source_id=SOURCE_ID,
        timeout_seconds=5,
        require_https=False,
        receipt_public_keys={RECEIPT_KEY_ID: private_key.public_key()},
        trusted_receiver_id=RECEIVER_ID,
        client=receiver_client,
    )
    valid = await valid_sink.publish(anchor)

    def handler(_request: httpx.Request) -> httpx.Response:
        tampered = {**valid, "accepted_at": "2026-07-23T00:00:00Z"}
        return httpx.Response(
            200,
            json=tampered,
            headers={"Content-Type": "application/json"},
        )

    attacker_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    )
    tampered_sink = HttpAuditAnchorSink(
        "http://receiver.test/v1/anchors",
        bearer_token=TOKEN,
        source_id=SOURCE_ID,
        timeout_seconds=5,
        require_https=False,
        receipt_public_keys={RECEIPT_KEY_ID: private_key.public_key()},
        trusted_receiver_id=RECEIVER_ID,
        client=attacker_client,
    )
    try:
        with pytest.raises(Exception, match="invalid_receipt_signature"):
            await tampered_sink.publish(anchor)
    finally:
        await attacker_client.aclose()
        await receiver_client.aclose()
        await ledger.close()


@pytest.mark.asyncio
async def test_receiver_rejects_duplicate_json_keys_and_wrong_token(
    tmp_path,
) -> None:
    anchor = (await _claimed_anchors(tmp_path))[0]
    ledger, client, _sink, _private_key = await _receiver(tmp_path)
    duplicate_body = (
        '{"protocol_version":"sentinelops.audit-anchor.v1",'
        '"protocol_version":"sentinelops.audit-anchor.v1"}'
    )
    try:
        duplicate = await client.post(
            "/v1/anchors",
            content=duplicate_body,
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json",
                "Idempotency-Key": anchor.anchor_id,
            },
        )
        unauthorized = await client.get(
            "/v1/anchors/latest",
            params={
                "source_id": SOURCE_ID,
                "incident_id": anchor.incident_id,
            },
            headers={"Authorization": "Bearer wrong"},
        )
    finally:
        await client.aclose()
        await ledger.close()

    assert duplicate.status_code == 422
    assert unauthorized.status_code == 401


def test_receipt_key_rotation_keeps_old_receipts_verifiable() -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    old_receipt = {
        "protocol_version": "sentinelops.audit-anchor-receipt.v2",
        "receipt_key_id": "old-key",
        "receipt_id": "old-receipt",
    }
    old_receipt["receipt_signature"] = sign_receipt(
        old_receipt,
        private_key=old_key,
    )
    new_receipt = {
        "protocol_version": "sentinelops.audit-anchor-receipt.v2",
        "receipt_key_id": "new-key",
        "receipt_id": "new-receipt",
    }
    new_receipt["receipt_signature"] = sign_receipt(
        new_receipt,
        private_key=new_key,
    )

    assert verify_receipt_signature(
        old_receipt,
        public_key=old_key.public_key(),
    )
    assert verify_receipt_signature(
        new_receipt,
        public_key=new_key.public_key(),
    )
    assert not verify_receipt_signature(
        old_receipt,
        public_key=new_key.public_key(),
    )
