from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sentinelops.anchor_crypto import (
    verify_inventory_signature,
    verify_receipt_signature,
)
from sentinelops.storage import (
    AuditAnchor,
    AuditAnchorClaim,
    AuditAnchorUnlockConflictError,
    IncidentStore,
)
from sentinelops.storage.anchor import anchor_id
from sentinelops.storage.audit import canonical_payload_hash
from sentinelops.worker_health import run_with_health_pulse

logger = logging.getLogger(__name__)

REQUEST_PROTOCOL = "sentinelops.audit-anchor.v1"
RECEIPT_PROTOCOL = "sentinelops.audit-anchor-receipt.v1"
SIGNED_RECEIPT_PROTOCOL = "sentinelops.audit-anchor-receipt.v2"
INVENTORY_PROTOCOL = "sentinelops.audit-anchor-inventory.v2"
MAX_RECEIPT_BYTES = 65_536
MAX_INVENTORY_BYTES = 1_048_576
MAX_INVENTORY_AGE_SECONDS = 60


class AuditAnchorDeliveryError(RuntimeError):
    def __init__(self, category: str, *, retryable: bool) -> None:
        super().__init__(category)
        self.category = category
        self.retryable = retryable


class LocalAuditIntegrityError(RuntimeError):
    pass


class StrictAuditAnchorReconciliationError(RuntimeError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class VerifiedAnchorInventory:
    items: list[dict[str, object]]
    snapshot_id: str
    snapshot_root: str
    challenge: str
    generated_at: datetime


@dataclass(frozen=True)
class StrictReconciliationAttestation:
    local_snapshot_hash: str
    inventory_revision: int
    remote_snapshot_id: str
    remote_snapshot_root: str
    challenge: str
    generated_at: datetime


def anchor_request_payload(
    anchor: AuditAnchor,
    *,
    source_id: str,
) -> dict[str, object]:
    return {
        "protocol_version": REQUEST_PROTOCOL,
        "anchor_id": anchor.anchor_id,
        "source_id": source_id,
        "incident_id": anchor.incident_id,
        "sequence": anchor.sequence,
        "head_hash": anchor.head_hash,
        "head_auth_tag": anchor.audit_auth_tag,
        "head_committed_at": anchor.audit_committed_at.isoformat(),
        "audit": {
            "auth_algorithm": anchor.audit_auth_algorithm,
            "key_id": anchor.audit_key_id,
        },
        "previous_anchor_id": anchor.previous_anchor_id,
        "bootstrap_checkpoint": (
            anchor.sequence > 1 and anchor.previous_anchor_id is None
        ),
    }


def canonical_anchor_request(
    anchor: AuditAnchor,
    *,
    source_id: str,
) -> bytes:
    return json.dumps(
        anchor_request_payload(anchor, source_id=source_id),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


class HttpAuditAnchorSink:
    def __init__(
        self,
        url: str,
        *,
        bearer_token: str,
        source_id: str,
        timeout_seconds: float,
        require_https: bool,
        receipt_public_keys: Mapping[str, Ed25519PublicKey] | None = None,
        trusted_receiver_id: str | None = None,
        inventory_url: str | None = None,
        inventory_bearer_token: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlsplit(url)
        allowed_schemes = {"https"} if require_https else {"http", "https"}
        if (
            parsed.scheme.casefold() not in allowed_schemes
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            requirement = "固定 HTTPS URL" if require_https else "固定 HTTP(S) URL"
            raise ValueError(
                f"审计锚定地址必须是无账号、query 和 fragment 的{requirement}"
            )
        if not bearer_token:
            raise ValueError("审计锚定服务需要独立 Bearer Token")
        self.url = url
        if inventory_url is not None:
            inventory_parsed = urlsplit(inventory_url)
            if (
                inventory_parsed.scheme.casefold() not in allowed_schemes
                or not inventory_parsed.hostname
                or inventory_parsed.username is not None
                or inventory_parsed.password is not None
                or inventory_parsed.query
                or inventory_parsed.fragment
            ):
                raise ValueError("审计锚点 Inventory 地址不安全")
        self.inventory_url = inventory_url
        self.inventory_bearer_token = (
            inventory_bearer_token or bearer_token
        )
        self.bearer_token = bearer_token
        self.source_id = source_id
        self.receipt_public_keys = dict(receipt_public_keys or {})
        self.trusted_receiver_id = trusted_receiver_id
        if self.receipt_public_keys and not trusted_receiver_id:
            raise ValueError(
                "Signed receipt verification requires a trusted receiver ID"
            )
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            headers={"Accept-Encoding": "identity"},
        )

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def publish(self, anchor: AuditAnchor) -> dict[str, object]:
        request_payload = anchor_request_payload(
            anchor,
            source_id=self.source_id,
        )
        request_body = json.dumps(
            request_payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        try:
            response = await self.client.post(
                self.url,
                content=request_body,
                headers={
                    "Authorization": f"Bearer {self.bearer_token}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": anchor.anchor_id,
                },
            )
        except httpx.HTTPError as exc:
            raise AuditAnchorDeliveryError(
                "transport_error",
                retryable=True,
            ) from exc

        if response.status_code in {408, 429} or response.status_code >= 500:
            raise AuditAnchorDeliveryError(
                f"http_{response.status_code}",
                retryable=True,
            )
        if response.status_code not in {200, 201}:
            raise AuditAnchorDeliveryError(
                f"http_{response.status_code}",
                retryable=False,
            )
        content_encoding = response.headers.get("content-encoding", "identity")
        if content_encoding.casefold() != "identity":
            raise AuditAnchorDeliveryError(
                "compressed_receipt",
                retryable=False,
            )
        content_type = response.headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip().casefold() != "application/json":
            raise AuditAnchorDeliveryError(
                "invalid_receipt_content_type",
                retryable=False,
            )
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise AuditAnchorDeliveryError(
                    "invalid_receipt_length",
                    retryable=False,
                ) from exc
            if declared_length > MAX_RECEIPT_BYTES:
                raise AuditAnchorDeliveryError(
                    "receipt_too_large",
                    retryable=False,
                )
        if len(response.content) > MAX_RECEIPT_BYTES:
            raise AuditAnchorDeliveryError(
                "receipt_too_large",
                retryable=False,
            )
        try:
            receipt = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AuditAnchorDeliveryError(
                "invalid_receipt_json",
                retryable=False,
            ) from exc
        if not isinstance(receipt, dict):
            raise AuditAnchorDeliveryError(
                "invalid_receipt_shape",
                retryable=False,
            )
        expected = {
            "protocol_version": (
                SIGNED_RECEIPT_PROTOCOL
                if self.receipt_public_keys
                else RECEIPT_PROTOCOL
            ),
            "anchor_id": anchor.anchor_id,
            "source_id": self.source_id,
            "incident_id": anchor.incident_id,
            "sequence": anchor.sequence,
            "head_hash": anchor.head_hash,
            "head_auth_tag": anchor.audit_auth_tag,
            "head_committed_at": anchor.audit_committed_at.isoformat(),
            "audit": request_payload["audit"],
            "previous_anchor_id": anchor.previous_anchor_id,
            "bootstrap_checkpoint": request_payload["bootstrap_checkpoint"],
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise AuditAnchorDeliveryError(
                "receipt_echo_mismatch",
                retryable=False,
            )
        if receipt.get("status") not in {"accepted", "duplicate"}:
            raise AuditAnchorDeliveryError(
                "receipt_not_accepted",
                retryable=False,
            )
        receipt_id = receipt.get("receipt_id")
        if not isinstance(receipt_id, str) or not receipt_id.strip():
            raise AuditAnchorDeliveryError(
                "missing_receipt_id",
                retryable=False,
            )
        safe_receipt: dict[str, object] = {
            **expected,
            "status": receipt["status"],
            "receipt_id": receipt_id,
        }
        if self.receipt_public_keys:
            self._verify_signed_receipt(
                receipt,
                request_sha256=hashlib.sha256(request_body).hexdigest(),
            )
            safe_receipt.update(
                {
                    "request_sha256": receipt["request_sha256"],
                    "receiver_id": receipt["receiver_id"],
                    "signature_algorithm": receipt[
                        "signature_algorithm"
                    ],
                    "receipt_key_id": receipt["receipt_key_id"],
                    "receipt_signature": receipt["receipt_signature"],
                }
            )
        accepted_at = receipt.get("accepted_at")
        if isinstance(accepted_at, str) and len(accepted_at) <= 64:
            safe_receipt["accepted_at"] = accepted_at
        return safe_receipt

    def _verify_signed_receipt(
        self,
        receipt: dict[str, object],
        *,
        request_sha256: str,
    ) -> None:
        if (
            receipt.get("receiver_id") != self.trusted_receiver_id
            or receipt.get("request_sha256") != request_sha256
            or receipt.get("signature_algorithm") != "ed25519"
        ):
            raise AuditAnchorDeliveryError(
                "signed_receipt_binding_mismatch",
                retryable=False,
            )
        key_id = receipt.get("receipt_key_id")
        if not isinstance(key_id, str):
            raise AuditAnchorDeliveryError(
                "missing_receipt_key_id",
                retryable=False,
            )
        public_key = self.receipt_public_keys.get(key_id)
        if public_key is None:
            raise AuditAnchorDeliveryError(
                "unknown_receipt_key_id",
                retryable=True,
            )
        if not verify_receipt_signature(receipt, public_key=public_key):
            raise AuditAnchorDeliveryError(
                "invalid_receipt_signature",
                retryable=False,
            )

    async def fetch_inventory(self) -> list[dict[str, object]]:
        return (await self.fetch_inventory_snapshot()).items

    async def fetch_inventory_snapshot(self) -> VerifiedAnchorInventory:
        if not self.inventory_url or not self.receipt_public_keys:
            raise AuditAnchorDeliveryError(
                "inventory_not_configured",
                retryable=False,
            )
        challenge = secrets.token_urlsafe(32)
        try:
            response = await self.client.get(
                self.inventory_url,
                params={
                    "source_id": self.source_id,
                    "challenge": challenge,
                },
                headers={
                    "Authorization": (
                        f"Bearer {self.inventory_bearer_token}"
                    ),
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise AuditAnchorDeliveryError(
                "inventory_transport_error",
                retryable=True,
            ) from exc
        if response.status_code in {408, 429} or response.status_code >= 500:
            raise AuditAnchorDeliveryError(
                f"inventory_http_{response.status_code}",
                retryable=True,
            )
        if response.status_code != 200:
            raise AuditAnchorDeliveryError(
                f"inventory_http_{response.status_code}",
                retryable=False,
            )
        if response.headers.get(
            "content-encoding",
            "identity",
        ).casefold() != "identity":
            raise AuditAnchorDeliveryError(
                "compressed_inventory",
                retryable=False,
            )
        if (
            response.headers.get("content-type", "")
            .split(";", 1)[0]
            .strip()
            .casefold()
            != "application/json"
        ):
            raise AuditAnchorDeliveryError(
                "invalid_inventory_content_type",
                retryable=False,
            )
        if len(response.content) > MAX_INVENTORY_BYTES:
            raise AuditAnchorDeliveryError(
                "inventory_too_large",
                retryable=False,
            )
        try:
            inventory = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AuditAnchorDeliveryError(
                "invalid_inventory_json",
                retryable=False,
            ) from exc
        if (
            not isinstance(inventory, dict)
            or inventory.get("protocol_version")
            != INVENTORY_PROTOCOL
            or inventory.get("source_id") != self.source_id
            or inventory.get("signature_algorithm") != "ed25519"
            or inventory.get("challenge") != challenge
        ):
            raise AuditAnchorDeliveryError(
                "invalid_inventory_contract",
                retryable=False,
            )
        generated_at_raw = inventory.get("generated_at")
        if not isinstance(generated_at_raw, str):
            raise AuditAnchorDeliveryError(
                "invalid_inventory_freshness",
                retryable=False,
            )
        try:
            generated_at = datetime.fromisoformat(generated_at_raw)
        except ValueError as exc:
            raise AuditAnchorDeliveryError(
                "invalid_inventory_freshness",
                retryable=False,
            ) from exc
        if generated_at.tzinfo is None:
            raise AuditAnchorDeliveryError(
                "invalid_inventory_freshness",
                retryable=False,
            )
        age_seconds = (
            datetime.now(UTC) - generated_at.astimezone(UTC)
        ).total_seconds()
        if age_seconds < -10 or age_seconds > MAX_INVENTORY_AGE_SECONDS:
            raise AuditAnchorDeliveryError(
                "invalid_inventory_freshness",
                retryable=False,
            )
        items = inventory.get("items")
        if (
            not isinstance(items, list)
            or len(items) > 10_000
            or inventory.get("total_streams") != len(items)
            or inventory.get("snapshot_root")
            != canonical_payload_hash(items)
        ):
            raise AuditAnchorDeliveryError(
                "invalid_inventory_snapshot",
                retryable=False,
            )
        snapshot_id = hashlib.sha256(
            self.source_id.encode()
            + b"\0"
            + challenge.encode()
            + b"\0"
            + generated_at_raw.encode()
            + b"\0"
            + str(len(items)).encode()
            + b"\0"
            + str(inventory["snapshot_root"]).encode()
        ).hexdigest()
        if inventory.get("snapshot_id") != snapshot_id:
            raise AuditAnchorDeliveryError(
                "invalid_inventory_snapshot_id",
                retryable=False,
            )
        key_id = inventory.get("inventory_key_id")
        public_key = (
            self.receipt_public_keys.get(key_id)
            if isinstance(key_id, str)
            else None
        )
        if public_key is None:
            raise AuditAnchorDeliveryError(
                "unknown_inventory_key_id",
                retryable=True,
            )
        if not verify_inventory_signature(
            inventory,
            public_key=public_key,
        ):
            raise AuditAnchorDeliveryError(
                "invalid_inventory_signature",
                retryable=False,
            )
        seen_incidents: set[str] = set()
        verified: list[dict[str, object]] = []
        for item in items:
            if not isinstance(item, dict):
                raise AuditAnchorDeliveryError(
                    "invalid_inventory_item",
                    retryable=False,
                )
            incident_id = item.get("incident_id")
            sequence = item.get("sequence")
            head_hash = item.get("head_hash")
            if (
                not isinstance(incident_id, str)
                or incident_id in seen_incidents
                or not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or sequence < 1
                or not isinstance(head_hash, str)
                or item.get("anchor_id")
                != anchor_id(incident_id, sequence, head_hash)
                or item.get("source_id") != self.source_id
                or item.get("protocol_version")
                != SIGNED_RECEIPT_PROTOCOL
            ):
                raise AuditAnchorDeliveryError(
                    "invalid_inventory_item",
                    retryable=False,
                )
            request_payload = {
                key: item.get(key)
                for key in (
                    "anchor_id",
                    "source_id",
                    "incident_id",
                    "sequence",
                    "head_hash",
                    "head_auth_tag",
                    "head_committed_at",
                    "audit",
                    "previous_anchor_id",
                    "bootstrap_checkpoint",
                )
            }
            request_payload["protocol_version"] = REQUEST_PROTOCOL
            request_sha256 = canonical_payload_hash(request_payload)
            self._verify_signed_receipt(
                item,
                request_sha256=request_sha256,
            )
            seen_incidents.add(incident_id)
            verified.append(item)
        return VerifiedAnchorInventory(
            items=verified,
            snapshot_id=snapshot_id,
            snapshot_root=str(inventory["snapshot_root"]),
            challenge=challenge,
            generated_at=generated_at.astimezone(UTC),
        )


class AuditAnchorPublisher:
    def __init__(
        self,
        store: IncidentStore,
        sink: HttpAuditAnchorSink,
        *,
        owner_id: str,
        claim_ttl_seconds: float,
        poll_interval_seconds: float,
        retry_base_seconds: float,
        retry_max_seconds: float,
        reconciler: AuditAnchorReconciler | None = None,
        reconcile_interval_seconds: float = 60,
        health_callback: Callable[[], None] | None = None,
        health_interval_seconds: float = 5,
    ) -> None:
        self.store = store
        self.sink = sink
        self.owner_id = owner_id
        self.claim_ttl_seconds = claim_ttl_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self.retry_base_seconds = retry_base_seconds
        self.retry_max_seconds = retry_max_seconds
        self.reconciler = reconciler
        self.reconcile_interval_seconds = reconcile_interval_seconds
        self.health_callback = health_callback
        self.health_interval_seconds = health_interval_seconds

    async def run_once(self) -> bool:
        claim = await self.store.claim_audit_anchor(
            owner_id=self.owner_id,
            ttl_seconds=self.claim_ttl_seconds,
        )
        if claim is None:
            self._heartbeat()
            return False
        try:
            await self._verify_claim(claim)
        except LocalAuditIntegrityError as exc:
            await self.store.dead_letter_audit_anchor(
                claim,
                error=str(exc),
            )
            self._heartbeat()
            return True

        try:
            receipt = await self.sink.publish(claim.anchor)
        except AuditAnchorDeliveryError as exc:
            if exc.retryable:
                await self.store.retry_audit_anchor(
                    claim,
                    error=exc.category,
                    retry_after_seconds=self._retry_delay(claim),
                )
            else:
                await self.store.dead_letter_audit_anchor(
                    claim,
                    error=exc.category,
                )
            self._heartbeat()
            return True
        await self.store.complete_audit_anchor(claim, receipt=receipt)
        self._heartbeat()
        return True

    async def run_forever(self) -> None:
        await run_with_health_pulse(
            self._run_work_loop(),
            callback=self.health_callback,
            interval_seconds=self.health_interval_seconds,
        )

    async def _run_work_loop(self) -> None:
        next_reconcile_at = 0.0
        while True:
            now = asyncio.get_running_loop().time()
            if self.reconciler is not None and now >= next_reconcile_at:
                try:
                    await self.reconciler.reconcile_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(
                        "audit anchor reconciliation failed safely: %s",
                        type(exc).__name__,
                    )
                    await self._close_write_gate_after_reconcile_failure(exc)
                next_reconcile_at = now + self.reconcile_interval_seconds
            try:
                processed = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "audit anchor publisher iteration failed safely: %s",
                    type(exc).__name__,
                )
                processed = False
            if not processed:
                if self.reconciler is not None:
                    try:
                        await self.reconciler.reconcile_unlock_once(
                            owner_id=f"{self.owner_id}:unlock",
                            lease_ttl_seconds=self.claim_ttl_seconds,
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.warning(
                            "audit anchor unlock reconciliation failed safely: %s",
                            type(exc).__name__,
                        )
                await asyncio.sleep(self.poll_interval_seconds)

    async def _close_write_gate_after_reconcile_failure(
        self,
        exc: Exception,
    ) -> None:
        try:
            await self.store.set_audit_anchor_security_state(
                status="degraded",
                write_blocked=True,
                reason=(
                    "publisher_reconciliation_failed:"
                    f"{type(exc).__name__}"
                ),
                successful=False,
            )
        except Exception as gate_exc:
            logger.error(
                "audit anchor write gate could not be persisted: %s",
                type(gate_exc).__name__,
            )

    async def _verify_claim(self, claim: AuditAnchorClaim) -> None:
        anchor = claim.anchor
        verification = await self.store.verify_audit_chain(
            anchor.incident_id
        )
        if not verification.valid:
            raise LocalAuditIntegrityError("local_chain_invalid")
        events = await self.store.list_audit_events(anchor.incident_id)
        if anchor.sequence < 1 or anchor.sequence > len(events):
            raise LocalAuditIntegrityError("anchor_sequence_missing")
        event = events[anchor.sequence - 1]
        if (
            event.sequence != anchor.sequence
            or event.entry_hash != anchor.head_hash
            or event.key_id != anchor.audit_key_id
            or event.auth_algorithm != anchor.audit_auth_algorithm
            or event.auth_tag != anchor.audit_auth_tag
            or event.committed_at != anchor.audit_committed_at.isoformat()
            or anchor.anchor_id
            != anchor_id(
                anchor.incident_id,
                anchor.sequence,
                anchor.head_hash,
            )
        ):
            raise LocalAuditIntegrityError("anchor_event_mismatch")
        if anchor.previous_anchor_id is not None:
            if anchor.sequence <= 1:
                raise LocalAuditIntegrityError("invalid_anchor_predecessor")
            previous = events[anchor.sequence - 2]
            expected_previous = anchor_id(
                anchor.incident_id,
                previous.sequence,
                previous.entry_hash,
            )
            if anchor.previous_anchor_id != expected_previous:
                raise LocalAuditIntegrityError("anchor_predecessor_mismatch")

    def _retry_delay(self, claim: AuditAnchorClaim) -> float:
        exponent = min(max(claim.anchor.attempt_count - 1, 0), 16)
        return min(
            self.retry_max_seconds,
            self.retry_base_seconds * (2**exponent),
        )

    def _heartbeat(self) -> None:
        if self.health_callback is not None:
            self.health_callback()


class AuditAnchorReconciler:
    def __init__(
        self,
        store: IncidentStore,
        sink: HttpAuditAnchorSink,
        *,
        max_staleness_seconds: float,
    ) -> None:
        self.store = store
        self.sink = sink
        self.max_staleness_seconds = max_staleness_seconds

    async def reconcile_once(self) -> str:
        state = await self.store.audit_anchor_security_state()
        if state is not None and state.status == "unlock_pending":
            # The ordinary health reconciler must never open a security gate
            # that was closed by an integrity failure. Only the dedicated,
            # challenge-bound unlock workflow may complete that transition.
            return state.status
        if state is None:
            await self.store.set_audit_anchor_security_state(
                status="initializing",
                write_blocked=True,
                reason="first_reconciliation_pending",
                successful=False,
            )
        try:
            remote_items = await self.sink.fetch_inventory()
        except AuditAnchorDeliveryError as exc:
            previous = await self.store.audit_anchor_security_state()
            if exc.retryable:
                fresh = (
                    previous is not None
                    and previous.status in {"healthy", "degraded"}
                    and previous.last_success_at is not None
                    and (
                        datetime.now(UTC) - previous.last_success_at
                    ).total_seconds()
                    <= self.max_staleness_seconds
                )
                updated = await self.store.set_audit_anchor_security_state(
                    status="degraded",
                    write_blocked=not fresh,
                    reason=exc.category,
                    successful=False,
                )
                return updated.status
            updated = await self.store.set_audit_anchor_security_state(
                status="configuration_blocked",
                write_blocked=True,
                reason=exc.category,
                successful=False,
            )
            return updated.status

        local_incident_ids = set(
            await self.store.list_audit_incident_ids()
        )
        current_heads = {
            item.incident_id: item
            for item in await self.store.list_audit_anchor_heads()
        }
        delivered_heads = {
            item.incident_id: item
            for item in await self.store.list_audit_anchor_heads(
                delivered_only=True
            )
        }
        remote = {
            str(item["incident_id"]): item for item in remote_items
        }
        if local_incident_ids - set(current_heads):
            return await self._block("local_outbox_missing")

        for incident_id, remote_item in remote.items():
            local = current_heads.get(incident_id)
            if local is None or incident_id not in local_incident_ids:
                return await self._block("local_stream_deleted")
            remote_sequence = int(remote_item["sequence"])
            if remote_sequence > local.sequence:
                return await self._block("local_database_rollback")
            verification = await self.store.verify_audit_chain(incident_id)
            if not verification.valid:
                return await self._block("local_chain_invalid")
            events = await self.store.list_audit_events(incident_id)
            if remote_sequence > len(events):
                return await self._block("local_event_deleted")
            event = events[remote_sequence - 1]
            if (
                event.sequence != remote_sequence
                or event.entry_hash != remote_item["head_hash"]
                or anchor_id(
                    incident_id,
                    remote_sequence,
                    event.entry_hash,
                )
                != remote_item["anchor_id"]
            ):
                return await self._block("local_remote_fork")

        for incident_id, delivered in delivered_heads.items():
            remote_item = remote.get(incident_id)
            if remote_item is None:
                return await self._block("remote_stream_missing")
            remote_sequence = int(remote_item["sequence"])
            if remote_sequence < delivered.sequence:
                return await self._block("remote_stream_truncated")
            if (
                remote_sequence == delivered.sequence
                and (
                    remote_item["anchor_id"] != delivered.anchor_id
                    or remote_item["head_hash"] != delivered.head_hash
                )
            ):
                return await self._block("delivered_anchor_fork")

        updated = await self.store.set_audit_anchor_security_state(
            status="healthy",
            write_blocked=False,
            reason="inventory_matches_local_history",
            successful=True,
        )
        return updated.status

    async def reconcile_unlock_once(
        self,
        *,
        owner_id: str,
        lease_ttl_seconds: float,
    ) -> str:
        claim = await self.store.claim_audit_anchor_unlock_reconciliation(
            owner_id=owner_id,
            ttl_seconds=lease_ttl_seconds,
        )
        if claim is None:
            state = await self.store.audit_anchor_security_state()
            return state.status if state is not None else "not_initialized"
        try:
            attestation = await self.verify_strict_inventory()
        except StrictAuditAnchorReconciliationError as exc:
            if exc.category in {
                "strict_outbox_not_drained",
                "strict_head_not_delivered",
                "strict_local_snapshot_changed",
            }:
                return "unlock_waiting_for_stable_inventory"
            try:
                await self.store.fail_audit_anchor_unlock_reconciliation(
                    claim,
                    reason=exc.category,
                )
            except AuditAnchorUnlockConflictError:
                return "unlock_pending"
            return "integrity_blocked"
        except AuditAnchorDeliveryError as exc:
            if exc.retryable:
                return "unlock_waiting_for_remote_inventory"
            try:
                await self.store.fail_audit_anchor_unlock_reconciliation(
                    claim,
                    reason=exc.category,
                )
            except AuditAnchorUnlockConflictError:
                return "unlock_pending"
            return "integrity_blocked"
        try:
            await self.store.complete_audit_anchor_unlock_reconciliation(
                claim,
                inventory_revision=attestation.inventory_revision,
                local_snapshot_hash=attestation.local_snapshot_hash,
                remote_snapshot_id=attestation.remote_snapshot_id,
                remote_snapshot_root=attestation.remote_snapshot_root,
                challenge=attestation.challenge,
                attested_at=attestation.generated_at,
            )
        except AuditAnchorUnlockConflictError:
            return "unlock_pending"
        return "healthy"

    async def verify_strict_inventory(
        self,
    ) -> StrictReconciliationAttestation:
        revision_before = (
            await self.store.audit_anchor_inventory_revision()
        )
        before, current_heads = await self._strict_local_snapshot()
        if (
            await self.store.audit_anchor_inventory_revision()
            != revision_before
        ):
            raise StrictAuditAnchorReconciliationError(
                "strict_local_snapshot_changed"
            )
        remote_snapshot = await self.sink.fetch_inventory_snapshot()
        remote = {
            str(item["incident_id"]): item
            for item in remote_snapshot.items
        }
        if set(remote) != set(current_heads):
            raise StrictAuditAnchorReconciliationError(
                "strict_stream_set_mismatch"
            )
        for incident_id, local in current_heads.items():
            remote_item = remote[incident_id]
            if (
                int(remote_item["sequence"]) != local.sequence
                or remote_item["anchor_id"] != local.anchor_id
                or remote_item["head_hash"] != local.head_hash
            ):
                raise StrictAuditAnchorReconciliationError(
                    "strict_head_mismatch"
                )
        after, _ = await self._strict_local_snapshot()
        revision_after = (
            await self.store.audit_anchor_inventory_revision()
        )
        if after != before or revision_after != revision_before:
            raise StrictAuditAnchorReconciliationError(
                "strict_local_snapshot_changed"
            )
        return StrictReconciliationAttestation(
            local_snapshot_hash=before,
            inventory_revision=revision_before,
            remote_snapshot_id=remote_snapshot.snapshot_id,
            remote_snapshot_root=remote_snapshot.snapshot_root,
            challenge=remote_snapshot.challenge,
            generated_at=remote_snapshot.generated_at,
        )

    async def _strict_local_snapshot(
        self,
    ) -> tuple[str, dict[str, AuditAnchor]]:
        incident_ids = await self.store.list_audit_incident_ids()
        heads = await self.store.list_audit_anchor_heads()
        delivered = await self.store.list_audit_anchor_heads(
            delivered_only=True
        )
        metrics = await self.store.audit_anchor_metrics()
        head_map = {item.incident_id: item for item in heads}
        delivered_map = {item.incident_id: item for item in delivered}
        if set(incident_ids) != set(head_map):
            raise StrictAuditAnchorReconciliationError(
                "strict_local_stream_missing"
            )
        if any(
            metrics.status_counts.get(status, 0) > 0
            for status in ("pending", "claimed", "dead_letter")
        ):
            raise StrictAuditAnchorReconciliationError(
                "strict_outbox_not_drained"
            )
        if set(delivered_map) != set(head_map):
            raise StrictAuditAnchorReconciliationError(
                "strict_head_not_delivered"
            )
        for incident_id, head in head_map.items():
            delivered_head = delivered_map[incident_id]
            if (
                delivered_head.sequence != head.sequence
                or delivered_head.anchor_id != head.anchor_id
                or delivered_head.head_hash != head.head_hash
            ):
                raise StrictAuditAnchorReconciliationError(
                    "strict_head_not_delivered"
                )
            verification = await self.store.verify_audit_chain(incident_id)
            if not verification.valid:
                raise StrictAuditAnchorReconciliationError(
                    "strict_local_chain_invalid"
                )
        snapshot = {
            "incident_ids": sorted(incident_ids),
            "heads": [
                {
                    "incident_id": item.incident_id,
                    "sequence": item.sequence,
                    "anchor_id": item.anchor_id,
                    "head_hash": item.head_hash,
                }
                for item in sorted(
                    heads,
                    key=lambda candidate: candidate.incident_id,
                )
            ],
            "outbox_status_counts": {
                status: int(metrics.status_counts.get(status, 0))
                for status in (
                    "pending",
                    "claimed",
                    "delivered",
                    "dead_letter",
                )
            },
        }
        return canonical_payload_hash(snapshot), head_map

    async def _block(self, reason: str) -> str:
        updated = await self.store.set_audit_anchor_security_state(
            status="integrity_blocked",
            write_blocked=True,
            reason=reason,
            successful=False,
        )
        return updated.status
