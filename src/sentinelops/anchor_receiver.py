from __future__ import annotations

import hashlib
import hmac
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    insert,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from sentinelops.anchor_crypto import sign_inventory, sign_receipt
from sentinelops.audit_anchor import (
    INVENTORY_PROTOCOL,
    REQUEST_PROTOCOL,
    SIGNED_RECEIPT_PROTOCOL,
)
from sentinelops.storage.anchor import anchor_id
from sentinelops.storage.audit import canonical_payload_hash

MAX_ANCHOR_REQUEST_BYTES = 65_536
RECEIPT_ID_DOMAIN = b"sentinelops.audit.anchor.receiver.receipt.v1\0"

receiver_metadata = MetaData()

anchor_ledger_heads = Table(
    "sentinelops_anchor_ledger_heads",
    receiver_metadata,
    Column("source_id", String(128), primary_key=True),
    Column("incident_id", String(64), primary_key=True),
    Column("sequence", BigInteger, nullable=False),
    Column("anchor_id", String(64), nullable=False),
    Column("head_hash", String(64), nullable=False),
    Column("receipt", JSON, nullable=False),
    Column("updated_at", String(40), nullable=False),
)

anchor_ledger_entries = Table(
    "sentinelops_anchor_ledger_entries",
    receiver_metadata,
    Column("source_id", String(128), primary_key=True),
    Column("incident_id", String(64), primary_key=True),
    Column("sequence", BigInteger, primary_key=True),
    Column("anchor_id", String(64), nullable=False),
    Column("head_hash", String(64), nullable=False),
    Column("previous_anchor_id", String(64), nullable=True),
    Column("request_sha256", String(64), nullable=False),
    Column("request_payload", JSON, nullable=False),
    Column("receipt", JSON, nullable=False),
    Column("accepted_at", String(40), nullable=False),
    UniqueConstraint(
        "source_id",
        "anchor_id",
        name="uq_anchor_ledger_source_anchor",
    ),
)


class AnchorAuditMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    auth_algorithm: str = Field(min_length=1, max_length=24)
    key_id: str = Field(min_length=1, max_length=64)


class AnchorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    protocol_version: str
    anchor_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_id: str = Field(min_length=1, max_length=128)
    incident_id: str = Field(min_length=1, max_length=64)
    sequence: int = Field(ge=1)
    head_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    head_auth_tag: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    head_committed_at: str = Field(min_length=20, max_length=40)
    audit: AnchorAuditMetadata
    previous_anchor_id: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    bootstrap_checkpoint: bool = False

    @model_validator(mode="after")
    def validate_contract(self) -> AnchorRequest:
        if self.protocol_version != REQUEST_PROTOCOL:
            raise ValueError("unsupported protocol version")
        try:
            committed_at = datetime.fromisoformat(self.head_committed_at)
        except ValueError as exc:
            raise ValueError("head_committed_at must be ISO-8601") from exc
        if committed_at.tzinfo is None:
            raise ValueError("head_committed_at must include a timezone")
        if self.anchor_id != anchor_id(
            self.incident_id,
            self.sequence,
            self.head_hash,
        ):
            raise ValueError("anchor_id does not match the chain head")
        if self.audit.auth_algorithm == "hmac-sha256":
            if self.head_auth_tag is None:
                raise ValueError("HMAC audit anchors require head_auth_tag")
        elif self.audit.auth_algorithm == "none":
            if self.head_auth_tag is not None:
                raise ValueError("unkeyed audit anchors cannot include an auth tag")
        else:
            raise ValueError("unsupported audit authentication algorithm")
        if self.bootstrap_checkpoint:
            if self.sequence <= 1 or self.previous_anchor_id is not None:
                raise ValueError("invalid bootstrap checkpoint")
        elif self.sequence == 1:
            if self.previous_anchor_id is not None:
                raise ValueError("the first anchor cannot have a predecessor")
        elif self.previous_anchor_id is None:
            raise ValueError("non-bootstrap anchors require a predecessor")
        return self


class AnchorLedgerConflict(RuntimeError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


class AnchorLedger:
    def __init__(
        self,
        database_url: str,
        *,
        receiver_id: str,
        signing_key: Ed25519PrivateKey,
        signing_key_id: str,
    ) -> None:
        self.engine: AsyncEngine = create_async_engine(
            database_url,
            pool_pre_ping=True,
        )
        self.receiver_id = receiver_id
        self.signing_key = signing_key
        self.signing_key_id = signing_key_id

    async def setup(self) -> None:
        async with self.engine.begin() as connection:
            await connection.run_sync(receiver_metadata.create_all)

    async def close(self) -> None:
        await self.engine.dispose()

    async def accept(
        self,
        request: AnchorRequest,
        *,
        request_payload: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        request_sha256 = canonical_payload_hash(request_payload)
        for attempt in range(2):
            try:
                async with self.engine.begin() as connection:
                    head = (
                        await connection.execute(
                            select(anchor_ledger_heads)
                            .where(
                                anchor_ledger_heads.c.source_id
                                == request.source_id,
                                anchor_ledger_heads.c.incident_id
                                == request.incident_id,
                            )
                            .with_for_update()
                        )
                    ).mappings().one_or_none()
                    existing = (
                        await connection.execute(
                            select(anchor_ledger_entries).where(
                                anchor_ledger_entries.c.source_id
                                == request.source_id,
                                anchor_ledger_entries.c.incident_id
                                == request.incident_id,
                                anchor_ledger_entries.c.sequence
                                == request.sequence,
                            )
                        )
                    ).mappings().one_or_none()
                    if existing is not None:
                        if (
                            existing["anchor_id"] == request.anchor_id
                            and existing["request_sha256"] == request_sha256
                        ):
                            return dict(existing["receipt"]), False
                        raise AnchorLedgerConflict("fork_detected")
                    if head is None:
                        if not (
                            (
                                request.sequence == 1
                                and request.previous_anchor_id is None
                                and not request.bootstrap_checkpoint
                            )
                            or request.bootstrap_checkpoint
                        ):
                            raise AnchorLedgerConflict("invalid_initial_anchor")
                    else:
                        if request.sequence <= int(head["sequence"]):
                            raise AnchorLedgerConflict("stale_or_rollback")
                        if request.sequence != int(head["sequence"]) + 1:
                            raise AnchorLedgerConflict("sequence_gap")
                        if request.bootstrap_checkpoint:
                            raise AnchorLedgerConflict(
                                "bootstrap_after_stream_start"
                            )
                        if request.previous_anchor_id != head["anchor_id"]:
                            raise AnchorLedgerConflict("predecessor_mismatch")

                    accepted_at = datetime.now(UTC).isoformat()
                    receipt = self._signed_receipt(
                        request_payload,
                        request_sha256=request_sha256,
                        accepted_at=accepted_at,
                    )
                    await connection.execute(
                        insert(anchor_ledger_entries).values(
                            source_id=request.source_id,
                            incident_id=request.incident_id,
                            sequence=request.sequence,
                            anchor_id=request.anchor_id,
                            head_hash=request.head_hash,
                            previous_anchor_id=request.previous_anchor_id,
                            request_sha256=request_sha256,
                            request_payload=request_payload,
                            receipt=receipt,
                            accepted_at=accepted_at,
                        )
                    )
                    if head is None:
                        await connection.execute(
                            insert(anchor_ledger_heads).values(
                                source_id=request.source_id,
                                incident_id=request.incident_id,
                                sequence=request.sequence,
                                anchor_id=request.anchor_id,
                                head_hash=request.head_hash,
                                receipt=receipt,
                                updated_at=accepted_at,
                            )
                        )
                    else:
                        changed = await connection.execute(
                            update(anchor_ledger_heads)
                            .where(
                                anchor_ledger_heads.c.source_id
                                == request.source_id,
                                anchor_ledger_heads.c.incident_id
                                == request.incident_id,
                                anchor_ledger_heads.c.sequence
                                == head["sequence"],
                                anchor_ledger_heads.c.anchor_id
                                == head["anchor_id"],
                            )
                            .values(
                                sequence=request.sequence,
                                anchor_id=request.anchor_id,
                                head_hash=request.head_hash,
                                receipt=receipt,
                                updated_at=accepted_at,
                            )
                        )
                        if changed.rowcount != 1:
                            raise AnchorLedgerConflict(
                                "concurrent_head_update"
                            )
                    return receipt, True
            except IntegrityError:
                if attempt == 0:
                    continue
                raise AnchorLedgerConflict("concurrent_head_update") from None
        raise AnchorLedgerConflict("concurrent_head_update")

    async def latest(
        self,
        *,
        source_id: str,
        incident_id: str,
    ) -> dict[str, Any] | None:
        async with self.engine.connect() as connection:
            receipt = (
                await connection.execute(
                    select(anchor_ledger_heads.c.receipt).where(
                        anchor_ledger_heads.c.source_id == source_id,
                        anchor_ledger_heads.c.incident_id == incident_id,
                    )
                )
            ).scalar_one_or_none()
        return dict(receipt) if receipt is not None else None

    async def list_latest(
        self,
        *,
        source_id: str,
        cursor: str | None,
        limit: int,
    ) -> tuple[list[dict[str, Any]], str | None]:
        statement = (
            select(
                anchor_ledger_heads.c.incident_id,
                anchor_ledger_heads.c.receipt,
            )
            .where(anchor_ledger_heads.c.source_id == source_id)
            .order_by(anchor_ledger_heads.c.incident_id.asc())
            .limit(limit + 1)
        )
        if cursor is not None:
            statement = statement.where(
                anchor_ledger_heads.c.incident_id > cursor
            )
        async with self.engine.connect() as connection:
            rows = list((await connection.execute(statement)).mappings())
        has_more = len(rows) > limit
        page = rows[:limit]
        next_cursor = (
            str(page[-1]["incident_id"])
            if has_more and page
            else None
        )
        return [dict(row["receipt"]) for row in page], next_cursor

    async def inventory(
        self,
        *,
        source_id: str,
        challenge: str,
    ) -> dict[str, Any]:
        async with self.engine.connect() as connection:
            rows = list(
                (
                    await connection.execute(
                        select(
                            anchor_ledger_heads.c.incident_id,
                            anchor_ledger_heads.c.receipt,
                        )
                        .where(
                            anchor_ledger_heads.c.source_id == source_id
                        )
                        .order_by(
                            anchor_ledger_heads.c.incident_id.asc()
                        )
                        .limit(10_001)
                    )
                ).mappings()
            )
        if len(rows) > 10_000:
            raise AnchorLedgerConflict("inventory_limit_exceeded")
        items = [dict(row["receipt"]) for row in rows]
        snapshot_root = canonical_payload_hash(items)
        generated_at = datetime.now(UTC).isoformat()
        snapshot_id = hashlib.sha256(
            source_id.encode()
            + b"\0"
            + challenge.encode()
            + b"\0"
            + generated_at.encode()
            + b"\0"
            + str(len(items)).encode()
            + b"\0"
            + snapshot_root.encode()
        ).hexdigest()
        inventory = {
            "protocol_version": INVENTORY_PROTOCOL,
            "source_id": source_id,
            "challenge": challenge,
            "snapshot_id": snapshot_id,
            "snapshot_root": snapshot_root,
            "total_streams": len(items),
            "items": items,
            "generated_at": generated_at,
            "signature_algorithm": "ed25519",
            "inventory_key_id": self.signing_key_id,
        }
        inventory["inventory_signature"] = sign_inventory(
            inventory,
            private_key=self.signing_key,
        )
        return inventory

    def _signed_receipt(
        self,
        request_payload: dict[str, Any],
        *,
        request_sha256: str,
        accepted_at: str,
    ) -> dict[str, Any]:
        receipt_id = hashlib.sha256(
            RECEIPT_ID_DOMAIN
            + self.receiver_id.encode()
            + b"\0"
            + request_sha256.encode()
        ).hexdigest()
        receipt = {
            **{
                key: value
                for key, value in request_payload.items()
                if key != "protocol_version"
            },
            "protocol_version": SIGNED_RECEIPT_PROTOCOL,
            "status": "accepted",
            "request_sha256": request_sha256,
            "receiver_id": self.receiver_id,
            "receipt_id": receipt_id,
            "accepted_at": accepted_at,
            "signature_algorithm": "ed25519",
            "receipt_key_id": self.signing_key_id,
        }
        receipt["receipt_signature"] = sign_receipt(
            receipt,
            private_key=self.signing_key,
        )
        return receipt


def _single_header(request: Request, name: bytes) -> str | None:
    values = [
        value.decode("latin-1")
        for key, value in request.scope.get("headers", [])
        if key.lower() == name
    ]
    if len(values) > 1:
        raise HTTPException(status_code=400, detail="duplicate_header")
    return values[0] if values else None


def _authenticate(request: Request, bearer_token: str) -> None:
    authorization = _single_header(request, b"authorization")
    if (
        authorization is None
        or not authorization.startswith("Bearer ")
        or not hmac.compare_digest(
            authorization[7:].encode(),
            bearer_token.encode(),
        )
    ):
        raise HTTPException(status_code=401, detail="unauthorized")


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def create_anchor_receiver_app(
    ledger: AnchorLedger,
    *,
    bearer_token: str,
    inventory_bearer_token: str | None = None,
    allowed_source_id: str,
) -> FastAPI:
    inventory_token = inventory_bearer_token or bearer_token
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await ledger.setup()
        try:
            yield
        finally:
            await ledger.close()

    app = FastAPI(
        title="SentinelOps Reference Audit Anchor Receiver",
        lifespan=lifespan,
    )

    @app.post("/v1/anchors")
    async def accept_anchor(request: Request) -> JSONResponse:
        _authenticate(request, bearer_token)
        idempotency_key = _single_header(request, b"idempotency-key")
        content_type = _single_header(request, b"content-type") or ""
        content_encoding = _single_header(request, b"content-encoding")
        if content_type.split(";", 1)[0].strip().casefold() != "application/json":
            raise HTTPException(status_code=415, detail="json_required")
        if content_encoding not in {None, "", "identity"}:
            raise HTTPException(status_code=415, detail="compression_not_allowed")
        declared_length = request.headers.get("content-length")
        if declared_length:
            try:
                if int(declared_length) > MAX_ANCHOR_REQUEST_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="request_too_large",
                    )
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail="invalid_content_length",
                ) from exc
        body = await request.body()
        if len(body) > MAX_ANCHOR_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="request_too_large")
        try:
            payload = json.loads(
                body,
                object_pairs_hook=_reject_duplicate_keys,
            )
            parsed = AnchorRequest.model_validate(payload)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail="invalid_anchor_request",
            ) from exc
        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=422,
                detail="invalid_anchor_request",
            )
        if idempotency_key != parsed.anchor_id:
            raise HTTPException(
                status_code=422,
                detail="idempotency_key_mismatch",
            )
        if parsed.source_id != allowed_source_id:
            raise HTTPException(status_code=403, detail="source_not_allowed")
        try:
            receipt, created = await ledger.accept(
                parsed,
                request_payload=payload,
            )
            return JSONResponse(
                status_code=201 if created else 200,
                content=receipt,
            )
        except AnchorLedgerConflict as exc:
            raise HTTPException(status_code=409, detail=exc.category) from exc

    @app.get("/v1/anchors/latest")
    async def latest_anchor(
        request: Request,
        source_id: str = Query(min_length=1, max_length=128),
        incident_id: str = Query(min_length=1, max_length=64),
    ) -> dict[str, Any]:
        _authenticate(request, inventory_token)
        if source_id != allowed_source_id:
            raise HTTPException(status_code=403, detail="source_not_allowed")
        receipt = await ledger.latest(
            source_id=source_id,
            incident_id=incident_id,
        )
        if receipt is None:
            raise HTTPException(status_code=404, detail="anchor_not_found")
        return receipt

    @app.get("/v1/anchors")
    async def list_anchors(
        request: Request,
        source_id: str = Query(min_length=1, max_length=128),
        cursor: str | None = Query(default=None, max_length=64),
        limit: int = Query(default=100, ge=1, le=200),
    ) -> dict[str, Any]:
        _authenticate(request, inventory_token)
        if source_id != allowed_source_id:
            raise HTTPException(status_code=403, detail="source_not_allowed")
        items, next_cursor = await ledger.list_latest(
            source_id=source_id,
            cursor=cursor,
            limit=limit,
        )
        return {
            "protocol_version": INVENTORY_PROTOCOL,
            "source_id": source_id,
            "items": items,
            "next_cursor": next_cursor,
        }

    @app.get("/v1/anchor-inventory")
    async def anchor_inventory(
        request: Request,
        source_id: str = Query(min_length=1, max_length=128),
        challenge: str = Query(
            min_length=43,
            max_length=43,
            pattern=r"^[A-Za-z0-9_-]{43}$",
        ),
    ) -> dict[str, Any]:
        _authenticate(request, inventory_token)
        if source_id != allowed_source_id:
            raise HTTPException(status_code=403, detail="source_not_allowed")
        try:
            return await ledger.inventory(
                source_id=source_id,
                challenge=challenge,
            )
        except AnchorLedgerConflict as exc:
            raise HTTPException(status_code=503, detail=exc.category) from exc

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
