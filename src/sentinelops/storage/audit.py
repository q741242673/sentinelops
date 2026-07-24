from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

ENTRY_DOMAIN = b"sentinelops.audit.entry.v1\0"
GENESIS_DOMAIN = b"sentinelops.audit.genesis.v1\0"
MAC_DOMAIN = b"sentinelops.audit.mac.v1\0"
CANONICALIZATION = "python-json-v1"
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AuditEvent:
    incident_id: str
    sequence: int
    operation_id: str
    event_type: str
    source_component: str
    actor_type: str
    actor_id: str
    actor_assurance: str
    subject_type: str
    subject_id: str
    payload: dict[str, Any]
    occurred_at: str
    committed_at: str
    previous_hash: str
    entry_hash: str
    auth_tag: str | None
    auth_algorithm: str
    key_id: str
    canonicalization: str
    schema_version: int


@dataclass(frozen=True)
class AuditVerification:
    incident_id: str
    valid: bool
    event_count: int
    head_sequence: int
    head_hash: str | None
    auth_algorithm: str | None
    key_id: str | None
    first_invalid_sequence: int | None
    errors: tuple[str, ...]


def genesis_hash(incident_id: str) -> str:
    return hashlib.sha256(GENESIS_DOMAIN + incident_id.encode()).hexdigest()


def canonical_audit_document(
    *,
    incident_id: str,
    sequence: int,
    operation_id: str,
    event_type: str,
    source_component: str,
    actor_type: str,
    actor_id: str,
    actor_assurance: str,
    subject_type: str,
    subject_id: str,
    payload: dict[str, Any],
    occurred_at: str,
    committed_at: str,
    previous_hash: str,
    auth_algorithm: str,
    key_id: str,
) -> bytes:
    document = {
        "actor_id": actor_id,
        "actor_assurance": actor_assurance,
        "actor_type": actor_type,
        "auth_algorithm": auth_algorithm,
        "canonicalization": CANONICALIZATION,
        "committed_at": committed_at,
        "event_type": event_type,
        "incident_id": incident_id,
        "key_id": key_id,
        "occurred_at": occurred_at,
        "operation_id": operation_id,
        "payload": payload,
        "previous_hash": previous_hash,
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
        "source_component": source_component,
        "subject_id": subject_id,
        "subject_type": subject_type,
    }
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def audit_entry_hash(document: bytes) -> str:
    return hashlib.sha256(ENTRY_DOMAIN + document).hexdigest()


def audit_auth_tag(entry_hash: str, *, hmac_key: bytes | None) -> str | None:
    if hmac_key is None:
        return None
    return hmac.new(hmac_key, MAC_DOMAIN + entry_hash.encode(), hashlib.sha256).hexdigest()


def canonical_payload_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()
