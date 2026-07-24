from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RECEIPT_SIGNATURE_DOMAIN = b"sentinelops.audit.anchor.receipt.v2\0"
INVENTORY_SIGNATURE_DOMAIN = b"sentinelops.audit.anchor.inventory.v2\0"


def canonical_receipt_document(receipt: dict[str, Any]) -> bytes:
    unsigned = {
        key: value
        for key, value in receipt.items()
        if key != "receipt_signature"
    }
    return json.dumps(
        unsigned,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def sign_receipt(
    receipt: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey,
) -> str:
    signature = private_key.sign(
        RECEIPT_SIGNATURE_DOMAIN + canonical_receipt_document(receipt)
    )
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


def verify_receipt_signature(
    receipt: dict[str, Any],
    *,
    public_key: Ed25519PublicKey,
) -> bool:
    encoded = receipt.get("receipt_signature")
    if not isinstance(encoded, str) or not encoded:
        return False
    try:
        signature = base64.urlsafe_b64decode(
            encoded + "=" * (-len(encoded) % 4)
        )
        public_key.verify(
            signature,
            RECEIPT_SIGNATURE_DOMAIN
            + canonical_receipt_document(receipt),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_inventory(
    inventory: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey,
) -> str:
    unsigned = {
        key: value
        for key, value in inventory.items()
        if key != "inventory_signature"
    }
    document = json.dumps(
        unsigned,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    signature = private_key.sign(INVENTORY_SIGNATURE_DOMAIN + document)
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


def verify_inventory_signature(
    inventory: dict[str, Any],
    *,
    public_key: Ed25519PublicKey,
) -> bool:
    encoded = inventory.get("inventory_signature")
    if not isinstance(encoded, str) or not encoded:
        return False
    unsigned = {
        key: value
        for key, value in inventory.items()
        if key != "inventory_signature"
    }
    try:
        signature = base64.urlsafe_b64decode(
            encoded + "=" * (-len(encoded) % 4)
        )
        document = json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        public_key.verify(
            signature,
            INVENTORY_SIGNATURE_DOMAIN + document,
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def load_ed25519_private_key(file_path: str) -> Ed25519PrivateKey:
    try:
        payload = Path(file_path).read_bytes()
    except OSError as exc:
        raise ValueError("Anchor receipt private key file cannot be read") from exc
    if len(payload) > 65_536:
        raise ValueError("Anchor receipt private key file exceeds 64 KiB")
    try:
        key = serialization.load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("Anchor receipt private key is not valid PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Anchor receipt private key must be Ed25519")
    return key


def load_ed25519_public_keyring(
    file_path: str,
) -> dict[str, Ed25519PublicKey]:
    try:
        payload = Path(file_path).read_bytes()
    except OSError as exc:
        raise ValueError("Anchor receipt public keyring cannot be read") from exc
    if len(payload) > 262_144:
        raise ValueError("Anchor receipt public keyring exceeds 256 KiB")
    try:
        document = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Anchor receipt public keyring is not valid JSON") from exc
    if not isinstance(document, dict) or not document:
        raise ValueError("Anchor receipt public keyring must be a non-empty object")
    keys: dict[str, Ed25519PublicKey] = {}
    for key_id, encoded in document.items():
        if (
            not isinstance(key_id, str)
            or not 1 <= len(key_id) <= 64
            or not isinstance(encoded, str)
        ):
            raise ValueError("Anchor receipt public keyring contains invalid entries")
        try:
            raw = base64.urlsafe_b64decode(
                encoded + "=" * (-len(encoded) % 4)
            )
            keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc:
            raise ValueError(
                "Anchor receipt public keyring contains an invalid Ed25519 key"
            ) from exc
    return keys


def export_ed25519_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")
