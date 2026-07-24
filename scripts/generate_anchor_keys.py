#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from sentinelops.anchor_crypto import export_ed25519_public_key


def _new_file(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a local Ed25519 audit-anchor receipt keypair"
    )
    parser.add_argument("--key-id", required=True)
    parser.add_argument(
        "--private-key",
        type=Path,
        default=Path("anchor-receipt-private.pem"),
    )
    parser.add_argument(
        "--public-keyring",
        type=Path,
        default=Path("anchor-receipt-public-keys.json"),
    )
    args = parser.parse_args()
    if not 1 <= len(args.key_id) <= 64:
        raise SystemExit("--key-id must contain 1 to 64 characters")
    private_key = Ed25519PrivateKey.generate()
    private_payload = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_payload = (
        json.dumps(
            {
                args.key_id: export_ed25519_public_key(
                    private_key.public_key()
                )
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    _new_file(args.private_key, private_payload, 0o600)
    try:
        _new_file(args.public_keyring, public_payload, 0o644)
    except BaseException:
        args.private_key.unlink(missing_ok=True)
        raise
    print(f"Created {args.private_key} and {args.public_keyring}")


if __name__ == "__main__":
    main()
