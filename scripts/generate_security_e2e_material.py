#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    generate_private_key,
)

from sentinelops.anchor_crypto import export_ed25519_public_key

ISSUER = "http://oidc-jwks.sentinelops-security.svc.cluster.local:8080"
AUDIENCE = "sentinelops-api"
OIDC_KEY_ID = "security-e2e-rs256-v1"
ANCHOR_KEY_ID = "security-e2e-ed25519-v1"


def _write_exclusive(path: Path, payload: bytes, mode: int) -> None:
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


def _base64url(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


def _token(
    private_key: object,
    *,
    subject: str,
    roles: list[str],
    audience: str = AUDIENCE,
) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": audience,
            "sub": subject,
            "iat": int((now - timedelta(seconds=5)).timestamp()),
            "exp": int((now + timedelta(minutes=20)).timestamp()),
            "roles": roles,
            "sentinelops_actor_type": "human",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": OIDC_KEY_ID},
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ephemeral OIDC and audit-anchor E2E material."
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)

    oidc_private_key = generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_numbers = oidc_private_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": OIDC_KEY_ID,
                "n": _base64url(public_numbers.n),
                "e": _base64url(public_numbers.e),
            }
        ]
    }
    viewer_roles = ["sentinelops.incident.view"]
    approver_roles = [
        "sentinelops.incident.view",
        "sentinelops.incident.approve",
    ]
    materials: list[tuple[str, bytes, int]] = [
        (
            "jwks.json",
            (json.dumps(jwks, sort_keys=True) + "\n").encode(),
            0o644,
        ),
        (
            "viewer.jwt",
            (
                _token(
                    oidc_private_key,
                    subject="security-e2e-viewer",
                    roles=viewer_roles,
                )
                + "\n"
            ).encode(),
            0o600,
        ),
        (
            "approver.jwt",
            (
                _token(
                    oidc_private_key,
                    subject="security-e2e-approver",
                    roles=approver_roles,
                )
                + "\n"
            ).encode(),
            0o600,
        ),
        (
            "invalid.jwt",
            (
                _token(
                    oidc_private_key,
                    subject="security-e2e-invalid",
                    roles=approver_roles,
                    audience="wrong-audience",
                )
                + "\n"
            ).encode(),
            0o600,
        ),
        (
            "anchor-delivery.token",
            secrets.token_urlsafe(48).encode(),
            0o600,
        ),
        (
            "anchor-inventory.token",
            secrets.token_urlsafe(48).encode(),
            0o600,
        ),
    ]

    anchor_private_key = Ed25519PrivateKey.generate()
    materials.extend(
        [
            (
                "anchor-private.pem",
                anchor_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
                0o600,
            ),
            (
                "anchor-public-keys.json",
                (
                    json.dumps(
                        {ANCHOR_KEY_ID: export_ed25519_public_key(anchor_private_key.public_key())},
                        sort_keys=True,
                    )
                    + "\n"
                ).encode(),
                0o644,
            ),
        ]
    )
    for filename, payload, mode in materials:
        _write_exclusive(args.output_dir / filename, payload, mode)


if __name__ == "__main__":
    main()
