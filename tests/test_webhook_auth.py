from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

import sentinelops.api as api_module
from sentinelops.api import app
from sentinelops.config import Settings


def _payload_bytes(fingerprint: str = "authenticated-webhook") -> bytes:
    return json.dumps(
        {
            "status": "firing",
            "receiver": "sentinelops",
            "alerts": [
                {
                    "status": "firing",
                    "fingerprint": fingerprint,
                    "startsAt": "2026-07-23T08:00:00Z",
                    "labels": {
                        "alertname": "HighOrderServiceErrorRate",
                        "namespace": "payments",
                        "service": "order-service",
                        "severity": "critical",
                    },
                    "annotations": {"summary": "Order service SLO exceeded"},
                }
            ],
        },
        separators=(",", ":"),
    ).encode()


def _hmac_headers(
    body: bytes,
    *,
    secret: str,
    timestamp: int,
) -> dict[str, str]:
    signature = hmac.new(
        secret.encode(),
        (
            b"sentinelops.alertmanager.v1\n"
            + str(timestamp).encode()
            + b"\n"
            + body
        ),
        hashlib.sha256,
    ).hexdigest()
    return {
        "content-type": "application/json",
        "x-sentinelops-timestamp": str(timestamp),
        "x-sentinelops-signature": f"v1={signature}",
    }


def _prepare(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    monkeypatch.setattr(api_module, "get_settings", lambda: settings)
    monkeypatch.setattr(api_module, "_schedule_investigation", lambda *_: None)
    api_module.incident_records.clear()
    api_module.incident_versions.clear()
    api_module.alert_fingerprints.clear()
    api_module.resolved_incident_ids.clear()
    api_module.incident_store = None


@pytest.mark.asyncio
async def test_bearer_auth_rejects_missing_and_wrong_token_then_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "alertmanager-production-token"
    settings = Settings(
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token=token,
    )
    _prepare(monkeypatch, settings)
    transport = ASGITransport(app=app)
    body = _payload_bytes("bearer-auth")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers={"content-type": "application/json"},
        )
        wrong = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers={
                "content-type": "application/json",
                "authorization": "Bearer wrong-token",
            },
        )
        accepted = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {token}",
            },
        )

    assert missing.status_code == wrong.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert token not in missing.text
    assert token not in wrong.text
    assert accepted.status_code == 202
    assert accepted.json()["accepted"][0]["status"] == "accepted"


@pytest.mark.asyncio
async def test_bearer_auth_reads_token_from_mounted_secret_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    token = "mounted-alertmanager-production-token"
    token_file = tmp_path / "webhook-bearer-token"
    token_file.write_text(f"{token}\n")
    settings = Settings(
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token_file=str(token_file),
    )
    _prepare(monkeypatch, settings)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=_payload_bytes("mounted-secret"),
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {token}",
            },
        )

    assert response.status_code == 202


@pytest.mark.asyncio
async def test_hmac_auth_covers_exact_body_and_rejects_tampering_and_old_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "hmac-signing-secret"
    settings = Settings(
        alertmanager_webhook_auth_mode="hmac_sha256",
        alertmanager_webhook_signing_secret=secret,
        alertmanager_webhook_signature_ttl_seconds=300,
    )
    _prepare(monkeypatch, settings)
    transport = ASGITransport(app=app)
    timestamp = int(datetime.now(UTC).timestamp())
    body = _payload_bytes("hmac-auth")
    valid_headers = _hmac_headers(
        body,
        secret=secret,
        timestamp=timestamp,
    )
    tampered = body.replace(b"Order service SLO exceeded", b"forged summary")
    stale_headers = _hmac_headers(
        body,
        secret=secret,
        timestamp=timestamp - 301,
    )
    future_headers = _hmac_headers(
        body,
        secret=secret,
        timestamp=timestamp + 31,
    )

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        accepted = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers=valid_headers,
        )
        tampered_response = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=tampered,
            headers=valid_headers,
        )
        stale = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers=stale_headers,
        )
        future = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers=future_headers,
        )

    assert accepted.status_code == 202
    assert (
        tampered_response.status_code
        == stale.status_code
        == future.status_code
        == 401
    )
    assert secret not in tampered_response.text
    assert secret not in stale.text


@pytest.mark.asyncio
async def test_authentication_runs_before_payload_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token="validation-order-token",
    )
    _prepare(monkeypatch, settings)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        unauthenticated = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=b"{not-json",
            headers={"content-type": "application/json"},
        )
        authenticated = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=b"{not-json",
            headers={
                "content-type": "application/json",
                "authorization": "Bearer validation-order-token",
            },
        )

    assert unauthenticated.status_code == 401
    assert authenticated.status_code == 422


@pytest.mark.asyncio
async def test_duplicate_authentication_headers_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token="duplicate-header-token",
    )
    _prepare(monkeypatch, settings)
    transport = ASGITransport(app=app)
    body = _payload_bytes("duplicate-header")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers=[
                ("content-type", "application/json"),
                ("authorization", "Bearer duplicate-header-token"),
                ("authorization", "Bearer attacker-token"),
            ],
        )

    assert response.status_code == 401
    assert api_module.incident_records == {}

    hmac_settings = Settings(
        alertmanager_webhook_auth_mode="hmac_sha256",
        alertmanager_webhook_signing_secret="duplicate-hmac-secret",
    )
    _prepare(monkeypatch, hmac_settings)
    timestamp = int(datetime.now(UTC).timestamp())
    hmac_headers = _hmac_headers(
        body,
        secret="duplicate-hmac-secret",
        timestamp=timestamp,
    )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        duplicate_signature = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers=[
                ("content-type", "application/json"),
                (
                    "x-sentinelops-timestamp",
                    hmac_headers["x-sentinelops-timestamp"],
                ),
                (
                    "x-sentinelops-signature",
                    hmac_headers["x-sentinelops-signature"],
                ),
                ("x-sentinelops-signature", "v1=" + "0" * 64),
            ],
        )

    assert duplicate_signature.status_code == 401
    assert api_module.incident_records == {}


@pytest.mark.asyncio
async def test_webhook_body_limit_and_content_encoding_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token="bounded-body-token",
        alertmanager_webhook_max_body_bytes=1024,
    )
    _prepare(monkeypatch, settings)
    transport = ASGITransport(app=app)
    oversized = _payload_bytes("x" * 2_000)
    headers = {
        "content-type": "application/json",
        "authorization": "Bearer bounded-body-token",
    }

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        too_large = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=oversized,
            headers=headers,
        )
        compressed = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=_payload_bytes("compressed"),
            headers={**headers, "content-encoding": "gzip"},
        )
        wrong_media_type = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=_payload_bytes("plain-text"),
            headers={
                "content-type": "text/plain",
                "authorization": "Bearer bounded-body-token",
            },
        )

    assert too_large.status_code == 413
    assert compressed.status_code == 415
    assert wrong_media_type.status_code == 415
    assert api_module.incident_records == {}


@pytest.mark.asyncio
async def test_previous_bearer_token_only_works_before_absolute_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous = "previous-rotation-token"
    active_rotation = Settings(
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token="current-rotation-token",
        alertmanager_webhook_previous_bearer_token=previous,
        alertmanager_webhook_previous_secret_expires_at=(
            datetime.now(UTC) + timedelta(minutes=5)
        ),
    )
    _prepare(monkeypatch, active_rotation)
    transport = ASGITransport(app=app)
    body = _payload_bytes("active-rotation")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        accepted = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {previous}",
            },
        )

    expired_rotation = active_rotation.model_copy(
        update={
            "alertmanager_webhook_previous_secret_expires_at": (
                datetime.now(UTC) - timedelta(seconds=1)
            )
        }
    )
    _prepare(monkeypatch, expired_rotation)
    monkeypatch.setattr(api_module, "get_settings", lambda: expired_rotation)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        rejected = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=_payload_bytes("expired-rotation"),
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {previous}",
            },
        )

    assert accepted.status_code == 202
    assert rejected.status_code == 401


@pytest.mark.asyncio
async def test_previous_hmac_secret_only_works_before_absolute_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous = "previous-hmac-signing-secret"
    active_rotation = Settings(
        alertmanager_webhook_auth_mode="hmac_sha256",
        alertmanager_webhook_signing_secret="current-hmac-signing-secret",
        alertmanager_webhook_previous_signing_secret=previous,
        alertmanager_webhook_previous_secret_expires_at=(
            datetime.now(UTC) + timedelta(minutes=5)
        ),
    )
    _prepare(monkeypatch, active_rotation)
    transport = ASGITransport(app=app)
    body = _payload_bytes("active-hmac-rotation")
    timestamp = int(datetime.now(UTC).timestamp())
    headers = _hmac_headers(body, secret=previous, timestamp=timestamp)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        accepted = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=body,
            headers=headers,
        )

    expired_rotation = active_rotation.model_copy(
        update={
            "alertmanager_webhook_previous_secret_expires_at": (
                datetime.now(UTC) - timedelta(seconds=1)
            )
        }
    )
    _prepare(monkeypatch, expired_rotation)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        rejected = await client.post(
            "/api/v1/webhooks/alertmanager",
            content=_payload_bytes("expired-hmac-rotation"),
            headers=_hmac_headers(
                _payload_bytes("expired-hmac-rotation"),
                secret=previous,
                timestamp=timestamp,
            ),
        )

    assert accepted.status_code == 202
    assert rejected.status_code == 401


@pytest.mark.asyncio
async def test_production_startup_rejects_anonymous_or_incomplete_webhook_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anonymous = Settings(
        environment="production",
        executor_mode="external",
        alertmanager_source_id="prod-cluster",
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: anonymous)
    with pytest.raises(RuntimeError, match="禁止匿名"):
        await api_module.initialize_persistence()

    incomplete = anonymous.model_copy(
        update={"alertmanager_webhook_auth_mode": "hmac_sha256"}
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: incomplete)
    with pytest.raises(RuntimeError, match="SIGNING_SECRET"):
        await api_module.initialize_persistence()

    empty = Settings(
        environment="production",
        executor_mode="external",
        alertmanager_source_id="prod-cluster",
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token="",
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: empty)
    with pytest.raises(RuntimeError, match="BEARER_TOKEN"):
        await api_module.initialize_persistence()

    missing_audit_key = Settings(
        environment="production",
        executor_mode="external",
        alertmanager_source_id="prod-cluster",
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token="valid-webhook-token-00000000000001",
    )
    monkeypatch.setattr(
        api_module,
        "get_settings",
        lambda: missing_audit_key,
    )
    with pytest.raises(RuntimeError, match="审计 HMAC"):
        await api_module.initialize_persistence()


def test_secret_values_are_masked_in_settings_representation() -> None:
    token = "must-not-appear-in-repr"
    settings = Settings(
        alertmanager_webhook_auth_mode="bearer",
        alertmanager_webhook_bearer_token=token,
    )

    assert token not in repr(settings)
