from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from fastapi import HTTPException, Request

import sentinelops.api as api_module
from sentinelops.api import app
from sentinelops.config import Settings
from sentinelops.operator_auth import (
    INCIDENT_APPROVE_PERMISSION,
    INCIDENT_VIEW_PERMISSION,
    UNLOCK_APPROVE_PERMISSION,
    UNLOCK_REQUEST_PERMISSION,
    OIDCAuthenticator,
    operator_auth_configuration_error,
)
from sentinelops.storage import SqlIncidentStore

ISSUER = "https://identity.example.test"
AUDIENCE = "sentinelops-api"
JWKS_URL = "https://identity.example.test/.well-known/jwks.json"
KEY_ID = "operator-test-v1"


def _settings(**updates) -> Settings:
    values = {
        "operator_auth_mode": "oidc",
        "oidc_issuer": ISSUER,
        "oidc_audience": AUDIENCE,
        "oidc_jwks_url": JWKS_URL,
        **updates,
    }
    return Settings(
        **values,
    )


def _request(token: str, *, duplicate: bool = False) -> Request:
    headers = [(b"authorization", f"Bearer {token}".encode())]
    if duplicate:
        headers.append((b"authorization", b"Bearer attacker"))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/approval",
            "headers": headers,
        }
    )


def _token(private_key, **claim_updates) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "employee-123",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "sentinelops_actor_type": "human",
        "roles": [INCIDENT_APPROVE_PERMISSION],
        **claim_updates,
    }
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


def _jwks(private_key) -> dict:
    key = jwt.algorithms.RSAAlgorithm.to_jwk(
        private_key.public_key(),
        as_dict=True,
    )
    key.update({"kid": KEY_ID, "alg": "RS256", "use": "sig"})
    return {"keys": [key]}


@pytest.mark.asyncio
async def test_oidc_authenticates_human_permission_and_caches_jwks() -> None:
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json=_jwks(private_key),
            headers={"Content-Type": "application/json"},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    authenticator = OIDCAuthenticator(_settings(), client=client)
    token = _token(private_key)
    try:
        first = await authenticator.authenticate(
            _request(token),
            required_permission=INCIDENT_APPROVE_PERMISSION,
        )
        second = await authenticator.authenticate(
            _request(token),
            required_permission=INCIDENT_APPROVE_PERMISSION,
        )
    finally:
        await client.aclose()

    assert first == second
    assert first.assurance == "oidc-human"
    assert first.subject == "employee-123"
    assert len(first.subject_hash) == 64
    assert "employee-123" not in first.subject_hash
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim_updates", "status_code"),
    [
        ({"aud": "another-api"}, 401),
        ({"sentinelops_actor_type": "service-account"}, 403),
        ({"roles": []}, 403),
        ({"exp": datetime.now(UTC) - timedelta(minutes=5)}, 401),
    ],
)
async def test_oidc_rejects_invalid_identity_or_authority(
    claim_updates,
    status_code: int,
) -> None:
    private_key = generate_private_key(public_exponent=65537, key_size=2048)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_jwks(private_key),
            headers={"Content-Type": "application/json"},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    authenticator = OIDCAuthenticator(_settings(), client=client)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(
                _request(_token(private_key, **claim_updates)),
                required_permission=INCIDENT_APPROVE_PERMISSION,
            )
    finally:
        await client.aclose()

    assert exc_info.value.status_code == status_code


@pytest.mark.asyncio
async def test_oidc_rejects_duplicate_authorization_headers() -> None:
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json=_jwks(private_key),
                headers={"Content-Type": "application/json"},
            )
        )
    )
    authenticator = OIDCAuthenticator(_settings(), client=client)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(
                _request(_token(private_key), duplicate=True),
                required_permission=INCIDENT_APPROVE_PERMISSION,
            )
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 401


def test_production_operator_auth_fails_closed() -> None:
    disabled = Settings(environment="production")
    insecure = _settings(
        environment="production",
        oidc_issuer="http://identity.example.test",
        oidc_jwks_url="http://identity.example.test/jwks",
    )

    assert "必须启用 OIDC" in (
        operator_auth_configuration_error(disabled, production=True) or ""
    )
    assert "安全的 URL" in (
        operator_auth_configuration_error(insecure, production=True) or ""
    )


@pytest.mark.asyncio
async def test_api_v1_requires_oidc_but_health_stays_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    jwks_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json=_jwks(private_key),
                headers={"Content-Type": "application/json"},
            )
        )
    )
    settings = _settings()
    authenticator = OIDCAuthenticator(settings, client=jwks_client)
    monkeypatch.setattr(api_module, "get_settings", lambda: settings)
    monkeypatch.setattr(
        api_module,
        "operator_authenticator",
        authenticator,
    )
    transport = httpx.ASGITransport(app=app)
    token = _token(
        private_key,
        roles=[INCIDENT_VIEW_PERMISSION],
    )
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://sentinelops.test",
        ) as client:
            health = await client.get("/health")
            missing = await client.get("/api/v1/runtime")
            accepted = await client.get(
                "/api/v1/runtime",
                headers={"Authorization": f"Bearer {token}"},
            )
    finally:
        await jwks_client.aclose()

    assert health.status_code == 200
    assert missing.status_code == 401
    assert accepted.status_code == 200


@pytest.mark.asyncio
async def test_unlock_api_requires_distinct_oidc_permissions_and_keeps_gate_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    jwks_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json=_jwks(private_key),
                headers={"Content-Type": "application/json"},
            )
        )
    )
    settings = _settings()
    authenticator = OIDCAuthenticator(settings, client=jwks_client)
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'unlock-api.db'}",
        audit_hmac_key="unlock-api-audit-key-000000000000001",
        audit_key_id="unlock-api-test-v1",
    )
    await store.setup()
    blocked = await store.set_audit_anchor_security_state(
        status="integrity_blocked",
        write_blocked=True,
        reason="external_fork",
        successful=False,
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: settings)
    monkeypatch.setattr(
        api_module,
        "operator_authenticator",
        authenticator,
    )
    monkeypatch.setattr(api_module, "incident_store", store)
    requester_token = _token(
        private_key,
        sub="security-engineer-a",
        roles=[UNLOCK_REQUEST_PERMISSION],
    )
    approver_token = _token(
        private_key,
        sub="security-engineer-b",
        roles=[UNLOCK_APPROVE_PERMISSION],
    )
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://sentinelops.test",
        ) as client:
            created = await client.post(
                "/api/v1/security/audit-anchor/unlock-requests",
                headers={
                    "Authorization": f"Bearer {requester_token}",
                    "Idempotency-Key": "unlock-request-api-test",
                },
                json={
                    "expected_security_generation": blocked.generation,
                    "change_ticket": "CHG-42",
                    "justification": "external ledger restored",
                    "ttl_seconds": 600,
                },
            )
            assert created.status_code == 201, created.text
            payload = created.json()
            approved = await client.post(
                (
                    "/api/v1/security/audit-anchor/unlock-requests/"
                    f"{payload['request_id']}/decision"
                ),
                headers={
                    "Authorization": f"Bearer {approver_token}",
                    "Idempotency-Key": "unlock-approval-api-test",
                },
                json={
                    "expected_request_version": payload["version"],
                    "expected_security_generation": blocked.generation,
                    "approved": True,
                    "note": "second human approval",
                },
            )
    finally:
        await jwks_client.aclose()

    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    state = await store.audit_anchor_security_state()
    assert state is not None
    assert state.status == "unlock_pending"
    assert state.write_blocked is True
    await store.close()
