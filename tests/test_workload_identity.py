from __future__ import annotations

import base64
import gzip
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import HTTPException
from starlette.requests import Request

from sentinelops.workload_identity import (
    MAX_JWKS_BYTES,
    WorkloadIdentityAuthenticator,
)

ISSUER_A = "https://cluster-a.example.test"
ISSUER_B = "https://cluster-b.example.test"
AUDIENCE = "sentinelops-control-gateway"
KEY_ID = "workload-test-v1"
NAMESPACE = "sentinelops-system"
SERVICE_ACCOUNT = "sentinelops-executor"
SA_UID_A = "11111111-1111-1111-1111-111111111111"
SA_UID_B = "22222222-2222-2222-2222-222222222222"
POD_UID_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
POD_UID_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
REVIEWER_TOKEN = "token-reviewer-test-token"
REVIEWER_TOKEN_FILE = Path("/tmp/sentinelops-workload-reviewer-token")
TOKEN_REVIEW_CA_FILE = Path("/tmp/sentinelops-workload-token-review-ca.pem")


def _base64url(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


def _rsa_jwk(private_key: Any, *, key_id: str = KEY_ID) -> dict[str, object]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "key_ops": ["verify"],
        "alg": "RS256",
        "kid": key_id,
        "n": _base64url(numbers.n),
        "e": _base64url(numbers.e),
    }


def _bundle() -> bytes:
    return json.dumps(
        {
            "clusters": [
                {
                    "cluster_id": "cluster-a",
                    "display_name": "Cluster A",
                    "default_namespace": "sentinelops-workloads",
                    "issuer": ISSUER_A,
                    "audience": AUDIENCE,
                    "jwks_url": f"{ISSUER_A}/openid/v1/jwks",
                    "namespace": NAMESPACE,
                    "service_account": SERVICE_ACCOUNT,
                    "service_account_uid": SA_UID_A,
                    "token_review_url": (
                        f"{ISSUER_A}/apis/authentication.k8s.io/v1/tokenreviews"
                    ),
                    "reviewer_token_file": str(REVIEWER_TOKEN_FILE),
                    "token_review_ca_file": str(TOKEN_REVIEW_CA_FILE),
                    "allowed_capabilities": [
                        "action.execute",
                        "action.reconcile",
                    ],
                },
                {
                    "cluster_id": "cluster-b",
                    "display_name": "Cluster B",
                    "default_namespace": "sentinelops-workloads",
                    "issuer": ISSUER_B,
                    "audience": AUDIENCE,
                    "jwks_url": f"{ISSUER_B}/openid/v1/jwks",
                    "namespace": NAMESPACE,
                    "service_account": SERVICE_ACCOUNT,
                    "service_account_uid": SA_UID_B,
                    "token_review_url": (
                        f"{ISSUER_B}/apis/authentication.k8s.io/v1/tokenreviews"
                    ),
                    "reviewer_token_file": str(REVIEWER_TOKEN_FILE),
                    "token_review_ca_file": str(TOKEN_REVIEW_CA_FILE),
                    "allowed_capabilities": ["action.execute"],
                },
            ]
        }
    ).encode()


def _token(
    private_key: Any,
    *,
    issuer: str = ISSUER_A,
    audience: str = AUDIENCE,
    sa_uid: str = SA_UID_A,
    pod_uid: str | None = POD_UID_A,
    issued_at: datetime | None = None,
    not_before: datetime | None = None,
    expires_at: datetime | None = None,
    algorithm: str = "RS256",
    headers: dict[str, str] | None = None,
    extra_claims: dict[str, object] | None = None,
) -> str:
    now = datetime.now(UTC)
    issued_at = issued_at or now - timedelta(seconds=5)
    not_before = not_before or issued_at
    expires_at = expires_at or now + timedelta(minutes=10)
    pod = {"name": "executor-0"}
    if pod_uid is not None:
        pod["uid"] = pod_uid
    claims: dict[str, object] = {
        "iss": issuer,
        "aud": audience,
        "sub": f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}",
        "iat": int(issued_at.timestamp()),
        "nbf": int(not_before.timestamp()),
        "exp": int(expires_at.timestamp()),
        "kubernetes.io": {
            "namespace": NAMESPACE,
            "serviceaccount": {
                "name": SERVICE_ACCOUNT,
                "uid": sa_uid,
            },
            "pod": pod,
        },
    }
    claims.update(extra_claims or {})
    return jwt.encode(
        claims,
        private_key,
        algorithm=algorithm,
        headers={"kid": KEY_ID, **(headers or {})},
    )


def _request(
    token: str,
    *,
    cluster_id: str = "cluster-a",
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    headers = [
        (b"x-sentinelops-cluster-id", cluster_id.encode()),
        (b"authorization", f"Bearer {token}".encode()),
    ]
    headers.extend(extra_headers or [])
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/executor/actions/claim",
            "headers": headers,
        }
    )


def _client(
    keys_by_host: dict[str, list[dict[str, object]]],
    *,
    headers: dict[str, str] | None = None,
    token_review_handler: Any | None = None,
) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tokenreviews"):
            if token_review_handler is not None:
                return token_review_handler(request)
            assert request.headers["authorization"] == f"Bearer {REVIEWER_TOKEN}"
            review = json.loads(request.content)
            assert review["spec"]["audiences"] == [AUDIENCE]
            service_account_uid = (
                SA_UID_B
                if request.url.host == "cluster-b.example.test"
                else SA_UID_A
            )
            return httpx.Response(
                201,
                json={
                    "apiVersion": "authentication.k8s.io/v1",
                    "kind": "TokenReview",
                    "status": {
                        "authenticated": True,
                        "audiences": [AUDIENCE],
                        "user": {
                            "username": (
                                f"system:serviceaccount:{NAMESPACE}:"
                                f"{SERVICE_ACCOUNT}"
                            ),
                            "uid": service_account_uid,
                        },
                    },
                },
                headers={"Content-Type": "application/json"},
            )
        keys = keys_by_host.get(request.url.host or "", [])
        return httpx.Response(
            200,
            json={"keys": keys},
            headers=headers or {"Content-Type": "application/json"},
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _authenticator(
    private_key: Any,
    *,
    client: httpx.AsyncClient | None = None,
    **kwargs: Any,
) -> tuple[WorkloadIdentityAuthenticator, httpx.AsyncClient]:
    await anyio.Path(REVIEWER_TOKEN_FILE).write_text(
        REVIEWER_TOKEN,
        encoding="ascii",
    )
    client = client or _client(
        {
            "cluster-a.example.test": [_rsa_jwk(private_key)],
            "cluster-b.example.test": [_rsa_jwk(private_key)],
        }
    )
    authenticator = WorkloadIdentityAuthenticator.from_json(
        _bundle(),
        production=True,
        client=client,
        jwks_min_refresh_seconds=1,
        **kwargs,
    )
    return authenticator, client


@pytest.mark.asyncio
async def test_valid_projected_token_returns_server_side_identity() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    authenticator, client = await _authenticator(private_key)
    token = _token(
        private_key,
        extra_claims={
            "roles": ["root"],
            "capabilities": ["cluster.admin"],
        },
    )
    try:
        identity = await authenticator.authenticate(
            _request(token),
            required_capability="action.execute",
            expected_pod_uid=POD_UID_A,
        )
    finally:
        await client.aclose()

    assert identity.cluster_id == "cluster-a"
    assert identity.pod_uid == POD_UID_A
    assert identity.assurance == "kubernetes-oidc"
    assert len(identity.subject_hash) == 64
    assert identity.allowed_capabilities == {
        "action.execute",
        "action.reconcile",
    }
    assert "cluster.admin" not in identity.allowed_capabilities


@pytest.mark.asyncio
async def test_token_cannot_cross_cluster_boundary() -> None:
    key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = _client(
        {
            "cluster-a.example.test": [_rsa_jwk(key_a)],
            "cluster-b.example.test": [_rsa_jwk(key_b)],
        }
    )
    authenticator = WorkloadIdentityAuthenticator.from_json(
        _bundle(),
        production=True,
        client=client,
        jwks_min_refresh_seconds=1,
    )
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(
                _request(_token(key_a), cluster_id="cluster-b")
            )
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes", "expected_status"),
    [
        ({"issuer": "https://attacker.example"}, 401),
        ({"audience": "wrong-audience"}, 401),
        (
            {
                "expires_at": datetime.now(UTC) - timedelta(minutes=1),
                "issued_at": datetime.now(UTC) - timedelta(minutes=10),
            },
            401,
        ),
        (
            {
                "issued_at": datetime.now(UTC) + timedelta(minutes=2),
                "not_before": datetime.now(UTC) + timedelta(minutes=2),
                "expires_at": datetime.now(UTC) + timedelta(minutes=8),
            },
            401,
        ),
        (
            {
                "issued_at": datetime.now(UTC) - timedelta(minutes=1),
                "not_before": datetime.now(UTC) + timedelta(minutes=2),
            },
            401,
        ),
        (
            {
                "issued_at": datetime.now(UTC) - timedelta(minutes=1),
                "expires_at": datetime.now(UTC) + timedelta(minutes=20),
            },
            401,
        ),
        ({"sa_uid": "wrong-service-account-uid"}, 403),
        ({"pod_uid": None}, 403),
    ],
)
async def test_claim_and_binding_failures_are_rejected(
    changes: dict[str, object],
    expected_status: int,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    authenticator, client = await _authenticator(private_key)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(
                _request(_token(private_key, **changes))
            )
    finally:
        await client.aclose()

    assert exc_info.value.status_code == expected_status


@pytest.mark.asyncio
async def test_pod_uid_must_match_executor_instance() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    authenticator, client = await _authenticator(private_key)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(
                _request(_token(private_key)),
                expected_pod_uid=POD_UID_B,
            )
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_disallowed_algorithm_and_remote_key_headers_are_rejected() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    authenticator, client = await _authenticator(private_key)
    hs_token = jwt.encode(
        {"sub": "attacker"},
        "not-a-public-key",
        algorithm="HS256",
        headers={"kid": KEY_ID},
    )
    jku_token = _token(
        private_key,
        headers={"jku": "https://attacker.example/jwks"},
    )
    try:
        for token in (hs_token, jku_token):
            with pytest.raises(HTTPException) as exc_info:
                await authenticator.authenticate(_request(token))
            assert exc_info.value.status_code == 401
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_es256_is_supported_when_pinned_by_jwks() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(
        jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key())
    )
    public_jwk.update(
        {
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "ES256",
            "kid": KEY_ID,
        }
    )
    client = _client(
        {
            "cluster-a.example.test": [public_jwk],
            "cluster-b.example.test": [public_jwk],
        }
    )
    authenticator, _ = await _authenticator(private_key, client=client)
    try:
        identity = await authenticator.authenticate(
            _request(_token(private_key, algorithm="ES256"))
        )
    finally:
        await client.aclose()

    assert identity.cluster_id == "cluster-a"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "jwks_response",
    [
        httpx.Response(
            200,
            json={"keys": []},
            headers={"Content-Type": "application/json"},
        ),
        httpx.Response(
            200,
            json={"keys": [{"kid": KEY_ID}, {"kid": KEY_ID}]},
            headers={"Content-Type": "application/json"},
        ),
        httpx.Response(
            200,
            content=b"{}",
            headers={"Content-Type": "text/plain"},
        ),
        httpx.Response(
            200,
            content=gzip.compress(b"{}"),
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        ),
    ],
)
async def test_invalid_jwks_responses_fail_closed(
    jwks_response: httpx.Response,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: jwks_response)
    )
    authenticator, _ = await _authenticator(private_key, client=client)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(_request(_token(private_key)))
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_duplicate_jwks_kid_is_rejected() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    duplicate = _rsa_jwk(private_key)
    client = _client(
        {
            "cluster-a.example.test": [duplicate, duplicate],
            "cluster-b.example.test": [duplicate],
        }
    )
    authenticator, _ = await _authenticator(private_key, client=client)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(_request(_token(private_key)))
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_unknown_kid_triggers_safe_jwks_rotation_refresh() -> None:
    old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        if _request.url.path.endswith("/tokenreviews"):
            return httpx.Response(
                200,
                json={
                    "status": {
                        "authenticated": True,
                        "audiences": [AUDIENCE],
                        "user": {
                            "username": (
                                f"system:serviceaccount:{NAMESPACE}:"
                                f"{SERVICE_ACCOUNT}"
                            ),
                            "uid": SA_UID_A,
                        },
                    }
                },
                headers={"Content-Type": "application/json"},
            )
        requests += 1
        keys = [_rsa_jwk(old_key)] if requests == 1 else [
            _rsa_jwk(old_key),
            _rsa_jwk(new_key, key_id="workload-test-v2"),
        ]
        return httpx.Response(
            200,
            json={"keys": keys},
            headers={"Content-Type": "application/json"},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    authenticator, _ = await _authenticator(old_key, client=client)
    first = _token(old_key)
    rotated = _token(
        new_key,
        headers={"kid": "workload-test-v2"},
    )
    try:
        await authenticator.authenticate(_request(first))
        authenticator._caches["cluster-a"].last_refresh_attempt -= 2
        identity = await authenticator.authenticate(_request(rotated))
    finally:
        await client.aclose()

    assert identity.cluster_id == "cluster-a"
    assert requests == 2


@pytest.mark.asyncio
async def test_token_review_is_not_cached_and_revoked_pod_token_fails_closed() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    reviews = 0

    def review(request: httpx.Request) -> httpx.Response:
        nonlocal reviews
        reviews += 1
        authenticated = reviews == 1
        return httpx.Response(
            200,
            json={
                "status": {
                    "authenticated": authenticated,
                    **(
                        {
                            "audiences": [AUDIENCE],
                            "user": {
                                "username": (
                                    f"system:serviceaccount:{NAMESPACE}:"
                                    f"{SERVICE_ACCOUNT}"
                                ),
                                "uid": SA_UID_A,
                            },
                        }
                        if authenticated
                        else {}
                    ),
                }
            },
            headers={"Content-Type": "application/json"},
        )

    client = _client(
        {
            "cluster-a.example.test": [_rsa_jwk(private_key)],
            "cluster-b.example.test": [_rsa_jwk(private_key)],
        },
        token_review_handler=review,
    )
    authenticator, _ = await _authenticator(private_key, client=client)
    token = _token(private_key)
    try:
        await authenticator.authenticate(_request(token))
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(_request(token))
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 401
    assert reviews == 2


@pytest.mark.asyncio
async def test_token_review_maps_kubernetes_invalidated_token_error_to_unauthorized() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = _client(
        {
            "cluster-a.example.test": [_rsa_jwk(private_key)],
            "cluster-b.example.test": [_rsa_jwk(private_key)],
        },
        token_review_handler=lambda _request: httpx.Response(
            201,
            json={
                "status": {
                    "user": {},
                    "error": (
                        "invalid bearer token, service account token "
                        "has been invalidated"
                    ),
                }
            },
            headers={"Content-Type": "application/json"},
        ),
    )
    authenticator, _ = await _authenticator(private_key, client=client)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(_request(_token(private_key)))
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_token_review_unavailable_fails_closed() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = _client(
        {
            "cluster-a.example.test": [_rsa_jwk(private_key)],
            "cluster-b.example.test": [_rsa_jwk(private_key)],
        },
        token_review_handler=lambda _request: httpx.Response(
            503,
            headers={"Content-Type": "application/json"},
        ),
    )
    authenticator, _ = await _authenticator(private_key, client=client)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(_request(_token(private_key)))
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_token_review_timeout_fails_closed() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("token review timed out", request=request)

    client = _client(
        {
            "cluster-a.example.test": [_rsa_jwk(private_key)],
            "cluster-b.example.test": [_rsa_jwk(private_key)],
        },
        token_review_handler=timeout,
    )
    authenticator, _ = await _authenticator(private_key, client=client)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(_request(_token(private_key)))
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        {
            "authenticated": True,
            "audiences": ["another-audience"],
            "user": {
                "username": (
                    f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
                ),
                "uid": SA_UID_A,
            },
        },
        {
            "authenticated": True,
            "audiences": [AUDIENCE],
            "user": {
                "username": (
                    f"system:serviceaccount:{NAMESPACE}:another-account"
                ),
                "uid": SA_UID_A,
            },
        },
    ],
)
async def test_token_review_rejects_wrong_audience_or_username(
    status: dict[str, object],
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = _client(
        {
            "cluster-a.example.test": [_rsa_jwk(private_key)],
            "cluster-b.example.test": [_rsa_jwk(private_key)],
        },
        token_review_handler=lambda _request: httpx.Response(
            200,
            json={"status": status},
            headers={"Content-Type": "application/json"},
        ),
    )
    authenticator, _ = await _authenticator(private_key, client=client)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(_request(_token(private_key)))
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_oversized_jwks_stream_is_stopped_before_full_buffering() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class OversizedStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.chunks_yielded = 0

        async def __aiter__(self):
            for chunk in (
                b"x" * MAX_JWKS_BYTES,
                b"x",
                b"must-not-be-read",
            ):
                self.chunks_yielded += 1
                yield chunk

    stream = OversizedStream()

    def handler(request: httpx.Request) -> httpx.Response:
        assert not request.url.path.endswith("/tokenreviews")
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    authenticator, _ = await _authenticator(private_key, client=client)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await authenticator.authenticate(_request(_token(private_key)))
    finally:
        await client.aclose()

    assert exc_info.value.status_code == 503
    assert stream.chunks_yielded == 2


def test_trust_bundle_is_strict_and_production_requires_https(tmp_path) -> None:
    insecure = json.loads(_bundle())
    insecure["clusters"][0]["issuer"] = "http://cluster-a.example.test"
    bundle_path = tmp_path / "trust.json"
    bundle_path.write_text(json.dumps(insecure))

    with pytest.raises(ValueError, match="安全"):
        WorkloadIdentityAuthenticator.from_file(
            bundle_path,
            production=True,
        )


def test_production_trust_requires_token_review_file_paths() -> None:
    payload = json.loads(_bundle())
    for key in (
        "token_review_url",
        "reviewer_token_file",
        "token_review_ca_file",
    ):
        payload["clusters"][0].pop(key)

    with pytest.raises(ValueError, match="字段不完整"):
        WorkloadIdentityAuthenticator.from_json(
            json.dumps(payload),
            production=True,
        )


def test_duplicate_workload_binding_is_rejected() -> None:
    payload = json.loads(_bundle())
    payload["clusters"][1].update(
        {
            "issuer": ISSUER_A,
            "namespace": NAMESPACE,
            "service_account": SERVICE_ACCOUNT,
            "service_account_uid": SA_UID_A,
        }
    )

    with pytest.raises(ValueError, match="多个集群"):
        WorkloadIdentityAuthenticator.from_json(
            json.dumps(payload),
            production=True,
        )
