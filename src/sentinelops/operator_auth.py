from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
from fastapi import HTTPException, Request

from sentinelops.config import Settings

ALLOWED_JWT_ALGORITHMS = frozenset({"RS256", "ES256"})
MAX_AUTHORIZATION_BYTES = 16_384
MAX_JWKS_BYTES = 262_144
MAX_JWKS_KEYS = 100
UNLOCK_REQUEST_PERMISSION = "sentinelops.anchor-unlock.request"
UNLOCK_APPROVE_PERMISSION = "sentinelops.anchor-unlock.approve"
INCIDENT_APPROVE_PERMISSION = "sentinelops.incident.approve"
INCIDENT_VIEW_PERMISSION = "sentinelops.incident.view"
INCIDENT_CREATE_PERMISSION = "sentinelops.incident.create"
DEMO_OPERATE_PERMISSION = "sentinelops.demo.operate"


@dataclass(frozen=True)
class OperatorIdentity:
    issuer: str
    subject: str
    subject_hash: str
    permissions: frozenset[str]
    assurance: str
    expires_at: datetime | None


def operator_auth_configuration_error(
    settings: Settings,
    *,
    production: bool,
) -> str | None:
    if production and settings.operator_auth_mode != "oidc":
        return (
            "生产环境必须启用 OIDC 操作者认证："
            "设置 SENTINELOPS_OPERATOR_AUTH_MODE=oidc"
        )
    if settings.operator_auth_mode == "disabled":
        return None
    if not (
        settings.oidc_issuer
        and settings.oidc_audience
        and settings.oidc_jwks_url
    ):
        return "OIDC 认证必须配置 issuer、audience 和固定 JWKS URL"
    issuer = urlsplit(settings.oidc_issuer)
    jwks = urlsplit(settings.oidc_jwks_url)
    required_scheme = "https" if production else None
    for label, parsed in (("issuer", issuer), ("JWKS URL", jwks)):
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or (required_scheme and parsed.scheme.casefold() != required_scheme)
            or (
                not required_scheme
                and parsed.scheme.casefold() not in {"http", "https"}
            )
        ):
            return f"OIDC {label} 必须是固定且安全的 URL"
    if jwks.query:
        return "OIDC JWKS URL 不能包含 query"
    if settings.oidc_jwks_hard_cache_seconds < settings.oidc_jwks_cache_seconds:
        return "OIDC JWKS hard cache 必须大于等于普通 cache"
    return None


class OIDCAuthenticator:
    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        error = operator_auth_configuration_error(
            settings,
            production=(
                settings.environment.strip().casefold()
                in {"prod", "production"}
            ),
        )
        if error is not None or settings.operator_auth_mode != "oidc":
            raise ValueError(error or "OIDC operator authentication is disabled")
        assert settings.oidc_issuer is not None
        assert settings.oidc_audience is not None
        assert settings.oidc_jwks_url is not None
        self.issuer = settings.oidc_issuer
        self.audience = settings.oidc_audience
        self.jwks_url = settings.oidc_jwks_url
        self.roles_claim = settings.oidc_roles_claim
        self.human_claim = settings.oidc_human_claim
        self.human_value = settings.oidc_human_value
        self.clock_skew_seconds = settings.oidc_clock_skew_seconds
        self.max_token_lifetime_seconds = (
            settings.oidc_max_token_lifetime_seconds
        )
        self.jwks_cache_seconds = settings.oidc_jwks_cache_seconds
        self.jwks_hard_cache_seconds = (
            settings.oidc_jwks_hard_cache_seconds
        )
        self.jwks_min_refresh_seconds = (
            settings.oidc_jwks_min_refresh_seconds
        )
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(settings.oidc_timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            headers={"Accept-Encoding": "identity"},
        )
        self._keys: dict[str, jwt.PyJWK] = {}
        self._cache_deadline = 0.0
        self._hard_cache_deadline = 0.0
        self._last_refresh_attempt = 0.0
        self._refresh_lock = asyncio.Lock()

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def authenticate(
        self,
        request: Request,
        *,
        required_permission: str,
    ) -> OperatorIdentity:
        token = self._bearer_token(request)
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise self._unauthorized("OIDC Token 头部无效") from exc
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if (
            "jku" in header
            or "x5u" in header
            or
            algorithm not in ALLOWED_JWT_ALGORITHMS
            or not isinstance(key_id, str)
            or not key_id
            or len(key_id) > 128
        ):
            raise self._unauthorized("OIDC Token 算法或 Key ID 无效")
        key = await self._key(key_id, force_refresh=False)
        if key is None:
            key = await self._key(key_id, force_refresh=True)
        if key is None or key.algorithm_name != algorithm:
            raise self._unauthorized("OIDC Token 使用未知签名密钥")
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=[algorithm],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.clock_skew_seconds,
                options={
                    "require": ["exp", "iat", "iss", "sub"],
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise self._unauthorized("OIDC Token 校验失败") from exc
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        if (
            isinstance(issued_at, bool)
            or not isinstance(issued_at, (int, float))
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, (int, float))
            or expires_at <= issued_at
            or expires_at - issued_at > self.max_token_lifetime_seconds
        ):
            raise self._unauthorized("OIDC Token 生命周期无效")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not 1 <= len(subject) <= 512:
            raise self._unauthorized("OIDC Token 缺少有效 subject")
        if claims.get(self.human_claim) != self.human_value:
            raise HTTPException(
                status_code=403,
                detail="该身份不是允许执行人工审批的人类操作者",
            )
        permissions = self._permissions(claims.get(self.roles_claim))
        if required_permission not in permissions:
            raise HTTPException(
                status_code=403,
                detail="当前 OIDC 身份没有所需权限",
            )
        subject_hash = hashlib.sha256(
            f"{self.issuer}\0{subject}".encode()
        ).hexdigest()
        return OperatorIdentity(
            issuer=self.issuer,
            subject=subject,
            subject_hash=subject_hash,
            permissions=permissions,
            assurance="oidc-human",
            expires_at=datetime.fromtimestamp(expires_at, tz=UTC),
        )

    async def _key(
        self,
        key_id: str,
        *,
        force_refresh: bool,
    ) -> jwt.PyJWK | None:
        now = time.monotonic()
        if not force_refresh and now < self._cache_deadline:
            return self._keys.get(key_id)
        async with self._refresh_lock:
            now = time.monotonic()
            if not force_refresh and now < self._cache_deadline:
                return self._keys.get(key_id)
            if (
                force_refresh
                and self._keys
                and now - self._last_refresh_attempt
                < self.jwks_min_refresh_seconds
            ):
                return self._keys.get(key_id)
            self._last_refresh_attempt = now
            try:
                await self._refresh_keys()
            except HTTPException:
                if (
                    key_id in self._keys
                    and now < self._hard_cache_deadline
                ):
                    return self._keys[key_id]
                raise
            return self._keys.get(key_id)

    async def _refresh_keys(self) -> None:
        try:
            response = await self.client.get(
                self.jwks_url,
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail="OIDC JWKS 暂时不可用",
            ) from exc
        if response.status_code != 200:
            raise HTTPException(
                status_code=503,
                detail="OIDC JWKS 暂时不可用",
            )
        if response.headers.get(
            "content-encoding",
            "identity",
        ).casefold() != "identity":
            raise HTTPException(
                status_code=503,
                detail="OIDC JWKS 响应格式无效",
            )
        if (
            response.headers.get("content-type", "")
            .split(";", 1)[0]
            .strip()
            .casefold()
            != "application/json"
            or len(response.content) > MAX_JWKS_BYTES
        ):
            raise HTTPException(
                status_code=503,
                detail="OIDC JWKS 响应格式无效",
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=503,
                detail="OIDC JWKS 响应格式无效",
            ) from exc
        raw_keys = payload.get("keys") if isinstance(payload, dict) else None
        if (
            not isinstance(raw_keys, list)
            or not raw_keys
            or len(raw_keys) > MAX_JWKS_KEYS
        ):
            raise HTTPException(
                status_code=503,
                detail="OIDC JWKS 响应格式无效",
            )
        parsed: dict[str, jwt.PyJWK] = {}
        try:
            for raw_key in raw_keys:
                if not isinstance(raw_key, dict):
                    raise ValueError
                key_id = raw_key.get("kid")
                algorithm = raw_key.get("alg")
                if (
                    not isinstance(key_id, str)
                    or not key_id
                    or len(key_id) > 128
                    or algorithm not in ALLOWED_JWT_ALGORITHMS
                    or key_id in parsed
                ):
                    raise ValueError
                parsed[key_id] = jwt.PyJWK.from_dict(
                    raw_key,
                    algorithm=algorithm,
                )
        except (ValueError, jwt.PyJWTError) as exc:
            raise HTTPException(
                status_code=503,
                detail="OIDC JWKS 响应格式无效",
            ) from exc
        self._keys = parsed
        now = time.monotonic()
        self._cache_deadline = now + self.jwks_cache_seconds
        self._hard_cache_deadline = (
            now + self.jwks_hard_cache_seconds
        )

    @staticmethod
    def _permissions(raw: Any) -> frozenset[str]:
        if isinstance(raw, str):
            values = raw.split()
        elif isinstance(raw, list) and all(
            isinstance(value, str) for value in raw
        ):
            values = raw
        else:
            values = []
        return frozenset(
            value
            for value in values
            if 1 <= len(value) <= 200
        )

    @staticmethod
    def _bearer_token(request: Request) -> str:
        values = [
            value
            for name, value in request.scope.get("headers", [])
            if name.lower() == b"authorization"
        ]
        if len(values) != 1 or len(values[0]) > MAX_AUTHORIZATION_BYTES:
            raise OIDCAuthenticator._unauthorized(
                "需要唯一的 Bearer Token"
            )
        try:
            authorization = values[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise OIDCAuthenticator._unauthorized(
                "Bearer Token 格式无效"
            ) from exc
        if (
            not authorization.startswith("Bearer ")
            or not authorization[7:]
            or authorization[7:].strip() != authorization[7:]
        ):
            raise OIDCAuthenticator._unauthorized(
                "Bearer Token 格式无效"
            )
        return authorization[7:]

    @staticmethod
    def _unauthorized(detail: str) -> HTTPException:
        return HTTPException(
            status_code=401,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )
