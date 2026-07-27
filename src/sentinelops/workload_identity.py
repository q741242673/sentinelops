from __future__ import annotations

import asyncio
import hashlib
import json
import re
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
from fastapi import HTTPException, Request

ALLOWED_JWT_ALGORITHMS = frozenset({"RS256", "ES256"})
MAX_AUTHORIZATION_BYTES = 16_384
MAX_CLUSTER_HEADER_BYTES = 128
MAX_TRUST_BUNDLE_BYTES = 1_048_576
MAX_JWKS_BYTES = 262_144
MAX_TOKEN_REVIEW_BYTES = 262_144
MAX_REVIEWER_TOKEN_BYTES = 16_384
MAX_JWKS_KEYS = 100
MAX_TRUSTED_CLUSTERS = 1_000
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")


@dataclass(frozen=True)
class WorkloadTrust:
    cluster_id: str
    display_name: str
    default_namespace: str
    issuer: str
    audience: str
    jwks_url: str
    namespace: str
    service_account: str
    service_account_uid: str
    allowed_capabilities: tuple[str, ...]
    token_review_url: str | None = None
    reviewer_token_file: str | None = None
    token_review_ca_file: str | None = None


@dataclass(frozen=True)
class WorkloadIdentity:
    cluster_id: str
    subject_hash: str
    pod_uid: str
    allowed_capabilities: frozenset[str]
    assurance: str = "kubernetes-oidc"


@dataclass
class _JWKSCache:
    keys: dict[str, jwt.PyJWK]
    cache_deadline: float = 0.0
    hard_cache_deadline: float = 0.0
    last_refresh_attempt: float = 0.0


class WorkloadIdentityAuthenticator:
    """Authenticate cluster-scoped Kubernetes projected ServiceAccount tokens."""

    def __init__(
        self,
        trusts: tuple[WorkloadTrust, ...],
        *,
        production: bool,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 5,
        clock_skew_seconds: int = 30,
        max_token_lifetime_seconds: int = 900,
        jwks_cache_seconds: float = 300,
        jwks_hard_cache_seconds: float = 900,
        jwks_min_refresh_seconds: float = 5,
    ) -> None:
        if not trusts:
            raise ValueError("Workload trust bundle 至少需要一个集群")
        if len(trusts) > MAX_TRUSTED_CLUSTERS:
            raise ValueError("Workload trust bundle 集群数量超出限制")
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("Workload OIDC timeout 必须在 0 到 30 秒之间")
        if not 0 <= clock_skew_seconds <= 300:
            raise ValueError("Workload OIDC clock skew 必须在 0 到 300 秒之间")
        if not 60 <= max_token_lifetime_seconds <= 3_600:
            raise ValueError("Workload OIDC Token 生命周期上限必须在 60 到 3600 秒之间")
        if not 1 <= jwks_min_refresh_seconds <= 60:
            raise ValueError("Workload OIDC JWKS 最短刷新间隔无效")
        if not 30 <= jwks_cache_seconds <= 3_600:
            raise ValueError("Workload OIDC JWKS cache 无效")
        if not jwks_cache_seconds <= jwks_hard_cache_seconds <= 7_200:
            raise ValueError("Workload OIDC JWKS hard cache 必须覆盖普通 cache")

        by_cluster: dict[str, WorkloadTrust] = {}
        identity_bindings: set[tuple[str, str, str, str]] = set()
        for trust in trusts:
            self._validate_trust(trust, production=production)
            if trust.cluster_id in by_cluster:
                raise ValueError(f"Workload trust bundle 重复集群：{trust.cluster_id}")
            binding = (
                trust.issuer,
                trust.namespace,
                trust.service_account,
                trust.service_account_uid,
            )
            if binding in identity_bindings:
                raise ValueError("同一个 Workload 身份不能绑定多个集群")
            by_cluster[trust.cluster_id] = trust
            identity_bindings.add(binding)

        self.trusts = by_cluster
        self.clock_skew_seconds = clock_skew_seconds
        self.max_token_lifetime_seconds = max_token_lifetime_seconds
        self.jwks_cache_seconds = jwks_cache_seconds
        self.jwks_hard_cache_seconds = jwks_hard_cache_seconds
        self.jwks_min_refresh_seconds = jwks_min_refresh_seconds
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            headers={"Accept-Encoding": "identity"},
        )
        self._token_review_clients: dict[str, httpx.AsyncClient] = {}
        self._owned_token_review_clients: list[httpx.AsyncClient] = []
        token_review_clients_by_ca: dict[str, httpx.AsyncClient] = {}
        for cluster_id, trust in by_cluster.items():
            if trust.token_review_url is None:
                continue
            if client is not None:
                self._token_review_clients[cluster_id] = client
                continue
            assert trust.token_review_ca_file is not None
            review_client = token_review_clients_by_ca.get(
                trust.token_review_ca_file
            )
            if review_client is None:
                try:
                    verify = ssl.create_default_context(
                        cafile=trust.token_review_ca_file
                    )
                except (OSError, ssl.SSLError) as exc:
                    raise ValueError(
                        f"Workload TokenReview CA 文件无法读取：{cluster_id}"
                    ) from exc
                review_client = httpx.AsyncClient(
                    timeout=httpx.Timeout(timeout_seconds),
                    follow_redirects=False,
                    trust_env=False,
                    verify=verify,
                    headers={"Accept-Encoding": "identity"},
                )
                token_review_clients_by_ca[
                    trust.token_review_ca_file
                ] = review_client
                self._owned_token_review_clients.append(review_client)
            self._token_review_clients[cluster_id] = review_client
        self._caches = {
            cluster_id: _JWKSCache(keys={}) for cluster_id in by_cluster
        }
        self._refresh_locks = {
            cluster_id: asyncio.Lock() for cluster_id in by_cluster
        }

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        production: bool,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> WorkloadIdentityAuthenticator:
        bundle_path = Path(path)
        try:
            payload = bundle_path.read_bytes()
        except OSError as exc:
            raise ValueError("Workload trust bundle 文件无法读取") from exc
        if len(payload) > MAX_TRUST_BUNDLE_BYTES:
            raise ValueError("Workload trust bundle 文件超过 1 MiB")
        return cls.from_json(
            payload,
            production=production,
            client=client,
            **kwargs,
        )

    @classmethod
    def from_json(
        cls,
        payload: str | bytes,
        *,
        production: bool,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> WorkloadIdentityAuthenticator:
        encoded = payload.encode() if isinstance(payload, str) else payload
        if len(encoded) > MAX_TRUST_BUNDLE_BYTES:
            raise ValueError("Workload trust bundle 超过 1 MiB")
        try:
            raw = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Workload trust bundle 不是有效 JSON") from exc
        if not isinstance(raw, dict) or set(raw) != {"clusters"}:
            raise ValueError("Workload trust bundle 顶层只能包含 clusters")
        clusters = raw["clusters"]
        if (
            not isinstance(clusters, list)
            or not clusters
            or len(clusters) > MAX_TRUSTED_CLUSTERS
        ):
            raise ValueError("Workload trust bundle clusters 无效")
        required = {
            "cluster_id",
            "display_name",
            "default_namespace",
            "issuer",
            "audience",
            "jwks_url",
            "namespace",
            "service_account",
            "service_account_uid",
            "allowed_capabilities",
        }
        token_review_fields = {
            "token_review_url",
            "reviewer_token_file",
            "token_review_ca_file",
        }
        trusts: list[WorkloadTrust] = []
        for item in clusters:
            if not isinstance(item, dict):
                raise ValueError("Workload trust 条目字段不完整或包含未知字段")
            item_fields = set(item)
            allowed_item_fields = (
                (required | token_review_fields,)
                if production
                else (required, required | token_review_fields)
            )
            if all(item_fields != allowed for allowed in allowed_item_fields):
                raise ValueError("Workload trust 条目字段不完整或包含未知字段")
            capabilities = item["allowed_capabilities"]
            if not isinstance(capabilities, list) or not all(
                isinstance(value, str) for value in capabilities
            ):
                raise ValueError("Workload allowed_capabilities 必须是字符串数组")
            values = {
                key: item[key]
                for key in required - {"allowed_capabilities"}
            }
            if not all(isinstance(value, str) for value in values.values()):
                raise ValueError("Workload trust 身份字段必须是字符串")
            review_values = {
                key: item[key]
                for key in token_review_fields
                if key in item
            }
            if not all(
                isinstance(value, str) for value in review_values.values()
            ):
                raise ValueError("Workload TokenReview 配置必须是字符串")
            trusts.append(
                WorkloadTrust(
                    cluster_id=values["cluster_id"],
                    display_name=values["display_name"],
                    default_namespace=values["default_namespace"],
                    issuer=values["issuer"],
                    audience=values["audience"],
                    jwks_url=values["jwks_url"],
                    namespace=values["namespace"],
                    service_account=values["service_account"],
                    service_account_uid=values["service_account_uid"],
                    allowed_capabilities=tuple(capabilities),
                    token_review_url=review_values.get("token_review_url"),
                    reviewer_token_file=review_values.get(
                        "reviewer_token_file"
                    ),
                    token_review_ca_file=review_values.get(
                        "token_review_ca_file"
                    ),
                )
            )
        return cls(
            tuple(trusts),
            production=production,
            client=client,
            **kwargs,
        )

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()
            for client in self._owned_token_review_clients:
                await client.aclose()

    async def authenticate(
        self,
        request: Request,
        *,
        required_capability: str | None = None,
        expected_pod_uid: str | None = None,
    ) -> WorkloadIdentity:
        cluster_id = self._cluster_id(request)
        trust = self.trusts.get(cluster_id)
        if trust is None:
            raise self._unauthorized("Workload 集群身份未登记")
        token = self._bearer_token(request)
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise self._unauthorized("Workload Token 头部无效") from exc
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if (
            "jku" in header
            or "x5u" in header
            or algorithm not in ALLOWED_JWT_ALGORITHMS
            or not isinstance(key_id, str)
            or not key_id
            or len(key_id) > 128
        ):
            raise self._unauthorized("Workload Token 算法或 Key ID 无效")
        key = await self._key(trust, key_id, force_refresh=False)
        if key is None:
            key = await self._key(trust, key_id, force_refresh=True)
        if key is None or key.algorithm_name != algorithm:
            raise self._unauthorized("Workload Token 使用未知签名密钥")
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=[algorithm],
                audience=trust.audience,
                issuer=trust.issuer,
                leeway=self.clock_skew_seconds,
                options={
                    "require": ["exp", "iat", "nbf", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise self._unauthorized("Workload Token 校验失败") from exc

        issued_at = claims.get("iat")
        not_before = claims.get("nbf")
        expires_at = claims.get("exp")
        if (
            not self._numeric_date(issued_at)
            or not self._numeric_date(not_before)
            or not self._numeric_date(expires_at)
            or expires_at <= issued_at
            or not_before > expires_at
            or expires_at - issued_at > self.max_token_lifetime_seconds
        ):
            raise self._unauthorized("Workload Token 生命周期无效")

        subject = claims.get("sub")
        expected_subject = (
            f"system:serviceaccount:{trust.namespace}:{trust.service_account}"
        )
        if subject != expected_subject:
            raise self._forbidden("Workload ServiceAccount subject 不匹配")
        kubernetes_claims = claims.get("kubernetes.io")
        if not isinstance(kubernetes_claims, dict):
            raise self._forbidden("Workload Token 缺少 Kubernetes 绑定信息")
        namespace = kubernetes_claims.get("namespace")
        service_account = kubernetes_claims.get("serviceaccount")
        pod = kubernetes_claims.get("pod")
        if not isinstance(service_account, dict) or not isinstance(pod, dict):
            raise self._forbidden("Workload Token 的 Kubernetes 绑定信息无效")
        if (
            namespace != trust.namespace
            or service_account.get("name") != trust.service_account
            or service_account.get("uid") != trust.service_account_uid
        ):
            raise self._forbidden("Workload ServiceAccount 绑定不匹配")
        pod_uid = pod.get("uid")
        if (
            not isinstance(pod_uid, str)
            or not 1 <= len(pod_uid) <= 128
            or pod_uid.strip() != pod_uid
        ):
            raise self._forbidden("Workload Token 缺少有效 Pod UID")
        if expected_pod_uid is not None and pod_uid != expected_pod_uid:
            raise self._forbidden("Workload Token 的 Pod UID 与实例身份不匹配")
        await self._review_token(
            trust,
            token,
            expected_subject=expected_subject,
        )
        capabilities = frozenset(trust.allowed_capabilities)
        if (
            required_capability is not None
            and required_capability not in capabilities
        ):
            raise self._forbidden("Workload 身份没有所需权限")
        subject_hash = hashlib.sha256(
            (
                f"{trust.cluster_id}\0{trust.issuer}\0"
                f"{expected_subject}\0{trust.service_account_uid}"
            ).encode()
        ).hexdigest()
        return WorkloadIdentity(
            cluster_id=trust.cluster_id,
            subject_hash=subject_hash,
            pod_uid=pod_uid,
            allowed_capabilities=capabilities,
        )

    async def _key(
        self,
        trust: WorkloadTrust,
        key_id: str,
        *,
        force_refresh: bool,
    ) -> jwt.PyJWK | None:
        cache = self._caches[trust.cluster_id]
        now = time.monotonic()
        if not force_refresh and now < cache.cache_deadline:
            return cache.keys.get(key_id)
        async with self._refresh_locks[trust.cluster_id]:
            now = time.monotonic()
            if not force_refresh and now < cache.cache_deadline:
                return cache.keys.get(key_id)
            if (
                force_refresh
                and cache.keys
                and now - cache.last_refresh_attempt
                < self.jwks_min_refresh_seconds
            ):
                return cache.keys.get(key_id)
            cache.last_refresh_attempt = now
            try:
                await self._refresh_keys(trust, cache)
            except HTTPException:
                if key_id in cache.keys and now < cache.hard_cache_deadline:
                    return cache.keys[key_id]
                raise
            return cache.keys.get(key_id)

    async def _refresh_keys(
        self,
        trust: WorkloadTrust,
        cache: _JWKSCache,
    ) -> None:
        try:
            async with self.client.stream(
                "GET",
                trust.jwks_url,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            ) as response:
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=503,
                        detail="Workload OIDC JWKS 暂时不可用",
                    )
                self._require_json_response(
                    response,
                    detail="Workload OIDC JWKS 响应格式无效",
                )
                encoded = await self._bounded_response(
                    response,
                    max_bytes=MAX_JWKS_BYTES,
                    detail="Workload OIDC JWKS 响应格式无效",
                )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail="Workload OIDC JWKS 暂时不可用",
            ) from exc
        try:
            payload = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Workload OIDC JWKS 响应格式无效",
            ) from exc
        raw_keys = payload.get("keys") if isinstance(payload, dict) else None
        if (
            not isinstance(raw_keys, list)
            or not raw_keys
            or len(raw_keys) > MAX_JWKS_KEYS
        ):
            raise HTTPException(
                status_code=503,
                detail="Workload OIDC JWKS 响应格式无效",
            )
        parsed: dict[str, jwt.PyJWK] = {}
        try:
            for raw_key in raw_keys:
                if not isinstance(raw_key, dict):
                    raise ValueError
                key_id = raw_key.get("kid")
                algorithm = raw_key.get("alg")
                key_use = raw_key.get("use")
                key_ops = raw_key.get("key_ops")
                if (
                    not isinstance(key_id, str)
                    or not key_id
                    or len(key_id) > 128
                    or algorithm not in ALLOWED_JWT_ALGORITHMS
                    or key_id in parsed
                    or key_use not in {None, "sig"}
                    or (
                        key_ops is not None
                        and (
                            not isinstance(key_ops, list)
                            or "verify" not in key_ops
                        )
                    )
                ):
                    raise ValueError
                parsed[key_id] = jwt.PyJWK.from_dict(
                    raw_key,
                    algorithm=algorithm,
                )
        except (ValueError, jwt.PyJWTError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Workload OIDC JWKS 响应格式无效",
            ) from exc
        cache.keys = parsed
        now = time.monotonic()
        cache.cache_deadline = now + self.jwks_cache_seconds
        cache.hard_cache_deadline = now + self.jwks_hard_cache_seconds

    async def _review_token(
        self,
        trust: WorkloadTrust,
        token: str,
        *,
        expected_subject: str,
    ) -> None:
        if trust.token_review_url is None:
            return
        assert trust.reviewer_token_file is not None
        reviewer_token = self._read_reviewer_token(trust.reviewer_token_file)
        client = self._token_review_clients.get(trust.cluster_id, self.client)
        try:
            async with client.stream(
                "POST",
                trust.token_review_url,
                headers={
                    "Authorization": f"Bearer {reviewer_token}",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Content-Type": "application/json",
                },
                json={
                    "apiVersion": "authentication.k8s.io/v1",
                    "kind": "TokenReview",
                    "spec": {
                        "token": token,
                        "audiences": [trust.audience],
                    },
                },
            ) as response:
                if response.status_code not in {200, 201}:
                    raise HTTPException(
                        status_code=503,
                        detail="Workload TokenReview 暂时不可用",
                    )
                self._require_json_response(
                    response,
                    detail="Workload TokenReview 响应格式无效",
                )
                encoded = await self._bounded_response(
                    response,
                    max_bytes=MAX_TOKEN_REVIEW_BYTES,
                    detail="Workload TokenReview 响应格式无效",
                )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail="Workload TokenReview 暂时不可用",
            ) from exc
        try:
            payload = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Workload TokenReview 响应格式无效",
            ) from exc
        status = payload.get("status") if isinstance(payload, dict) else None
        if not isinstance(status, dict):
            raise HTTPException(
                status_code=503,
                detail="Workload TokenReview 响应格式无效",
            )
        if status.get("authenticated") is not True:
            raise self._unauthorized("Workload Token 已被集群撤销或拒绝")
        if status.get("error") not in {None, ""}:
            raise HTTPException(
                status_code=503,
                detail="Workload TokenReview 暂时不可用",
            )
        user = status.get("user")
        audiences = status.get("audiences")
        if (
            not isinstance(user, dict)
            or user.get("username") != expected_subject
            or user.get("uid") != trust.service_account_uid
            or not isinstance(audiences, list)
            or audiences != [trust.audience]
        ):
            raise self._forbidden("Workload TokenReview 身份或 audience 不匹配")

    @staticmethod
    def _read_reviewer_token(path: str) -> str:
        try:
            payload = Path(path).read_bytes()
        except OSError as exc:
            raise HTTPException(
                status_code=503,
                detail="Workload TokenReview reviewer Token 不可用",
            ) from exc
        if len(payload) > MAX_REVIEWER_TOKEN_BYTES:
            raise HTTPException(
                status_code=503,
                detail="Workload TokenReview reviewer Token 无效",
            )
        try:
            token = payload.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=503,
                detail="Workload TokenReview reviewer Token 无效",
            ) from exc
        if not token or any(character.isspace() for character in token):
            raise HTTPException(
                status_code=503,
                detail="Workload TokenReview reviewer Token 无效",
            )
        return token

    @staticmethod
    def _require_json_response(
        response: httpx.Response,
        *,
        detail: str,
    ) -> None:
        if response.headers.get(
            "content-encoding",
            "identity",
        ).strip().casefold() not in {"", "identity"}:
            raise HTTPException(status_code=503, detail=detail)
        media_type = (
            response.headers.get("content-type", "")
            .split(";", 1)[0]
            .strip()
            .casefold()
        )
        if media_type != "application/json" and not media_type.endswith("+json"):
            raise HTTPException(status_code=503, detail=detail)

    @staticmethod
    async def _bounded_response(
        response: httpx.Response,
        *,
        max_bytes: int,
        detail: str,
    ) -> bytes:
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError as exc:
                raise HTTPException(status_code=503, detail=detail) from exc
            if declared < 0 or declared > max_bytes:
                raise HTTPException(status_code=503, detail=detail)
        payload = bytearray()
        async for chunk in response.aiter_bytes():
            payload.extend(chunk)
            if len(payload) > max_bytes:
                raise HTTPException(status_code=503, detail=detail)
        return bytes(payload)

    @staticmethod
    def _validate_trust(trust: WorkloadTrust, *, production: bool) -> None:
        if _DNS_LABEL.fullmatch(trust.cluster_id) is None:
            raise ValueError("Workload cluster_id 必须是 DNS label")
        for label, value in (
            ("namespace", trust.namespace),
            ("service_account", trust.service_account),
            ("default_namespace", trust.default_namespace),
        ):
            if _DNS_LABEL.fullmatch(value) is None:
                raise ValueError(f"Workload {label} 必须是 DNS label")
        for label, value, limit in (
            ("display_name", trust.display_name, 128),
            ("audience", trust.audience, 256),
            ("service_account_uid", trust.service_account_uid, 128),
        ):
            if not value or len(value) > limit or value.strip() != value:
                raise ValueError(f"Workload {label} 无效")
        required_scheme = "https" if production else None
        for label, value in (
            ("issuer", trust.issuer),
            ("JWKS URL", trust.jwks_url),
        ):
            parsed = urlsplit(value)
            if (
                not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or (required_scheme and parsed.scheme.casefold() != "https")
                or (
                    not required_scheme
                    and parsed.scheme.casefold() not in {"http", "https"}
                )
            ):
                raise ValueError(f"Workload OIDC {label} 必须是固定且安全的 URL")
        review_values = (
            trust.token_review_url,
            trust.reviewer_token_file,
            trust.token_review_ca_file,
        )
        if production and any(value is None for value in review_values):
            raise ValueError("生产 Workload 身份必须配置在线 TokenReview")
        if any(value is not None for value in review_values) and any(
            value is None for value in review_values
        ):
            raise ValueError("Workload TokenReview 配置必须完整")
        if trust.token_review_url is not None:
            parsed = urlsplit(trust.token_review_url)
            if (
                not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or (
                    production
                    and parsed.scheme.casefold() != "https"
                )
                or (
                    not production
                    and parsed.scheme.casefold() not in {"http", "https"}
                )
            ):
                raise ValueError(
                    "Workload TokenReview URL 必须是固定且安全的 URL"
                )
            assert trust.reviewer_token_file is not None
            assert trust.token_review_ca_file is not None
            if production and (
                not Path(trust.reviewer_token_file).is_absolute()
                or not Path(trust.token_review_ca_file).is_absolute()
            ):
                raise ValueError(
                    "生产 Workload TokenReview 凭据和 CA 必须使用绝对文件路径"
                )
        if (
            not trust.allowed_capabilities
            or len(trust.allowed_capabilities)
            != len(set(trust.allowed_capabilities))
            or any(
                _CAPABILITY.fullmatch(capability) is None
                for capability in trust.allowed_capabilities
            )
        ):
            raise ValueError("Workload allowed_capabilities 无效")

    @staticmethod
    def _cluster_id(request: Request) -> str:
        values = [
            value
            for name, value in request.scope.get("headers", [])
            if name.lower() == b"x-sentinelops-cluster-id"
        ]
        if (
            len(values) != 1
            or not values[0]
            or len(values[0]) > MAX_CLUSTER_HEADER_BYTES
        ):
            raise WorkloadIdentityAuthenticator._unauthorized(
                "需要唯一的 X-SentinelOps-Cluster-ID"
            )
        try:
            cluster_id = values[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise WorkloadIdentityAuthenticator._unauthorized(
                "X-SentinelOps-Cluster-ID 格式无效"
            ) from exc
        if _DNS_LABEL.fullmatch(cluster_id) is None:
            raise WorkloadIdentityAuthenticator._unauthorized(
                "X-SentinelOps-Cluster-ID 格式无效"
            )
        return cluster_id

    @staticmethod
    def _bearer_token(request: Request) -> str:
        values = [
            value
            for name, value in request.scope.get("headers", [])
            if name.lower() == b"authorization"
        ]
        if len(values) != 1 or len(values[0]) > MAX_AUTHORIZATION_BYTES:
            raise WorkloadIdentityAuthenticator._unauthorized(
                "需要唯一的 Bearer Token"
            )
        try:
            authorization = values[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise WorkloadIdentityAuthenticator._unauthorized(
                "Bearer Token 格式无效"
            ) from exc
        if (
            not authorization.startswith("Bearer ")
            or not authorization[7:]
            or authorization[7:].strip() != authorization[7:]
        ):
            raise WorkloadIdentityAuthenticator._unauthorized(
                "Bearer Token 格式无效"
            )
        return authorization[7:]

    @staticmethod
    def _numeric_date(value: object) -> bool:
        return not isinstance(value, bool) and isinstance(value, (int, float))

    @staticmethod
    def _unauthorized(detail: str) -> HTTPException:
        return HTTPException(
            status_code=401,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

    @staticmethod
    def _forbidden(detail: str) -> HTTPException:
        return HTTPException(status_code=403, detail=detail)
