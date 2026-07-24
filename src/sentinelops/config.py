from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


def _secret_value(
    direct: SecretStr | str | None,
    file_path: str | None,
    *,
    setting_name: str,
) -> str | None:
    if direct is not None and file_path:
        raise ValueError(
            f"{setting_name} 不能同时通过环境变量和文件配置"
        )
    if direct is not None:
        return (
            direct.get_secret_value()
            if isinstance(direct, SecretStr)
            else direct
        )
    if not file_path:
        return None
    path = Path(file_path)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{setting_name} 的 Secret 文件无法读取") from exc
    if len(payload) > 65_536:
        raise ValueError(f"{setting_name} 的 Secret 文件超过 64 KiB")
    try:
        return payload.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{setting_name} 的 Secret 文件不是 UTF-8 文本") from exc


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SENTINELOPS_",
        extra="ignore",
    )

    environment: str = "development"
    tool_backend: Literal["simulator", "kubernetes"] = "simulator"
    model_provider: Literal["rule_based", "openai_compatible"] = "rule_based"
    model_name: str = "demo"
    model_base_url: str | None = None
    model_api_key: SecretStr | None = None
    model_api_key_file: str | None = None
    model_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    kubernetes_namespace: str = "sentinelops-demo"
    demo_enabled: bool = False
    demo_namespace: str = "sentinelops-demo"
    auto_approve_max_risk: Literal["read_only", "low", "medium", "high", "critical"] = "low"
    prometheus_url: str | None = None
    loki_url: str | None = None
    tempo_url: str | None = None
    observability_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    verification_probe_url: str | None = None
    demo_order_url: str | None = None
    demo_inventory_url: str | None = None
    demo_alert_timeout_seconds: float = Field(default=45.0, gt=0, le=120)
    diagnosis_confidence_threshold: float = Field(default=0.8, ge=0.5, le=1)
    max_reflection_rounds: int = Field(default=1, ge=0, le=3)
    change_repository_path: str | None = None
    change_history_hours: int = Field(default=24, ge=1, le=168)
    change_history_limit: int = Field(default=20, ge=1, le=100)
    database_url: str | None = None
    database_url_file: str | None = None
    database_auto_create: bool = False
    audit_hmac_key: SecretStr | None = None
    audit_hmac_key_file: str | None = None
    audit_key_id: str = Field(default="development-unkeyed", min_length=1, max_length=64)
    audit_anchor_url: str | None = None
    audit_anchor_inventory_url: str | None = None
    audit_anchor_source_id: str = Field(
        default="default",
        min_length=1,
        max_length=128,
    )
    audit_anchor_bearer_token: SecretStr | None = None
    audit_anchor_bearer_token_file: str | None = None
    audit_anchor_reconcile_bearer_token: SecretStr | None = None
    audit_anchor_reconcile_bearer_token_file: str | None = None
    audit_anchor_timeout_seconds: float = Field(default=10, gt=0, le=60)
    audit_anchor_claim_ttl_seconds: float = Field(default=60, ge=10, le=600)
    audit_anchor_poll_interval_seconds: float = Field(default=1, ge=0.1, le=60)
    audit_anchor_retry_base_seconds: float = Field(default=2, ge=0.5, le=60)
    audit_anchor_retry_max_seconds: float = Field(default=300, ge=10, le=3600)
    audit_anchor_reconcile_interval_seconds: float = Field(
        default=60,
        ge=5,
        le=3600,
    )
    audit_anchor_reconcile_max_staleness_seconds: float = Field(
        default=300,
        ge=30,
        le=86_400,
    )
    audit_anchor_enforcement_required: bool = False
    audit_anchor_receipt_public_keys_file: str | None = None
    audit_anchor_trusted_receiver_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )
    audit_anchor_health_file: str | None = None
    anchor_service_database_url: str | None = None
    anchor_service_database_url_file: str | None = None
    anchor_service_bearer_token: SecretStr | None = None
    anchor_service_bearer_token_file: str | None = None
    anchor_service_inventory_bearer_token: SecretStr | None = None
    anchor_service_inventory_bearer_token_file: str | None = None
    anchor_service_allowed_source_id: str = Field(
        default="local-kind",
        min_length=1,
        max_length=128,
    )
    anchor_service_receiver_id: str = Field(
        default="local-reference-anchor",
        min_length=1,
        max_length=128,
    )
    anchor_service_signing_private_key_file: str | None = None
    anchor_service_signing_key_id: str = Field(
        default="local-anchor-receipt-v1",
        min_length=1,
        max_length=64,
    )
    alertmanager_source_id: str = Field(
        default="default",
        min_length=1,
        max_length=128,
    )
    alertmanager_webhook_auth_mode: Literal[
        "disabled",
        "bearer",
        "hmac_sha256",
    ] = "disabled"
    alertmanager_webhook_bearer_token: SecretStr | None = None
    alertmanager_webhook_bearer_token_file: str | None = None
    alertmanager_webhook_signing_secret: SecretStr | None = None
    alertmanager_webhook_signing_secret_file: str | None = None
    alertmanager_webhook_previous_bearer_token: SecretStr | None = None
    alertmanager_webhook_previous_bearer_token_file: str | None = None
    alertmanager_webhook_previous_signing_secret: SecretStr | None = None
    alertmanager_webhook_previous_signing_secret_file: str | None = None
    alertmanager_webhook_previous_secret_expires_at: datetime | None = None
    alertmanager_webhook_signature_ttl_seconds: int = Field(
        default=300,
        ge=30,
        le=3600,
    )
    alertmanager_webhook_signature_future_skew_seconds: int = Field(
        default=30,
        ge=0,
        le=300,
    )
    alertmanager_webhook_max_body_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=10_485_760,
    )
    operator_auth_mode: Literal["disabled", "oidc"] = "disabled"
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_roles_claim: str = Field(
        default="roles",
        min_length=1,
        max_length=128,
    )
    oidc_human_claim: str = Field(
        default="sentinelops_actor_type",
        min_length=1,
        max_length=128,
    )
    oidc_human_value: str = Field(
        default="human",
        min_length=1,
        max_length=128,
    )
    oidc_timeout_seconds: float = Field(default=5, gt=0, le=30)
    oidc_jwks_cache_seconds: float = Field(default=300, ge=30, le=3600)
    oidc_jwks_hard_cache_seconds: float = Field(
        default=900,
        ge=60,
        le=7200,
    )
    oidc_jwks_min_refresh_seconds: float = Field(default=5, ge=1, le=60)
    oidc_clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    oidc_max_token_lifetime_seconds: int = Field(
        default=3600,
        ge=60,
        le=86_400,
    )
    worker_lease_ttl_seconds: float = Field(default=60.0, ge=10, le=600)
    worker_lease_heartbeat_seconds: float = Field(default=15.0, ge=1, le=120)
    worker_reconciliation_interval_seconds: float = Field(
        default=5.0,
        ge=0.1,
        le=60,
    )
    executor_mode: Literal["embedded", "external"] = "embedded"
    executor_claim_ttl_seconds: float = Field(default=60.0, ge=10, le=600)
    executor_poll_interval_seconds: float = Field(default=0.5, ge=0.05, le=10)
    executor_result_timeout_seconds: float = Field(default=120.0, ge=5, le=900)
    executor_health_file: str | None = None

    def resolved_model_api_key(self) -> str | None:
        return _secret_value(
            self.model_api_key,
            self.model_api_key_file,
            setting_name="SENTINELOPS_MODEL_API_KEY",
        )

    def resolved_database_url(self) -> str | None:
        return _secret_value(
            self.database_url,
            self.database_url_file,
            setting_name="SENTINELOPS_DATABASE_URL",
        )

    def resolved_audit_hmac_key(self) -> str | None:
        return _secret_value(
            self.audit_hmac_key,
            self.audit_hmac_key_file,
            setting_name="SENTINELOPS_AUDIT_HMAC_KEY",
        )

    def resolved_audit_anchor_bearer_token(self) -> str | None:
        return _secret_value(
            self.audit_anchor_bearer_token,
            self.audit_anchor_bearer_token_file,
            setting_name="SENTINELOPS_AUDIT_ANCHOR_BEARER_TOKEN",
        )

    def resolved_audit_anchor_reconcile_bearer_token(self) -> str | None:
        return _secret_value(
            self.audit_anchor_reconcile_bearer_token,
            self.audit_anchor_reconcile_bearer_token_file,
            setting_name=(
                "SENTINELOPS_AUDIT_ANCHOR_RECONCILE_BEARER_TOKEN"
            ),
        )

    def resolved_anchor_service_database_url(self) -> str | None:
        return _secret_value(
            self.anchor_service_database_url,
            self.anchor_service_database_url_file,
            setting_name="SENTINELOPS_ANCHOR_SERVICE_DATABASE_URL",
        )

    def resolved_anchor_service_bearer_token(self) -> str | None:
        return _secret_value(
            self.anchor_service_bearer_token,
            self.anchor_service_bearer_token_file,
            setting_name="SENTINELOPS_ANCHOR_SERVICE_BEARER_TOKEN",
        )

    def resolved_anchor_service_inventory_bearer_token(self) -> str | None:
        return _secret_value(
            self.anchor_service_inventory_bearer_token,
            self.anchor_service_inventory_bearer_token_file,
            setting_name=(
                "SENTINELOPS_ANCHOR_SERVICE_INVENTORY_BEARER_TOKEN"
            ),
        )

    def resolved_webhook_bearer_token(self, *, previous: bool = False) -> str | None:
        return _secret_value(
            (
                self.alertmanager_webhook_previous_bearer_token
                if previous
                else self.alertmanager_webhook_bearer_token
            ),
            (
                self.alertmanager_webhook_previous_bearer_token_file
                if previous
                else self.alertmanager_webhook_bearer_token_file
            ),
            setting_name=(
                "SENTINELOPS_ALERTMANAGER_WEBHOOK_PREVIOUS_BEARER_TOKEN"
                if previous
                else "SENTINELOPS_ALERTMANAGER_WEBHOOK_BEARER_TOKEN"
            ),
        )

    def resolved_webhook_signing_secret(self, *, previous: bool = False) -> str | None:
        return _secret_value(
            (
                self.alertmanager_webhook_previous_signing_secret
                if previous
                else self.alertmanager_webhook_signing_secret
            ),
            (
                self.alertmanager_webhook_previous_signing_secret_file
                if previous
                else self.alertmanager_webhook_signing_secret_file
            ),
            setting_name=(
                "SENTINELOPS_ALERTMANAGER_WEBHOOK_PREVIOUS_SIGNING_SECRET"
                if previous
                else "SENTINELOPS_ALERTMANAGER_WEBHOOK_SIGNING_SECRET"
            ),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
