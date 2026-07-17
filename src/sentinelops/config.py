from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    kubernetes_namespace: str = "sentinelops-demo"
    demo_enabled: bool = False
    demo_namespace: str = "sentinelops-demo"
    auto_approve_max_risk: Literal["read_only", "low", "medium", "high", "critical"] = "low"
    prometheus_url: str | None = None
    loki_url: str | None = None
    tempo_url: str | None = None
    observability_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    demo_order_url: str | None = None
    demo_inventory_url: str | None = None
    demo_alert_timeout_seconds: float = Field(default=45.0, gt=0, le=120)
    diagnosis_confidence_threshold: float = Field(default=0.8, ge=0.5, le=1)
    max_reflection_rounds: int = Field(default=1, ge=0, le=3)
    change_repository_path: str | None = None
    change_history_hours: int = Field(default=24, ge=1, le=168)
    change_history_limit: int = Field(default=20, ge=1, le=100)


@lru_cache
def get_settings() -> Settings:
    return Settings()
