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
    auto_approve_max_risk: Literal["read_only", "low", "medium", "high", "critical"] = "low"
    prometheus_url: str | None = None
    loki_url: str | None = None
    tempo_url: str | None = None
    observability_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    demo_order_url: str | None = None
    demo_inventory_url: str | None = None
    demo_alert_timeout_seconds: float = Field(default=45.0, gt=0, le=120)


@lru_cache
def get_settings() -> Settings:
    return Settings()
