from __future__ import annotations

from sentinelops.config import Settings
from sentinelops.llm.base import LLMProvider
from sentinelops.llm.openai_compatible import OpenAICompatibleProvider
from sentinelops.llm.rule_based import RuleBasedProvider


def build_provider(settings: Settings) -> LLMProvider:
    if settings.model_provider == "rule_based":
        return RuleBasedProvider()
    if not settings.model_api_key:
        raise ValueError("SENTINELOPS_MODEL_API_KEY is required for remote model providers")
    return OpenAICompatibleProvider(
        model=settings.model_name,
        api_key=settings.model_api_key.get_secret_value(),
        base_url=settings.model_base_url,
    )
