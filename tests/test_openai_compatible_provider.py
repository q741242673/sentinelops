from __future__ import annotations

import pytest

from sentinelops.llm.openai_compatible import OpenAICompatibleProvider


@pytest.mark.asyncio
async def test_provider_ignores_ambient_socks_proxy(monkeypatch) -> None:
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:1080")

    provider = OpenAICompatibleProvider(
        model="test-model",
        api_key="test-key",
        base_url="https://model.example/v1",
    )

    assert provider.name == "openai_compatible"
    await provider.client.close()
