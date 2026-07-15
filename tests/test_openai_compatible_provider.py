from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import BaseModel

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


class ExampleOutput(BaseModel):
    required_field: str


@pytest.mark.asyncio
async def test_provider_repairs_invalid_structured_output() -> None:
    provider = OpenAICompatibleProvider(
        model="test-model",
        api_key="test-key",
        base_url="https://model.example/v1",
    )
    create = AsyncMock(
        side_effect=[
            SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content='{"wrong": true}'))]
            ),
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content='{"required_field": "repaired"}')
                    )
                ]
            ),
        ]
    )
    provider.client.chat.completions.create = create

    result = await provider.structured(
        system="Return test data",
        prompt="Build the object",
        schema=ExampleOutput,
    )

    assert result.required_field == "repaired"
    assert create.await_count == 2
    correction_messages = create.await_args_list[1].kwargs["messages"]
    assert "Validation errors" in correction_messages[-1]["content"]
    await provider.client.close()
