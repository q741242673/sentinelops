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
    metrics = provider.metrics_snapshot()
    assert len(metrics) == 2
    assert metrics[0].request_succeeded is True
    assert metrics[0].valid_output is False
    assert metrics[1].valid_output is True
    assert all(metric.schema_name == "ExampleOutput" for metric in metrics)
    await provider.client.close()


@pytest.mark.asyncio
async def test_provider_records_usage_without_prompts_or_responses() -> None:
    provider = OpenAICompatibleProvider(
        model="test-model",
        api_key="test-key",
        base_url="https://model.example/v1",
        timeout_seconds=12,
    )
    provider.client.chat.completions.create = AsyncMock(
        return_value=SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content='{"required_field": "ok"}')
                )
            ],
            usage=SimpleNamespace(
                prompt_tokens=123,
                completion_tokens=17,
                total_tokens=140,
            ),
        )
    )

    await provider.structured(
        system="Return test data",
        prompt="Build the object",
        schema=ExampleOutput,
        metadata={"node": "diagnose", "incident_id": "must-not-be-recorded"},
    )

    payload = provider.metrics_snapshot()[0].model_dump(mode="json")
    assert payload["node"] == "diagnose"
    assert payload["input_tokens"] == 123
    assert payload["output_tokens"] == 17
    assert payload["total_tokens"] == 140
    assert "incident_id" not in payload
    assert "prompt" not in payload
    assert "response" not in payload
    await provider.client.close()


@pytest.mark.asyncio
async def test_provider_normalizes_remote_failure_and_records_safe_error_type() -> None:
    provider = OpenAICompatibleProvider(
        model="test-model",
        api_key="test-key",
        base_url="https://model.example/v1",
    )
    provider.client.chat.completions.create = AsyncMock(
        side_effect=TimeoutError("contains upstream details"),
    )

    with pytest.raises(RuntimeError, match="Model request failed: TimeoutError"):
        await provider.structured(
            system="Return test data",
            prompt="Build the object",
            schema=ExampleOutput,
        )

    metric = provider.metrics_snapshot()[0]
    assert metric.request_succeeded is False
    assert metric.error_type == "TimeoutError"
    assert "upstream" not in metric.model_dump_json()
    await provider.client.close()


def test_provider_rejects_non_positive_deadline() -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        OpenAICompatibleProvider(
            model="test-model",
            api_key="test-key",
            timeout_seconds=0,
        )
