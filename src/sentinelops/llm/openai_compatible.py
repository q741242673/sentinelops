from __future__ import annotations

import json
from time import perf_counter
from typing import Any, TypeVar

import httpx
from openai import AsyncOpenAI
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class ModelCallMetric(BaseModel):
    """Bounded model telemetry that never stores prompts or responses."""

    model: str
    schema_name: str
    node: str | None = None
    attempt: int
    request_succeeded: bool
    valid_output: bool
    duration_ms: float
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    error_type: str | None = None


class OpenAICompatibleProvider:
    """Works with providers exposing an OpenAI-compatible Chat Completions API."""

    name = "openai_compatible"

    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        base_url: str | None = None,
        timeout_seconds: float = 60,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.model = model
        self.call_metrics: list[ModelCallMetric] = []
        timeout = httpx.Timeout(
            timeout_seconds,
            connect=min(timeout_seconds, 10),
        )
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=1,
            http_client=httpx.AsyncClient(timeout=timeout, trust_env=False),
        )

    def metrics_snapshot(self) -> list[ModelCallMetric]:
        return [metric.model_copy(deep=True) for metric in self.call_metrics]

    def reset_metrics(self) -> None:
        self.call_metrics.clear()

    async def structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: type[T],
        metadata: dict[str, Any] | None = None,
    ) -> T:
        schema_json = json.dumps(schema.model_json_schema(), ensure_ascii=False)
        messages: list[dict[str, str]] = [
            {
                "role": "system",
                "content": (
                    f"{system}\nReturn only a complete JSON object matching this JSON Schema. "
                    f"Every required field must be present: {schema_json}"
                ),
            },
            {"role": "user", "content": prompt},
        ]
        for attempt in range(2):
            started = perf_counter()
            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=0,
                )
            except Exception as exc:
                self.call_metrics.append(
                    ModelCallMetric(
                        model=self.model,
                        schema_name=schema.__name__,
                        node=(
                            str(metadata.get("node"))
                            if metadata and metadata.get("node")
                            else None
                        ),
                        attempt=attempt + 1,
                        request_succeeded=False,
                        valid_output=False,
                        duration_ms=round((perf_counter() - started) * 1000, 3),
                        error_type=type(exc).__name__,
                    )
                )
                raise RuntimeError(
                    f"Model request failed: {type(exc).__name__}"
                ) from exc
            usage = getattr(response, "usage", None)
            metric = ModelCallMetric(
                model=self.model,
                schema_name=schema.__name__,
                node=str(metadata.get("node")) if metadata and metadata.get("node") else None,
                attempt=attempt + 1,
                request_succeeded=True,
                valid_output=False,
                duration_ms=round((perf_counter() - started) * 1000, 3),
                input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
                output_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
                total_tokens=int(getattr(usage, "total_tokens", 0) or 0),
            )
            content = response.choices[0].message.content
            if not content:
                self.call_metrics.append(metric)
                raise RuntimeError("Model returned an empty structured response")
            try:
                result = schema.model_validate_json(content)
                metric.valid_output = True
                self.call_metrics.append(metric)
                return result
            except ValidationError as exc:
                self.call_metrics.append(metric)
                if attempt == 1:
                    raise RuntimeError(
                        f"Model failed to produce valid {schema.__name__} JSON after correction"
                    ) from exc
                errors = json.dumps(
                    exc.errors(include_input=False, include_url=False),
                    ensure_ascii=False,
                )
                messages.extend(
                    [
                        {"role": "assistant", "content": content},
                        {
                            "role": "user",
                            "content": (
                                "Correct the JSON so it fully matches the schema. Return only the "
                                f"complete corrected object. Validation errors: {errors}"
                            ),
                        },
                    ]
                )
        raise AssertionError("Structured output retry loop exited unexpectedly")
