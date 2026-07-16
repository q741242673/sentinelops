from __future__ import annotations

import json
from typing import Any, TypeVar

import httpx
from openai import AsyncOpenAI
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class OpenAICompatibleProvider:
    """Works with providers exposing an OpenAI-compatible Chat Completions API."""

    name = "openai_compatible"

    def __init__(self, *, model: str, api_key: str, base_url: str | None = None) -> None:
        self.model = model
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=httpx.AsyncClient(trust_env=False),
        )

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
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0,
            )
            content = response.choices[0].message.content
            if not content:
                raise RuntimeError("Model returned an empty structured response")
            try:
                return schema.model_validate_json(content)
            except ValidationError as exc:
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
