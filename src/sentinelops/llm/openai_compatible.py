from __future__ import annotations

import json
from typing import Any, TypeVar

from openai import AsyncOpenAI
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class OpenAICompatibleProvider:
    """Works with providers exposing an OpenAI-compatible Chat Completions API."""

    name = "openai_compatible"

    def __init__(self, *, model: str, api_key: str, base_url: str | None = None) -> None:
        self.model = model
        self.client = AsyncOpenAI(api_key=api_key, base_url=base_url)

    async def structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: type[T],
        metadata: dict[str, Any] | None = None,
    ) -> T:
        schema_json = json.dumps(schema.model_json_schema(), ensure_ascii=False)
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        f"{system}\nReturn only a JSON object matching this JSON Schema: "
                        f"{schema_json}"
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )
        content = response.choices[0].message.content
        if not content:
            raise RuntimeError("Model returned an empty structured response")
        return schema.model_validate_json(content)
