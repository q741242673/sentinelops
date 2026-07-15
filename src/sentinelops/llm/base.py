from __future__ import annotations

from typing import Any, Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMProvider(Protocol):
    """Provider-neutral contract used by the agent graph."""

    name: str

    async def structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: type[T],
        metadata: dict[str, Any] | None = None,
    ) -> T: ...
