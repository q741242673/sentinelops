from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, Field

from sentinelops.domain import RiskLevel, ToolResult


class ToolSpec(BaseModel):
    name: str
    description: str
    risk: RiskLevel
    input_schema: dict[str, Any] = Field(default_factory=dict)


class ToolBackend(Protocol):
    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult: ...
