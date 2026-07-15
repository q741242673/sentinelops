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


class CompositeBackend:
    """Routes allowlisted tool names to focused backend implementations."""

    def __init__(self, routes: dict[str, ToolBackend]) -> None:
        self.routes = routes

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        backend = self.routes.get(name)
        if backend is None:
            return ToolResult(tool_name=name, success=False, error="No backend configured for tool")
        return await backend.call(name, arguments)
