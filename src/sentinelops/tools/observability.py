from __future__ import annotations

import re
import time
from typing import Any

import httpx

from sentinelops.domain import ToolResult


class ObservabilityBackend:
    """Read-only adapters for Prometheus, Loki, and Tempo HTTP APIs."""

    MAX_QUERY_LENGTH = 1_000
    MAX_LOKI_LIMIT = 200

    def __init__(
        self,
        *,
        prometheus_url: str | None = None,
        loki_url: str | None = None,
        tempo_url: str | None = None,
        timeout_seconds: float = 10,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.prometheus_url = self._normalize_url(prometheus_url)
        self.loki_url = self._normalize_url(loki_url)
        self.tempo_url = self._normalize_url(tempo_url)
        self.client = client or httpx.AsyncClient(timeout=timeout_seconds, trust_env=False)

    @staticmethod
    def _normalize_url(value: str | None) -> str | None:
        return value.rstrip("/") if value else None

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        started = time.perf_counter()
        handler = getattr(self, f"_tool_{name}", None)
        if handler is None:
            return ToolResult(tool_name=name, success=False, error=f"Unknown tool: {name}")
        try:
            content = await handler(arguments)
            return ToolResult(
                tool_name=name,
                success=True,
                content=content,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=name,
                success=False,
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )

    def _bounded_query(self, arguments: dict[str, Any]) -> str:
        query = str(arguments.get("query", "")).strip()
        if not query:
            raise ValueError("query is required")
        if len(query) > self.MAX_QUERY_LENGTH:
            raise ValueError(f"query exceeds {self.MAX_QUERY_LENGTH} characters")
        return query

    async def _tool_query_prometheus(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self.prometheus_url:
            raise RuntimeError("Prometheus URL is not configured")
        query = self._bounded_query(arguments)
        params: dict[str, Any] = {"query": query}
        if arguments.get("time"):
            params["time"] = arguments["time"]
        response = await self.client.get(
            f"{self.prometheus_url}/api/v1/query",
            params=params,
        )
        payload = self._validated_payload(response)
        data = payload.get("data", {})
        return {
            "source": "prometheus",
            "query": query,
            "result_type": data.get("resultType"),
            "result": data.get("result", []),
        }

    async def _tool_search_loki(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self.loki_url:
            raise RuntimeError("Loki URL is not configured")
        query = self._bounded_query(arguments)
        limit = min(max(int(arguments.get("limit", 100)), 1), self.MAX_LOKI_LIMIT)
        params: dict[str, Any] = {
            "query": query,
            "limit": limit,
            "direction": "backward",
        }
        if arguments.get("start"):
            params["start"] = arguments["start"]
        if arguments.get("end"):
            params["end"] = arguments["end"]
        response = await self.client.get(
            f"{self.loki_url}/loki/api/v1/query_range",
            params=params,
        )
        payload = self._validated_payload(response)
        data = payload.get("data", {})
        return {
            "source": "loki",
            "query": query,
            "limit": limit,
            "result_type": data.get("resultType"),
            "result": data.get("result", []),
        }

    async def _tool_get_trace(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self.tempo_url:
            raise RuntimeError("Tempo URL is not configured")
        trace_id = str(arguments.get("trace_id", "")).strip()
        if not re.fullmatch(r"[0-9a-fA-F]{16,64}", trace_id):
            raise ValueError("trace_id must be a 16-64 character hexadecimal value")
        response = await self.client.get(f"{self.tempo_url}/api/traces/{trace_id}")
        response.raise_for_status()
        return {"source": "tempo", "trace_id": trace_id, "trace": response.json()}

    @staticmethod
    def _validated_payload(response: httpx.Response) -> dict[str, Any]:
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") != "success":
            raise RuntimeError(
                f"Observability query failed: {payload.get('error', 'unknown error')}"
            )
        return payload
