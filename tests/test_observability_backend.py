from __future__ import annotations

import httpx
import pytest

from sentinelops.tools.observability import ObservabilityBackend


@pytest.mark.asyncio
async def test_prometheus_query_is_normalized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/query"
        assert request.url.params["query"] == "up"
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [{"metric": {"job": "demo"}, "value": [1, "1"]}],
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        backend = ObservabilityBackend(prometheus_url="http://prometheus:9090/", client=client)
        result = await backend.call("query_prometheus", {"query": "up"})

    assert result.success is True
    assert result.content["source"] == "prometheus"
    assert result.content["result_type"] == "vector"
    assert result.content["result"][0]["metric"]["job"] == "demo"


@pytest.mark.asyncio
async def test_loki_limit_is_bounded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/loki/api/v1/query_range"
        assert request.url.params["limit"] == "200"
        assert request.url.params["direction"] == "backward"
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {"resultType": "streams", "result": []},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        backend = ObservabilityBackend(loki_url="http://loki:3100", client=client)
        result = await backend.call(
            "search_loki",
            {"query": '{app="order-service"}', "limit": 10_000},
        )

    assert result.success is True
    assert result.content["limit"] == 200


@pytest.mark.asyncio
async def test_tempo_rejects_non_hex_trace_id_before_request() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: None)) as client:
        backend = ObservabilityBackend(tempo_url="http://tempo:3200", client=client)
        result = await backend.call("get_trace", {"trace_id": "../../secrets"})

    assert result.success is False
    assert "hexadecimal" in result.error


@pytest.mark.asyncio
async def test_unconfigured_backend_returns_tool_error() -> None:
    backend = ObservabilityBackend()
    result = await backend.call("query_prometheus", {"query": "up"})
    assert result.success is False
    assert result.error == "Prometheus URL is not configured"
