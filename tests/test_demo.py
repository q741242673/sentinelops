from __future__ import annotations

import httpx
import pytest

from sentinelops.config import Settings
from sentinelops.demo import live_demo_alert


@pytest.mark.asyncio
async def test_live_demo_alert_uses_prometheus_and_tempo_context() -> None:
    trace_id = "0123456789abcdef0123456789abcdef"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/checkout":
            return httpx.Response(502, json={"trace_id": trace_id})
        if request.url.path == "/api/v1/alerts":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "alerts": [
                            {
                                "state": "firing",
                                "labels": {
                                    "alertname": "HighInventoryErrorRate",
                                    "namespace": "sentinelops-demo",
                                    "service": "inventory-service",
                                    "severity": "critical",
                                },
                                "annotations": {"summary": "Inventory SLO exceeded"},
                            }
                        ]
                    }
                },
            )
        if request.url.path == f"/api/traces/{trace_id}":
            return httpx.Response(200, json={"batches": [{"scopeSpans": []}]})
        return httpx.Response(404)

    settings = Settings(
        tool_backend="kubernetes",
        demo_order_url="http://order.test",
        prometheus_url="http://prometheus.test",
        tempo_url="http://tempo.test",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        alert = await live_demo_alert(settings, client=client)

    assert alert.service == "inventory-service"
    assert alert.summary == "Inventory SLO exceeded"
    assert alert.labels["trace_id"] == trace_id
