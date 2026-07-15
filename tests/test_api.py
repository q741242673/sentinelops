from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from sentinelops.api import app


@pytest.mark.asyncio
async def test_api_incident_approval_flow() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/api/v1/incidents",
            json={
                "name": "HighOrderServiceErrorRate",
                "namespace": "sentinelops-demo",
                "service": "order-service",
                "severity": "critical",
                "summary": "Order service exceeded its error budget",
            },
        )
        assert created.status_code == 201
        incident = created.json()
        assert incident["status"] == "awaiting_approval"

        decided = await client.post(
            f"/api/v1/incidents/{incident['id']}/approval",
            json={"approved": True, "note": "approved in API test"},
        )
        assert decided.status_code == 200
        assert decided.json()["status"] == "resolved"

        fetched = await client.get(f"/api/v1/incidents/{incident['id']}")
        assert fetched.status_code == 200
        assert fetched.json()["postmortem"].startswith("# Incident")
