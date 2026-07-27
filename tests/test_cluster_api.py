from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

import sentinelops.api as api_module
from sentinelops.api import app
from sentinelops.config import Settings
from sentinelops.storage import SqlIncidentStore


@pytest.mark.asyncio
async def test_cluster_directory_uses_database_leases(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        cluster_id="cluster-a",
        cluster_display_name="生产集群 A",
        kubernetes_namespace="orders",
        executor_mode="external",
    )
    monkeypatch.setattr(api_module, "get_settings", lambda: settings)
    store = SqlIncidentStore(
        f"sqlite+aiosqlite:///{tmp_path / 'clusters.db'}"
    )
    await api_module.initialize_persistence(store, create_schema=True)
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as client:
            offline = await client.get("/api/v1/clusters")
            assert offline.status_code == 200
            assert offline.json() == [
                {
                    "cluster_id": "cluster-a",
                    "display_name": "生产集群 A",
                    "default_namespace": "orders",
                    "connection_status": "offline",
                    "routing_generation": 1,
                    "active_executors": 0,
                    "last_seen_at": None,
                    "lease_expires_at": None,
                    "capabilities": [],
                    "executors": [],
                }
            ]

            lease = await store.register_cluster_agent(
                cluster_id="cluster-a",
                instance_id="executor-a",
                session_id="a" * 32,
                capabilities=("action.execute", "action.reconcile"),
                version="test",
                ttl_seconds=60,
            )
            online = await client.get("/api/v1/clusters/cluster-a")
            assert online.status_code == 200
            payload = online.json()
            assert payload["connection_status"] == "online"
            assert payload["active_executors"] == 1
            assert payload["capabilities"] == [
                "action.execute",
                "action.reconcile",
            ]
            assert payload["executors"][0]["instance_id"] == "executor-a"
            assert payload["executors"][0]["session_id"] == "a" * 32

            await store.close_cluster_agent(lease)
            closed = await client.get("/api/v1/clusters/cluster-a")
            assert closed.status_code == 200
            assert closed.json()["connection_status"] == "offline"
            assert closed.json()["active_executors"] == 0

            missing = await client.get("/api/v1/clusters/cluster-b")
            assert missing.status_code == 404
    finally:
        await api_module.shutdown_persistence()
