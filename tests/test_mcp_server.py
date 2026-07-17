from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import Mock

from sentinelops import mcp_server
from sentinelops.config import Settings
from sentinelops.tools.kubernetes import KubernetesBackend
from sentinelops.tools.registry import ToolRegistry


class FakeFastMCP:
    def __init__(self, name: str) -> None:
        self.name = name
        self.registered_tools: dict[str, object] = {}

    def tool(self):
        def register(function):
            self.registered_tools[function.__name__] = function
            return function

        return register


def test_kubernetes_mcp_exposes_only_read_only_evidence_tools(monkeypatch) -> None:
    mcp_package = ModuleType("mcp")
    server_package = ModuleType("mcp.server")
    fastmcp_module = ModuleType("mcp.server.fastmcp")
    fastmcp_module.FastMCP = FakeFastMCP  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mcp", mcp_package)
    monkeypatch.setitem(sys.modules, "mcp.server", server_package)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fastmcp_module)

    backend = KubernetesBackend.__new__(KubernetesBackend)
    backend.apps = Mock()
    backend.core = Mock()
    registry = ToolRegistry(backend)
    monkeypatch.setattr(
        mcp_server,
        "get_settings",
        lambda: Settings(tool_backend="kubernetes", model_provider="rule_based"),
    )
    monkeypatch.setattr(mcp_server, "build_tool_registry", lambda settings: registry)

    server = mcp_server.create_server()

    assert set(server.registered_tools) == {
        "list_pods",
        "list_events",
        "get_pod_logs",
        "get_rollout_history",
        "query_prometheus",
        "search_loki",
        "get_trace",
    }
    assert not {
        "restart_deployment",
        "rollback_deployment",
        "scale_deployment",
    }.intersection(server.registered_tools)
