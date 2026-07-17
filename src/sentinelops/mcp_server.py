from __future__ import annotations

from typing import Any

from sentinelops.config import get_settings
from sentinelops.tools import build_tool_registry


def create_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - optional integration
        raise RuntimeError('Install the MCP extra first: pip install -e ".[mcp]"') from exc

    settings = get_settings()
    registry = build_tool_registry(settings)
    server = FastMCP("sentinelops-tools")

    async def invoke(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = await registry.call(name, arguments)
        return result.model_dump(mode="json")

    @server.tool()
    async def list_pods(label_selector: str = "") -> dict[str, Any]:
        """List pod health and restart counts in the configured namespace."""
        return await invoke("list_pods", {"label_selector": label_selector})

    @server.tool()
    async def list_events(name: str) -> dict[str, Any]:
        """List recent Kubernetes events bound to one target workload."""
        return await invoke("list_events", {"name": name})

    @server.tool()
    async def get_pod_logs(
        pod_name: str = "", label_selector: str = "app=order-service", tail_lines: int = 200
    ) -> dict[str, Any]:
        """Read a bounded log tail from one pod."""
        arguments: dict[str, Any] = {
            "label_selector": label_selector,
            "tail_lines": min(max(tail_lines, 1), 500),
        }
        if pod_name:
            arguments["pod_name"] = pod_name
        return await invoke("get_pod_logs", arguments)

    @server.tool()
    async def get_rollout_history(name: str) -> dict[str, Any]:
        """Inspect deployment rollout state."""
        return await invoke("get_rollout_history", {"name": name})

    @server.tool()
    async def query_prometheus(query: str, time: str = "") -> dict[str, Any]:
        """Run a bounded, read-only Prometheus instant query."""
        arguments = {"query": query}
        if time:
            arguments["time"] = time
        return await invoke("query_prometheus", arguments)

    @server.tool()
    async def search_loki(
        query: str,
        limit: int = 100,
        start: str = "",
        end: str = "",
    ) -> dict[str, Any]:
        """Search a bounded, read-only range of Loki log streams."""
        arguments: dict[str, Any] = {"query": query, "limit": limit}
        if start:
            arguments["start"] = start
        if end:
            arguments["end"] = end
        return await invoke("search_loki", arguments)

    @server.tool()
    async def get_trace(trace_id: str) -> dict[str, Any]:
        """Fetch a Tempo trace by trace ID."""
        return await invoke("get_trace", {"trace_id": trace_id})

    return server


def main() -> None:
    create_server().run()


if __name__ == "__main__":
    main()
