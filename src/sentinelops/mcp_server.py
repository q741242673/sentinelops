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
    server = FastMCP("sentinelops-kubernetes")

    async def invoke(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = await registry.call(name, arguments)
        return result.model_dump(mode="json")

    @server.tool()
    async def list_pods(label_selector: str = "") -> dict[str, Any]:
        """List pod health and restart counts in the configured namespace."""
        return await invoke("list_pods", {"label_selector": label_selector})

    @server.tool()
    async def list_events() -> dict[str, Any]:
        """List recent Kubernetes events in the configured namespace."""
        return await invoke("list_events", {})

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
    async def restart_deployment(name: str) -> dict[str, Any]:
        """Trigger a rolling restart. The host must enforce human approval."""
        return await invoke("restart_deployment", {"name": name})

    @server.tool()
    async def rollback_deployment(name: str, revision: int) -> dict[str, Any]:
        """Restore a deployment revision. The host must enforce human approval."""
        return await invoke("rollback_deployment", {"name": name, "revision": revision})

    @server.tool()
    async def scale_deployment(name: str, replicas: int) -> dict[str, Any]:
        """Scale a deployment. The host must enforce human approval."""
        return await invoke("scale_deployment", {"name": name, "replicas": replicas})

    return server


def main() -> None:
    create_server().run()


if __name__ == "__main__":
    main()
