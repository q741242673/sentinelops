from __future__ import annotations

import asyncio
from typing import Any

import httpx

from sentinelops.config import Settings
from sentinelops.domain import Alert
from sentinelops.tools.kubernetes import KubernetesBackend


def simulated_demo_alert(settings: Settings) -> Alert:
    return Alert(
        name="HighOrderServiceErrorRate",
        namespace=settings.kubernetes_namespace,
        service="order-service",
        severity="critical",
        summary="Order service error rate exceeded the 5% SLO threshold",
        labels={"source": "local-console", "scenario": "bad_rollout"},
    )


async def _find_failed_trace(
    client: httpx.AsyncClient,
    order_url: str,
    timeout_seconds: float,
) -> str:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        response = await client.post(f"{order_url.rstrip('/')}/checkout")
        payload = response.json()
        if response.status_code == 502 and payload.get("trace_id"):
            return str(payload["trace_id"])
        await asyncio.sleep(0.25)
    raise RuntimeError("Live demo traffic did not produce a failed checkout trace")


async def _wait_for_firing_alert(
    client: httpx.AsyncClient,
    prometheus_url: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        response = await client.get(f"{prometheus_url.rstrip('/')}/api/v1/alerts")
        response.raise_for_status()
        alerts = response.json().get("data", {}).get("alerts", [])
        match = next(
            (
                alert
                for alert in alerts
                if alert.get("labels", {}).get("alertname") == "HighInventoryErrorRate"
                and alert.get("state") == "firing"
            ),
            None,
        )
        if match:
            return match
        await asyncio.sleep(1)
    raise RuntimeError("Prometheus HighInventoryErrorRate alert did not become firing")


async def _wait_for_trace(
    client: httpx.AsyncClient,
    tempo_url: str | None,
    trace_id: str,
    timeout_seconds: float,
) -> None:
    if not tempo_url:
        return
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        response = await client.get(f"{tempo_url.rstrip('/')}/api/traces/{trace_id}")
        if response.status_code == 200:
            trace = response.json()
            if trace.get("batches") or trace.get("resourceSpans"):
                return
        await asyncio.sleep(0.5)
    raise RuntimeError(f"Tempo trace {trace_id} did not become queryable")


async def live_demo_alert(
    settings: Settings,
    *,
    client: httpx.AsyncClient | None = None,
) -> Alert:
    if not settings.demo_order_url:
        raise RuntimeError("SENTINELOPS_DEMO_ORDER_URL is required for the live console")
    if not settings.prometheus_url:
        raise RuntimeError("SENTINELOPS_PROMETHEUS_URL is required for the live console")

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=5, trust_env=False)
    try:
        trace_id = await _find_failed_trace(
            client,
            settings.demo_order_url,
            settings.demo_alert_timeout_seconds,
        )
        firing_alert, _ = await asyncio.gather(
            _wait_for_firing_alert(
                client,
                settings.prometheus_url,
                settings.demo_alert_timeout_seconds,
            ),
            _wait_for_trace(
                client,
                settings.tempo_url,
                trace_id,
                settings.demo_alert_timeout_seconds,
            ),
        )
    finally:
        if owns_client:
            await client.aclose()

    labels = {str(key): str(value) for key, value in firing_alert.get("labels", {}).items()}
    annotations = firing_alert.get("annotations", {})
    labels["trace_id"] = trace_id
    return Alert(
        name=labels.get("alertname", "HighInventoryErrorRate"),
        namespace=labels.get("namespace", settings.kubernetes_namespace),
        service=labels.get("service", "inventory-service"),
        severity="critical",
        summary=str(
            annotations.get("summary", "Inventory HTTP 503 rate exceeded the checkout SLO")
        ),
        labels=labels,
    )


async def build_demo_alert(settings: Settings) -> Alert:
    if settings.tool_backend == "simulator":
        return simulated_demo_alert(settings)
    return await live_demo_alert(settings)


async def enrich_alert_with_failed_trace(settings: Settings, alert: Alert) -> Alert:
    """Attach a fresh failed checkout trace to an event-driven demo alert."""
    if not settings.demo_order_url:
        return alert
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        trace_id = await _find_failed_trace(
            client,
            settings.demo_order_url,
            settings.demo_alert_timeout_seconds,
        )
        await _wait_for_trace(
            client,
            settings.tempo_url,
            trace_id,
            settings.demo_alert_timeout_seconds,
        )
    return alert.model_copy(update={"labels": {**alert.labels, "trace_id": trace_id}})


async def inject_demo_fault(settings: Settings) -> dict[str, Any]:
    if settings.tool_backend == "simulator":
        return {
            "deployment": "order-service",
            "fault_active": True,
            "already_active": False,
            "revision": 2,
            "failure_every": "simulated",
        }
    backend = KubernetesBackend(namespace=settings.kubernetes_namespace)
    result = await backend.call(
        "inject_demo_fault",
        {
            "name": "inventory-service",
            "timeout_seconds": settings.demo_alert_timeout_seconds,
        },
    )
    if not result.success:
        raise RuntimeError(result.error or "Failed to inject the live demo fault")
    return result.content


async def inject_auto_demo_fault(settings: Settings) -> dict[str, Any]:
    if settings.tool_backend == "simulator":
        return {
            "service": "inventory-service",
            "fault_active": True,
            "fault_type": "transient_runtime_fault",
        }
    if not settings.demo_inventory_url:
        raise RuntimeError("SENTINELOPS_DEMO_INVENTORY_URL is required for the auto demo")
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        try:
            response = await _post_with_transport_retry(
                client,
                f"{settings.demo_inventory_url.rstrip('/')}/demo/transient-fault",
            )
        except httpx.TransportError as exc:
            raise RuntimeError(
                "连接 inventory-service 失败；本地 port-forward 已重试 5 次，"
                "请稍后再次启动演示"
            ) from exc
        response.raise_for_status()
        return dict(response.json())


async def reset_demo_environment(settings: Settings) -> dict[str, Any]:
    """Explicit operator cleanup after a deliberately escalated demo incident."""
    if settings.tool_backend == "simulator":
        return {"deployment": "inventory-service", "baseline_restored": True}
    backend = KubernetesBackend(namespace=settings.kubernetes_namespace)
    history = await backend.call("get_rollout_history", {"name": "inventory-service"})
    if not history.success:
        raise RuntimeError(history.error or "Could not inspect demo rollout history")
    revisions = history.content.get("revisions", [])
    active = [
        item
        for item in revisions
        if (item.get("replicas") or 0) > 0 or (item.get("ready_replicas") or 0) > 0
    ]
    if not active:
        raise RuntimeError("No active inventory-service revision was found")
    current = max(active, key=lambda item: int(item.get("revision", 0)))
    previous = [
        item
        for item in revisions
        if int(item.get("revision", 0)) < int(current.get("revision", 0))
    ]
    if not previous:
        raise RuntimeError("No prior inventory-service revision was found")
    target = max(previous, key=lambda item: int(item.get("revision", 0)))
    rollback = await backend.call(
        "rollback_deployment",
        {"name": "inventory-service", "revision": int(target["revision"])},
    )
    if not rollback.success:
        raise RuntimeError(rollback.error or "Could not restore the demo baseline")

    for _ in range(60):
        metrics, pods = await asyncio.gather(
            backend.call("get_service_metrics", {"name": "inventory-service"}),
            backend.call("list_pods", {"label_selector": "app=inventory-service"}),
        )
        pod_items = pods.content.get("items", [])
        if (
            metrics.success
            and metrics.content.get("availability") == 1
            and pods.success
            and pod_items
            and all(item.get("ready") for item in pod_items)
        ):
            return {
                "deployment": "inventory-service",
                "baseline_restored": True,
                "source_revision": int(target["revision"]),
            }
        await asyncio.sleep(0.5)
    raise RuntimeError("Timed out waiting for the restored demo baseline")


async def _post_with_transport_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    attempts: int = 5,
) -> httpx.Response:
    """Retry only transient transport failures caused by local port-forward churn."""
    for attempt in range(1, attempts + 1):
        try:
            return await client.post(url)
        except httpx.TransportError:
            if attempt == attempts:
                raise
            await asyncio.sleep(0.4 * attempt)
    raise AssertionError("unreachable")
