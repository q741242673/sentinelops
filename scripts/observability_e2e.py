from __future__ import annotations

import argparse
import asyncio
import json
import time
from typing import Any

import httpx

from sentinelops.tools.observability import ObservabilityBackend


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate demo traffic and verify metrics, logs, and traces end to end."
    )
    parser.add_argument("--order-url", default="http://127.0.0.1:18080")
    parser.add_argument("--prometheus-url", default="http://127.0.0.1:19090")
    parser.add_argument("--loki-url", default="http://127.0.0.1:13100")
    parser.add_argument("--tempo-url", default="http://127.0.0.1:13200")
    parser.add_argument("--timeout", type=float, default=90)
    return parser.parse_args()


async def generate_traffic(order_url: str) -> tuple[str, dict[str, int]]:
    trace_id = ""
    outcomes: dict[str, int] = {}
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        for _ in range(12):
            response = await client.post(f"{order_url.rstrip('/')}/checkout")
            payload = response.json()
            candidate = payload.get("trace_id")
            if candidate:
                trace_id = str(candidate)
            key = str(response.status_code)
            outcomes[key] = outcomes.get(key, 0) + 1
    if not trace_id:
        raise RuntimeError("Demo traffic did not return a trace ID")
    if "200" not in outcomes or "502" not in outcomes:
        raise RuntimeError(f"Expected both healthy and failed requests, got {outcomes}")
    return trace_id, outcomes


def prometheus_has_samples(content: Any) -> bool:
    if not isinstance(content, dict):
        return False
    for series in content.get("result", []):
        value = series.get("value", [None, "0"])
        if len(value) == 2 and float(value[1]) > 0:
            return True
    return False


def loki_has_entries(content: Any) -> bool:
    if not isinstance(content, dict):
        return False
    return any(stream.get("values") for stream in content.get("result", []))


def tempo_has_spans(content: Any) -> bool:
    if not isinstance(content, dict):
        return False
    trace = content.get("trace")
    return isinstance(trace, dict) and bool(trace.get("batches") or trace.get("resourceSpans"))


async def verify_telemetry(args: argparse.Namespace, trace_id: str) -> dict[str, Any]:
    backend = ObservabilityBackend(
        prometheus_url=args.prometheus_url,
        loki_url=args.loki_url,
        tempo_url=args.tempo_url,
        timeout_seconds=5,
    )
    deadline = time.monotonic() + args.timeout
    last_results: dict[str, Any] = {}
    try:
        while time.monotonic() < deadline:
            prometheus, loki, tempo = await asyncio.gather(
                backend.call(
                    "query_prometheus",
                    {"query": 'sum(http_requests_total{service="order-service"})'},
                ),
                backend.call(
                    "search_loki",
                    {"query": '{service_name="order-service"} |= "checkout_"', "limit": 50},
                ),
                backend.call("get_trace", {"trace_id": trace_id}),
            )
            last_results = {
                "prometheus": prometheus.model_dump(mode="json"),
                "loki": loki.model_dump(mode="json"),
                "tempo": tempo.model_dump(mode="json"),
            }
            checks = {
                "prometheus": prometheus.success and prometheus_has_samples(prometheus.content),
                "loki": loki.success and loki_has_entries(loki.content),
                "tempo": tempo.success and tempo_has_spans(tempo.content),
            }
            if all(checks.values()):
                return {"checks": checks, "results": last_results}
            await asyncio.sleep(2)
    finally:
        await backend.client.aclose()
    raise RuntimeError(
        "Telemetry did not become queryable before the deadline:\n"
        + json.dumps(last_results, indent=2, default=str)
    )


async def main() -> None:
    args = parse_args()
    trace_id, outcomes = await generate_traffic(args.order_url)
    verification = await verify_telemetry(args, trace_id)
    print(
        json.dumps(
            {
                "traffic": outcomes,
                "trace_id": trace_id,
                "checks": verification["checks"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
