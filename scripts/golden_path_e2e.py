from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter

import httpx

from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentStatus
from sentinelops.runtime import build_agent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the live alert-to-diagnosis-to-rollback SentinelOps golden path."
    )
    parser.add_argument("--order-url", default="http://127.0.0.1:18080")
    return parser.parse_args()


async def find_failed_trace(client: httpx.AsyncClient, order_url: str) -> tuple[str, Counter]:
    outcomes: Counter = Counter()
    for _ in range(18):
        response = await client.post(f"{order_url.rstrip('/')}/checkout")
        outcomes[str(response.status_code)] += 1
        payload = response.json()
        if response.status_code == 502 and payload.get("trace_id"):
            return str(payload["trace_id"]), outcomes
    raise RuntimeError(f"Fault injection did not produce a failed trace: {dict(outcomes)}")


async def generate_background_traffic(
    order_url: str,
    stop: asyncio.Event,
    outcomes: Counter,
) -> None:
    async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
        while not stop.is_set():
            try:
                response = await client.post(f"{order_url.rstrip('/')}/checkout")
                outcomes[str(response.status_code)] += 1
            except httpx.HTTPError:
                outcomes["network_error"] += 1
            await asyncio.sleep(0.25)


async def wait_for_alert(
    client: httpx.AsyncClient,
    prometheus_url: str,
    *,
    firing: bool,
    timeout_seconds: float = 30,
) -> dict:
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
        if firing and match:
            return match
        if not firing and not match:
            return {}
        await asyncio.sleep(1)
    expected = "firing" if firing else "cleared"
    raise RuntimeError(f"Prometheus alert did not become {expected}")


async def assert_healthy_traffic(client: httpx.AsyncClient, order_url: str) -> Counter:
    outcomes: Counter = Counter()
    for _ in range(6):
        response = await client.post(f"{order_url.rstrip('/')}/checkout")
        outcomes[str(response.status_code)] += 1
    if set(outcomes) != {"200"}:
        raise RuntimeError(f"Checkout traffic did not recover after rollback: {dict(outcomes)}")
    return outcomes


async def main() -> None:
    args = parse_args()
    settings = Settings()
    if settings.tool_backend != "kubernetes":
        raise RuntimeError("SENTINELOPS_TOOL_BACKEND must be kubernetes")
    missing = [
        name
        for name, value in {
            "SENTINELOPS_PROMETHEUS_URL": settings.prometheus_url,
            "SENTINELOPS_LOKI_URL": settings.loki_url,
            "SENTINELOPS_TEMPO_URL": settings.tempo_url,
        }.items()
        if not value
    ]
    if missing:
        raise RuntimeError(f"Missing observability settings: {', '.join(missing)}")

    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        trace_id, initial_traffic = await find_failed_trace(client, args.order_url)
        background_traffic: Counter = Counter()
        stop = asyncio.Event()
        traffic_task = asyncio.create_task(
            generate_background_traffic(args.order_url, stop, background_traffic)
        )
        try:
            firing_alert = await wait_for_alert(
                client,
                settings.prometheus_url,
                firing=True,
            )
            alert_labels = firing_alert.get("labels", {})
            alert_annotations = firing_alert.get("annotations", {})
            agent = build_agent(settings)
            alert = Alert(
                name=alert_labels.get("alertname", "HighInventoryErrorRate"),
                namespace=alert_labels.get("namespace", settings.kubernetes_namespace),
                service=alert_labels.get("service", "inventory-service"),
                severity=alert_labels.get("severity", "critical"),
                summary=alert_annotations.get(
                    "summary", "Inventory HTTP 503 rate exceeded the checkout SLO"
                ),
                labels={**alert_labels, "trace_id": trace_id},
            )
            record = await agent.start(alert)
            if record.status != IncidentStatus.AWAITING_APPROVAL:
                raise RuntimeError(f"Expected approval gate, got {record.status.value}")
            if record.plan is None or record.diagnosis is None:
                raise RuntimeError("Agent did not produce a diagnosis and remediation plan")
            action = record.plan.actions[0]
            if action.tool_name != "rollback_deployment" or action.arguments != {
                "name": "inventory-service",
                "revision": 1,
            }:
                raise RuntimeError(f"Agent selected an unexpected remediation: {action}")

            record = await agent.resume(
                record.id,
                approved=True,
                note="Approved by the automated golden-path operator",
            )
            if record.status != IncidentStatus.RESOLVED:
                raise RuntimeError(f"Agent did not verify recovery: {record.status.value}")
        finally:
            stop.set()
            await traffic_task

        recovered_traffic = await assert_healthy_traffic(client, args.order_url)
        await wait_for_alert(client, settings.prometheus_url, firing=False)

    evidence_sources = sorted(
        {
            evidence.source
            for hypothesis in record.diagnosis.hypotheses
            for evidence in hypothesis.evidence
        }
    )
    verification = next(
        event.data for event in reversed(record.timeline) if event.type == "recovery.verified"
    )
    print(
        json.dumps(
            {
                "incident_id": record.id,
                "status": record.status.value,
                "model_provider": settings.model_provider,
                "failed_trace_id": trace_id,
                "prometheus_alert": firing_alert.get("labels", {}),
                "prometheus_alert_cleared": True,
                "initial_traffic": dict(initial_traffic),
                "background_traffic": dict(background_traffic),
                "root_cause": record.diagnosis.root_cause,
                "evidence_sources": evidence_sources,
                "remediation": action.model_dump(mode="json"),
                "verification": {
                    "attempts": verification.get("attempts"),
                    "request_error_rate": verification.get("request_error_rate"),
                },
                "recovered_traffic": dict(recovered_traffic),
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
