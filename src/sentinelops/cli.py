from __future__ import annotations

import argparse
import asyncio
import json

import uvicorn

from sentinelops.config import Settings, get_settings
from sentinelops.domain import Alert, IncidentStatus
from sentinelops.lab_profiles import build_simulated_lab_agent
from sentinelops.runtime import build_agent


async def run_demo(scenario: str, approve: bool) -> None:
    settings = Settings(tool_backend="simulator", model_provider="rule_based")
    agent = build_simulated_lab_agent(settings, scenario=scenario)
    alert = Alert(
        name="HighOrderServiceErrorRate",
        namespace=settings.kubernetes_namespace,
        service="order-service",
        severity="critical",
        summary="Order service error rate exceeded the 5% SLO threshold",
    )
    await run_incident(agent, alert, approve=approve)


async def run_incident(agent, alert: Alert, *, approve: bool) -> None:
    record = await agent.start(alert)
    print(json.dumps(record.model_dump(mode="json"), indent=2, ensure_ascii=False))
    if approve and record.status != IncidentStatus.AWAITING_APPROVAL:
        raise SystemExit(f"Expected an approval request, got status={record.status.value}")
    if record.status == IncidentStatus.AWAITING_APPROVAL and approve:
        print("\n--- approving remediation ---\n")
        record = await agent.resume(
            record.id,
            approved=True,
            note="Approved by local demo operator",
        )
        print(json.dumps(record.model_dump(mode="json"), indent=2, ensure_ascii=False))
        if record.status != IncidentStatus.RESOLVED:
            raise SystemExit(2)


async def run_live(approve: bool, service: str, trace_id: str, summary: str) -> None:
    settings = get_settings()
    if settings.tool_backend != "kubernetes":
        raise SystemExit("Set SENTINELOPS_TOOL_BACKEND=kubernetes before using investigate")
    agent = build_agent(settings)
    labels = {"trace_id": trace_id} if trace_id else {}
    alert = Alert(
        name=f"High{service.title().replace('-', '')}ErrorRate",
        namespace=settings.kubernetes_namespace,
        service=service,
        severity="critical",
        summary=summary,
        labels=labels,
    )
    await run_incident(agent, alert, approve=approve)


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelops")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="Run a deterministic offline incident")
    demo.add_argument(
        "--scenario",
        choices=["bad_rollout", "db_pool_exhaustion"],
        default="bad_rollout",
    )
    demo.add_argument("--approve", action="store_true", help="Approve and execute remediation")

    investigate = subparsers.add_parser(
        "investigate", help="Investigate the configured live Kubernetes namespace"
    )
    investigate.add_argument(
        "--approve",
        action="store_true",
        help="Approve the proposed remediation after the graph pauses",
    )
    investigate.add_argument("--service", default="order-service")
    investigate.add_argument("--trace-id", default="")
    investigate.add_argument(
        "--summary",
        default="Service error rate exceeded the SLO threshold",
    )

    serve = subparsers.add_parser("serve", help="Start the REST API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args()
    if args.command == "demo":
        asyncio.run(run_demo(args.scenario, args.approve))
    elif args.command == "investigate":
        asyncio.run(run_live(args.approve, args.service, args.trace_id, args.summary))
    elif args.command == "serve":
        uvicorn.run("sentinelops.api:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
