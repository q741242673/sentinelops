from __future__ import annotations

import argparse
import asyncio
import json

import uvicorn

from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentStatus
from sentinelops.runtime import build_agent


async def run_demo(scenario: str, approve: bool) -> None:
    settings = Settings(tool_backend="simulator", model_provider="rule_based")
    agent = build_agent(settings, scenario=scenario)
    alert = Alert(
        name="HighOrderServiceErrorRate",
        namespace="sentinelops-demo",
        service="order-service",
        severity="critical",
        summary="Order service error rate exceeded the 5% SLO threshold",
        labels={"scenario": scenario},
    )
    record = await agent.start(alert)
    print(json.dumps(record.model_dump(mode="json"), indent=2, ensure_ascii=False))
    if record.status == IncidentStatus.AWAITING_APPROVAL and approve:
        print("\n--- approving remediation ---\n")
        record = await agent.resume(
            record.id,
            approved=True,
            note="Approved by local demo operator",
        )
        print(json.dumps(record.model_dump(mode="json"), indent=2, ensure_ascii=False))


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

    serve = subparsers.add_parser("serve", help="Start the REST API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args()
    if args.command == "demo":
        asyncio.run(run_demo(args.scenario, args.approve))
    elif args.command == "serve":
        uvicorn.run("sentinelops.api:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
