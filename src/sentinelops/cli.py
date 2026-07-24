from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import time
from pathlib import Path
from uuid import uuid4

import uvicorn

from sentinelops.anchor_crypto import (
    load_ed25519_private_key,
    load_ed25519_public_keyring,
)
from sentinelops.anchor_receiver import (
    AnchorLedger,
    create_anchor_receiver_app,
)
from sentinelops.audit_anchor import (
    AuditAnchorPublisher,
    AuditAnchorReconciler,
    HttpAuditAnchorSink,
)
from sentinelops.config import Settings, get_settings
from sentinelops.domain import Alert, IncidentStatus
from sentinelops.executor import ExecutorWorker
from sentinelops.lab_profiles import build_simulated_lab_agent
from sentinelops.migration import require_current_schema, upgrade_database
from sentinelops.runtime import build_agent
from sentinelops.storage import SqlIncidentStore
from sentinelops.tools import build_tool_registry


def _touch_executor_health_file(file_path: str) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()


def check_executor_health(file_path: str, *, max_age_seconds: float) -> None:
    try:
        age_seconds = time.time() - Path(file_path).stat().st_mtime
    except OSError as exc:
        raise SystemExit("Executor health heartbeat is missing") from exc
    if age_seconds < 0 or age_seconds > max_age_seconds:
        raise SystemExit("Executor health heartbeat is stale")


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
        assert record.approval is not None
        print("\n--- approving remediation ---\n")
        record = await agent.resume(
            record.id,
            approval_id=record.approval.approval_id,
            approval_version=record.approval.version,
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


def initialize_database() -> None:
    settings = get_settings()
    database_url = settings.resolved_database_url()
    if not database_url:
        raise SystemExit("Set SENTINELOPS_DATABASE_URL before running db-init")
    upgrade_database(database_url)
    print("SentinelOps database schema is at the current migration head.")


async def check_database() -> None:
    settings = get_settings()
    database_url = settings.resolved_database_url()
    if not database_url:
        raise SystemExit("Set SENTINELOPS_DATABASE_URL before running db-check")
    store = SqlIncidentStore(database_url)
    try:
        revision = await require_current_schema(store)
    finally:
        await store.close()
    print(f"SentinelOps database schema is current: {revision}")


async def run_executor() -> None:
    settings = get_settings()
    database_url = settings.resolved_database_url()
    if not database_url:
        raise SystemExit("Set SENTINELOPS_DATABASE_URL before running executor")
    audit_hmac_key = settings.resolved_audit_hmac_key()
    if (
        settings.environment.strip().casefold() in {"prod", "production"}
        and (
            not audit_hmac_key
            or len(audit_hmac_key.encode()) < 32
            or settings.audit_key_id == "development-unkeyed"
        )
    ):
        raise SystemExit(
            "Production Executor requires a dedicated audit HMAC key and key ID"
        )
    store = SqlIncidentStore(
        database_url,
        audit_hmac_key=audit_hmac_key,
        audit_key_id=settings.audit_key_id,
    )
    owner_id = f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
    worker = ExecutorWorker(
        store,
        build_tool_registry(settings, allow_guarded_writes=True),
        owner_id=owner_id,
        claim_ttl_seconds=settings.executor_claim_ttl_seconds,
        poll_interval_seconds=settings.executor_poll_interval_seconds,
        health_callback=(
            lambda: _touch_executor_health_file(settings.executor_health_file or "")
            if settings.executor_health_file
            else None
        ),
    )
    try:
        await require_current_schema(store)
        if (
            settings.audit_anchor_enforcement_required
            and await store.audit_anchor_security_state() is None
        ):
            await store.set_audit_anchor_security_state(
                status="initializing",
                write_blocked=True,
                reason="first_reconciliation_pending",
                successful=False,
            )
        await worker.run_forever()
    finally:
        await store.close()


async def run_anchor_publisher() -> None:
    settings = get_settings()
    production = settings.environment.strip().casefold() in {"prod", "production"}
    database_url = settings.resolved_database_url()
    if not database_url:
        raise SystemExit(
            "Set SENTINELOPS_DATABASE_URL before running anchor-publisher"
        )
    if not settings.audit_anchor_url:
        raise SystemExit(
            "Set SENTINELOPS_AUDIT_ANCHOR_URL before running anchor-publisher"
        )
    audit_hmac_key = settings.resolved_audit_hmac_key()
    bearer_token = settings.resolved_audit_anchor_bearer_token()
    reconcile_token = (
        settings.resolved_audit_anchor_reconcile_bearer_token()
    )
    if not bearer_token:
        raise SystemExit(
            "Set a dedicated SENTINELOPS_AUDIT_ANCHOR_BEARER_TOKEN"
        )
    if production and (
        not audit_hmac_key
        or len(audit_hmac_key.encode()) < 32
        or settings.audit_key_id == "development-unkeyed"
    ):
        raise SystemExit(
            "Production Anchor Publisher requires the configured audit HMAC key"
        )
    if production and (
        settings.audit_anchor_source_id == "default"
        or len(bearer_token.encode()) < 32
    ):
        raise SystemExit(
            "Production Anchor Publisher requires a stable source ID and "
            "a dedicated token of at least 32 bytes"
        )
    if (
        settings.audit_anchor_claim_ttl_seconds
        <= settings.audit_anchor_timeout_seconds + 5
    ):
        raise SystemExit(
            "Audit Anchor claim TTL must exceed the HTTP timeout by more than 5 seconds"
        )
    if audit_hmac_key and bearer_token == audit_hmac_key:
        raise SystemExit(
            "Audit Anchor Bearer Token must not reuse the audit HMAC key"
        )
    webhook_tokens = {
        settings.resolved_webhook_bearer_token(),
        settings.resolved_webhook_signing_secret(),
    }
    if bearer_token in webhook_tokens:
        raise SystemExit(
            "Audit Anchor Bearer Token must not reuse an Alertmanager secret"
        )
    if production and (
        not settings.audit_anchor_receipt_public_keys_file
        or not settings.audit_anchor_trusted_receiver_id
        or not settings.audit_anchor_inventory_url
        or not reconcile_token
    ):
        raise SystemExit(
            "Production Anchor Publisher requires a receipt public keyring "
            "trusted receiver ID, and inventory URL"
        )
    if production and (
        reconcile_token == bearer_token
        or len((reconcile_token or "").encode()) < 32
    ):
        raise SystemExit(
            "Production reconciliation requires a separate read-only token"
        )
    try:
        receipt_public_keys = (
            load_ed25519_public_keyring(
                settings.audit_anchor_receipt_public_keys_file
            )
            if settings.audit_anchor_receipt_public_keys_file
            else {}
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    store = SqlIncidentStore(
        database_url,
        audit_hmac_key=audit_hmac_key,
        audit_key_id=settings.audit_key_id,
    )
    try:
        sink = HttpAuditAnchorSink(
            settings.audit_anchor_url,
            bearer_token=bearer_token,
            source_id=settings.audit_anchor_source_id,
            timeout_seconds=settings.audit_anchor_timeout_seconds,
            require_https=production,
            receipt_public_keys=receipt_public_keys,
            trusted_receiver_id=settings.audit_anchor_trusted_receiver_id,
            inventory_url=settings.audit_anchor_inventory_url,
            inventory_bearer_token=reconcile_token,
        )
    except ValueError as exc:
        await store.close()
        raise SystemExit(str(exc)) from exc
    reconciler = (
        AuditAnchorReconciler(
            store,
            sink,
            max_staleness_seconds=(
                settings.audit_anchor_reconcile_max_staleness_seconds
            ),
        )
        if settings.audit_anchor_inventory_url and receipt_public_keys
        else None
    )
    worker = AuditAnchorPublisher(
        store,
        sink,
        owner_id=f"{socket.gethostname()}:{os.getpid()}:{uuid4()}",
        claim_ttl_seconds=settings.audit_anchor_claim_ttl_seconds,
        poll_interval_seconds=settings.audit_anchor_poll_interval_seconds,
        retry_base_seconds=settings.audit_anchor_retry_base_seconds,
        retry_max_seconds=settings.audit_anchor_retry_max_seconds,
        reconciler=reconciler,
        reconcile_interval_seconds=(
            settings.audit_anchor_reconcile_interval_seconds
        ),
        health_callback=(
            lambda: _touch_executor_health_file(
                settings.audit_anchor_health_file or ""
            )
            if settings.audit_anchor_health_file
            else None
        ),
    )
    try:
        await require_current_schema(store)
        await worker.run_forever()
    finally:
        await sink.close()
        await store.close()


def run_anchor_service(host: str, port: int) -> None:
    settings = get_settings()
    database_url = settings.resolved_anchor_service_database_url()
    bearer_token = settings.resolved_anchor_service_bearer_token()
    inventory_token = (
        settings.resolved_anchor_service_inventory_bearer_token()
    )
    if not database_url:
        raise SystemExit(
            "Set SENTINELOPS_ANCHOR_SERVICE_DATABASE_URL before "
            "running anchor-service"
        )
    if not bearer_token:
        raise SystemExit(
            "Set SENTINELOPS_ANCHOR_SERVICE_BEARER_TOKEN before "
            "running anchor-service"
        )
    if not settings.anchor_service_signing_private_key_file:
        raise SystemExit(
            "Set SENTINELOPS_ANCHOR_SERVICE_SIGNING_PRIVATE_KEY_FILE"
        )
    production = settings.environment.strip().casefold() in {
        "prod",
        "production",
    }
    if production:
        primary_database_url = settings.resolved_database_url()
        if primary_database_url and primary_database_url == database_url:
            raise SystemExit(
                "Production Anchor Service must use an independent database"
            )
        if len(bearer_token.encode()) < 32:
            raise SystemExit(
                "Production Anchor Service token must be at least 32 bytes"
            )
        if (
            not inventory_token
            or inventory_token == bearer_token
            or len(inventory_token.encode()) < 32
        ):
            raise SystemExit(
                "Production Anchor Service requires a separate read-only "
                "inventory token"
            )
    try:
        signing_key = load_ed25519_private_key(
            settings.anchor_service_signing_private_key_file
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    ledger = AnchorLedger(
        database_url,
        receiver_id=settings.anchor_service_receiver_id,
        signing_key=signing_key,
        signing_key_id=settings.anchor_service_signing_key_id,
    )
    receiver_app = create_anchor_receiver_app(
        ledger,
        bearer_token=bearer_token,
        inventory_bearer_token=inventory_token,
        allowed_source_id=settings.anchor_service_allowed_source_id,
    )
    uvicorn.run(receiver_app, host=host, port=port, reload=False)


async def verify_audit(incident_id: str) -> None:
    settings = get_settings()
    database_url = settings.resolved_database_url()
    if not database_url:
        raise SystemExit("Set SENTINELOPS_DATABASE_URL before running audit-verify")
    store = SqlIncidentStore(
        database_url,
        audit_hmac_key=settings.resolved_audit_hmac_key(),
        audit_key_id=settings.audit_key_id,
    )
    try:
        await require_current_schema(store)
        result = await store.verify_audit_chain(incident_id)
    finally:
        await store.close()
    print(
        json.dumps(
            {
                "incident_id": result.incident_id,
                "valid": result.valid,
                "event_count": result.event_count,
                "head_sequence": result.head_sequence,
                "head_hash": result.head_hash,
                "auth_algorithm": result.auth_algorithm,
                "key_id": result.key_id,
                "first_invalid_sequence": result.first_invalid_sequence,
                "errors": list(result.errors),
            },
            ensure_ascii=False,
        )
    )
    if not result.valid:
        raise SystemExit(2)


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

    subparsers.add_parser("db-init", help="Create the durable incident store schema")
    subparsers.add_parser(
        "db-check",
        help="Verify that the database is at the required migration head",
    )
    subparsers.add_parser(
        "executor",
        help="Run the independent cluster-write Executor",
    )
    subparsers.add_parser(
        "anchor-publisher",
        help="Publish durable audit-chain anchors to an independent sink",
    )
    anchor_service = subparsers.add_parser(
        "anchor-service",
        help="Run the local reference audit-anchor receiver",
    )
    anchor_service.add_argument("--host", default="127.0.0.1")
    anchor_service.add_argument("--port", type=int, default=8010)
    executor_health = subparsers.add_parser(
        "executor-health",
        help="Check the independent Executor heartbeat file",
    )
    executor_health.add_argument("--file")
    executor_health.add_argument("--max-age-seconds", type=float, default=120)
    anchor_health = subparsers.add_parser(
        "anchor-health",
        help="Check the audit Anchor Publisher heartbeat file",
    )
    anchor_health.add_argument("--file")
    anchor_health.add_argument("--max-age-seconds", type=float, default=120)
    audit_verify = subparsers.add_parser(
        "audit-verify",
        help="Verify one incident's tamper-evident audit chain",
    )
    audit_verify.add_argument("--incident-id", required=True)

    args = parser.parse_args()
    if args.command == "demo":
        asyncio.run(run_demo(args.scenario, args.approve))
    elif args.command == "investigate":
        asyncio.run(run_live(args.approve, args.service, args.trace_id, args.summary))
    elif args.command == "serve":
        uvicorn.run("sentinelops.api:app", host=args.host, port=args.port, reload=False)
    elif args.command == "db-init":
        initialize_database()
    elif args.command == "db-check":
        asyncio.run(check_database())
    elif args.command == "executor":
        asyncio.run(run_executor())
    elif args.command == "anchor-publisher":
        asyncio.run(run_anchor_publisher())
    elif args.command == "anchor-service":
        run_anchor_service(args.host, args.port)
    elif args.command == "executor-health":
        settings = get_settings()
        file_path = args.file or settings.executor_health_file
        if not file_path:
            raise SystemExit("Set SENTINELOPS_EXECUTOR_HEALTH_FILE or pass --file")
        check_executor_health(
            file_path,
            max_age_seconds=args.max_age_seconds,
        )
    elif args.command == "anchor-health":
        settings = get_settings()
        file_path = args.file or settings.audit_anchor_health_file
        if not file_path:
            raise SystemExit(
                "Set SENTINELOPS_AUDIT_ANCHOR_HEALTH_FILE or pass --file"
            )
        check_executor_health(
            file_path,
            max_age_seconds=args.max_age_seconds,
        )
    elif args.command == "audit-verify":
        asyncio.run(verify_audit(args.incident_id))


if __name__ == "__main__":
    main()
