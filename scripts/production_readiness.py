from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from sqlalchemy import text, update

from sentinelops.domain import (
    Alert,
    IncidentRecord,
    IncidentStatus,
    RemediationAction,
    RiskLevel,
    TimelineEvent,
    ToolResult,
)
from sentinelops.migration import require_current_schema, upgrade_database
from sentinelops.storage import (
    ActionIntentConflictError,
    AuditAnchorConflictError,
    LeaseConflictError,
    SqlIncidentStore,
)
from sentinelops.storage.sqlalchemy import (
    action_intents,
    audit_anchor_outbox,
    worker_leases,
)

AUDIT_KEY = "production-readiness-audit-key-000000000001"
AUDIT_KEY_ID = "production-readiness-v1"


@dataclass(frozen=True)
class Observation:
    scenario: str
    trial: int
    passed: bool
    latency_ms: float
    unsafe_writes: int
    details: dict[str, object]


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, int(len(ordered) * percentile + 0.999999))
    return round(ordered[min(rank - 1, len(ordered) - 1)], 3)


def _store(database_url: str) -> SqlIncidentStore:
    return SqlIncidentStore(
        database_url,
        audit_hmac_key=AUDIT_KEY,
        audit_key_id=AUDIT_KEY_ID,
    )


def _record(run_id: str, scenario: str, trial: int) -> IncidentRecord:
    return IncidentRecord(
        alert=Alert(
            name=f"ProductionReadiness{scenario}",
            namespace="sentinelops-benchmark",
            service="order-service",
            severity="critical",
            summary=f"{run_id}:{scenario}:{trial}",
        ),
        status=IncidentStatus.INVESTIGATING,
    )


def _alert_placeholder(
    run_id: str,
    fingerprint: str,
    starts_at: datetime,
    trial: int,
    delivery: int,
) -> IncidentRecord:
    return IncidentRecord(
        alert=Alert(
            name="ProductionReadinessAlertDedup",
            namespace="sentinelops-benchmark",
            service="order-service",
            severity="critical",
            summary=f"{run_id}:{trial}:{delivery}",
            starts_at=starts_at,
            labels={
                "source": "alertmanager",
                "alertmanager_source_id": run_id,
                "alertmanager_fingerprint": fingerprint,
            },
        ),
        status=IncidentStatus.INVESTIGATING,
        timeline=[
            TimelineEvent(
                type="alertmanager.received",
                message="production readiness concurrent delivery",
                data={"fingerprint": fingerprint},
            )
        ],
    )


def _action(run_id: str, trial: int) -> RemediationAction:
    return RemediationAction(
        tool_name="restart_deployment",
        arguments={
            "namespace": "sentinelops-benchmark",
            "name": f"order-service-{trial}",
        },
        rationale=f"production readiness {run_id}",
        expected_outcome="exactly one executor owns the write intent",
        risk=RiskLevel.MEDIUM,
    )


async def _publisher_failover(
    database_url: str,
    run_id: str,
    rounds: int,
) -> list[Observation]:
    first = _store(database_url)
    second = _store(database_url)
    observations: list[Observation] = []
    try:
        for trial in range(rounds):
            record = _record(run_id, "PublisherFailover", trial)
            await first.save(record, expected_version=None, graph_state=None)
            stale = await first.claim_audit_anchor(
                owner_id=f"publisher-a-{run_id}",
                ttl_seconds=60,
            )
            if stale is None:
                raise RuntimeError("publisher failed to claim a pending anchor")
            async with first.engine.begin() as connection:
                await connection.execute(
                    update(audit_anchor_outbox)
                    .where(
                        audit_anchor_outbox.c.anchor_id
                        == stale.anchor.anchor_id
                    )
                    .values(
                        claim_until=(
                            datetime.now(UTC) - timedelta(seconds=1)
                        ).isoformat()
                    )
                )
            started = perf_counter()
            successor = await second.claim_audit_anchor(
                owner_id=f"publisher-b-{run_id}",
                ttl_seconds=60,
            )
            latency_ms = (perf_counter() - started) * 1_000
            stale_blocked = False
            try:
                await first.complete_audit_anchor(
                    stale,
                    receipt={"receipt_id": "stale-must-not-commit"},
                )
            except AuditAnchorConflictError:
                stale_blocked = True
            if successor is not None:
                await second.complete_audit_anchor(
                    successor,
                    receipt={
                        "receipt_id": (
                            f"readiness-{run_id}-{trial}"
                        )
                    },
                )
            passed = (
                successor is not None
                and successor.generation == stale.generation + 1
                and stale_blocked
            )
            observations.append(
                Observation(
                    scenario="publisher_failover",
                    trial=trial,
                    passed=passed,
                    latency_ms=latency_ms,
                    unsafe_writes=0 if stale_blocked else 1,
                    details={
                        "stale_completion_blocked": stale_blocked,
                        "successor_claimed": successor is not None,
                        "fencing_generation_advanced": (
                            successor is not None
                            and successor.generation
                            == stale.generation + 1
                        ),
                    },
                )
            )
    finally:
        await first.close()
        await second.close()
    return observations


async def _alert_dedup(
    database_url: str,
    run_id: str,
    rounds: int,
    concurrency: int,
) -> list[Observation]:
    stores = [_store(database_url) for _ in range(min(concurrency, 8))]
    observations: list[Observation] = []
    try:
        for trial in range(rounds):
            fingerprint = f"{run_id}-dedup-{trial}-{uuid4().hex}"
            starts_at = datetime.now(UTC)
            started = perf_counter()
            claims = await asyncio.gather(
                *[
                    stores[index % len(stores)].claim_alert_firing(
                        _alert_placeholder(
                            run_id,
                            fingerprint,
                            starts_at,
                            trial,
                            index,
                        ),
                        source_id=run_id,
                        fingerprint=fingerprint,
                        starts_at=starts_at,
                    )
                    for index in range(concurrency)
                ]
            )
            latency_ms = (perf_counter() - started) * 1_000
            accepted = sum(
                item.outcome == "accepted" for item in claims
            )
            deduplicated = sum(
                item.outcome == "deduplicated" for item in claims
            )
            incident_ids = {
                item.incident_id
                for item in claims
                if item.incident_id is not None
            }
            observations.append(
                Observation(
                    scenario="alert_deduplication",
                    trial=trial,
                    passed=(
                        accepted == 1
                        and deduplicated == concurrency - 1
                        and len(incident_ids) == 1
                    ),
                    latency_ms=latency_ms,
                    unsafe_writes=max(0, accepted - 1),
                    details={
                        "deliveries": concurrency,
                        "accepted": accepted,
                        "deduplicated": deduplicated,
                        "incident_count": len(incident_ids),
                    },
                )
            )
    finally:
        await asyncio.gather(
            *(store.close() for store in stores),
        )
    return observations


async def _prepare_intent(
    store: SqlIncidentStore,
    run_id: str,
    scenario: str,
    trial: int,
) -> tuple[IncidentRecord, str]:
    record = _record(run_id, scenario, trial)
    await store.save(record, expected_version=None, graph_state=None)
    lease = await store.acquire_lease(
        record.id,
        owner_id=f"agent-{run_id}-{trial}",
        ttl_seconds=60,
    )
    idempotency_key = hashlib.sha256(
        f"{run_id}\0{scenario}\0{trial}".encode()
    ).hexdigest()
    await store.prepare_action(
        lease,
        idempotency_key=idempotency_key,
        action=_action(run_id, trial),
        precondition={"resource_version": f"{run_id}-{trial}"},
    )
    await store.enqueue_action(
        lease,
        idempotency_key=idempotency_key,
    )
    return record, idempotency_key


async def _executor_single_claim(
    database_url: str,
    run_id: str,
    rounds: int,
    concurrency: int,
) -> list[Observation]:
    stores = [_store(database_url) for _ in range(min(concurrency, 8))]
    observations: list[Observation] = []
    try:
        for trial in range(rounds):
            record, idempotency_key = await _prepare_intent(
                stores[0],
                run_id,
                "ExecutorSingleClaim",
                trial,
            )
            started = perf_counter()
            claims = await asyncio.gather(
                *[
                    stores[index % len(stores)].claim_action_execution(
                        owner_id=f"executor-{run_id}-{trial}-{index}",
                        attempt_id=(
                            f"exact-{run_id[:8]}-{trial}-{index}"
                        ),
                        ttl_seconds=60,
                    )
                    for index in range(concurrency)
                ]
            )
            latency_ms = (perf_counter() - started) * 1_000
            winners = [item for item in claims if item is not None]
            correct_intent = (
                len(winners) == 1
                and winners[0].idempotency_key == idempotency_key
                and winners[0].incident_id == record.id
            )
            if len(winners) == 1:
                await stores[0].mark_action_dispatched(winners[0])
                await stores[0].complete_action(
                    claim=winners[0],
                    result=ToolResult(
                        tool_name="restart_deployment",
                        success=True,
                        content={"benchmark": True},
                    ),
                )
            observations.append(
                Observation(
                    scenario="executor_single_claim",
                    trial=trial,
                    passed=correct_intent,
                    latency_ms=latency_ms,
                    unsafe_writes=max(0, len(winners) - 1),
                    details={
                        "contenders": concurrency,
                        "claim_winners": len(winners),
                        "correct_intent": correct_intent,
                    },
                )
            )
    finally:
        await asyncio.gather(
            *(store.close() for store in stores),
        )
    return observations


async def _executor_crash_recovery(
    database_url: str,
    run_id: str,
    rounds: int,
) -> list[Observation]:
    first = _store(database_url)
    second = _store(database_url)
    observations: list[Observation] = []
    try:
        for trial in range(rounds):
            _record_value, idempotency_key = await _prepare_intent(
                first,
                run_id,
                "ExecutorCrashRecovery",
                trial,
            )
            stale = await first.claim_action_execution(
                owner_id=f"executor-a-{run_id}-{trial}",
                attempt_id=f"crash-a-{run_id[:8]}-{trial}",
                ttl_seconds=60,
            )
            if stale is None:
                raise RuntimeError("executor failed to claim queued intent")
            async with first.engine.begin() as connection:
                await connection.execute(
                    update(action_intents)
                    .where(
                        action_intents.c.idempotency_key
                        == idempotency_key
                    )
                    .values(
                        executor_lease_until=(
                            datetime.now(UTC) - timedelta(seconds=1)
                        ).isoformat()
                    )
                )
            started = perf_counter()
            successor = await second.claim_action_execution(
                owner_id=f"executor-b-{run_id}-{trial}",
                attempt_id=f"crash-b-{run_id[:8]}-{trial}",
                ttl_seconds=60,
            )
            latency_ms = (perf_counter() - started) * 1_000
            stale_blocked = False
            try:
                await first.mark_action_dispatched(stale)
            except ActionIntentConflictError:
                stale_blocked = True
            if successor is not None:
                await second.mark_action_dispatched(successor)
                await second.complete_action(
                    claim=successor,
                    result=ToolResult(
                        tool_name="restart_deployment",
                        success=True,
                        content={"recovered_after_crash": True},
                    ),
                )
            passed = (
                successor is not None
                and successor.idempotency_key == idempotency_key
                and successor.generation == stale.generation + 1
                and stale_blocked
            )
            observations.append(
                Observation(
                    scenario="executor_crash_recovery",
                    trial=trial,
                    passed=passed,
                    latency_ms=latency_ms,
                    unsafe_writes=0 if stale_blocked else 1,
                    details={
                        "successor_claimed": successor is not None,
                        "stale_dispatch_blocked": stale_blocked,
                        "fencing_generation_advanced": (
                            successor is not None
                            and successor.generation
                            == stale.generation + 1
                        ),
                    },
                )
            )
    finally:
        await first.close()
        await second.close()
    return observations


async def _worker_lease_fencing(
    database_url: str,
    run_id: str,
    rounds: int,
) -> list[Observation]:
    first = _store(database_url)
    second = _store(database_url)
    observations: list[Observation] = []
    try:
        for trial in range(rounds):
            record = _record(run_id, "WorkerLeaseFencing", trial)
            await first.save(record, expected_version=None, graph_state=None)
            stale = await first.acquire_lease(
                record.id,
                owner_id=f"worker-a-{run_id}-{trial}",
                ttl_seconds=60,
            )
            async with first.engine.begin() as connection:
                await connection.execute(
                    update(worker_leases)
                    .where(worker_leases.c.incident_id == record.id)
                    .values(
                        expires_at=(
                            datetime.now(UTC) - timedelta(seconds=1)
                        ).isoformat()
                    )
                )
            started = perf_counter()
            successor = await second.acquire_lease(
                record.id,
                owner_id=f"worker-b-{run_id}-{trial}",
                ttl_seconds=60,
            )
            latency_ms = (perf_counter() - started) * 1_000
            stale_blocked = False
            try:
                await first.heartbeat_lease(stale, ttl_seconds=60)
            except LeaseConflictError:
                stale_blocked = True
            observations.append(
                Observation(
                    scenario="worker_lease_fencing",
                    trial=trial,
                    passed=(
                        successor.generation == stale.generation + 1
                        and stale_blocked
                    ),
                    latency_ms=latency_ms,
                    unsafe_writes=0 if stale_blocked else 1,
                    details={
                        "stale_heartbeat_blocked": stale_blocked,
                        "fencing_generation_advanced": (
                            successor.generation
                            == stale.generation + 1
                        ),
                    },
                )
            )
    finally:
        await first.close()
        await second.close()
    return observations


def _summarize(
    observations: list[Observation],
) -> dict[str, object]:
    latencies = [item.latency_ms for item in observations]
    passed = sum(item.passed for item in observations)
    unsafe_writes = sum(item.unsafe_writes for item in observations)
    return {
        "trials": len(observations),
        "passed_trials": passed,
        "correctness_rate": (
            round(passed / len(observations), 6)
            if observations
            else 0.0
        ),
        "unsafe_writes": unsafe_writes,
        "latency_ms": {
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "failures": [
            asdict(item)
            for item in observations
            if not item.passed
        ][:20],
    }


async def run(
    *,
    database_url: str,
    rounds: int,
    concurrency: int,
) -> dict[str, object]:
    if not database_url.startswith(
        ("postgresql+asyncpg://", "postgres+asyncpg://")
    ):
        raise ValueError(
            "生产就绪基准必须使用独立 PostgreSQL 数据库"
        )
    await asyncio.to_thread(upgrade_database, database_url)
    verifier = _store(database_url)
    try:
        await require_current_schema(verifier)
        async with verifier.engine.connect() as connection:
            postgres_version = str(
                (
                    await connection.execute(text("SHOW server_version"))
                ).scalar_one()
            )
    finally:
        await verifier.close()

    run_id = uuid4().hex
    scenarios: list[
        tuple[
            str,
            Callable[[], Awaitable[list[Observation]]],
        ]
    ] = [
        (
            "publisher_failover",
            lambda: _publisher_failover(
                database_url,
                run_id,
                rounds,
            ),
        ),
        (
            "alert_deduplication",
            lambda: _alert_dedup(
                database_url,
                run_id,
                rounds,
                concurrency,
            ),
        ),
        (
            "executor_single_claim",
            lambda: _executor_single_claim(
                database_url,
                run_id,
                rounds,
                concurrency,
            ),
        ),
        (
            "executor_crash_recovery",
            lambda: _executor_crash_recovery(
                database_url,
                run_id,
                rounds,
            ),
        ),
        (
            "worker_lease_fencing",
            lambda: _worker_lease_fencing(
                database_url,
                run_id,
                rounds,
            ),
        ),
    ]
    results: dict[str, dict[str, object]] = {}
    all_observations: list[Observation] = []
    started = perf_counter()
    for name, scenario in scenarios:
        try:
            observations = await scenario()
        except Exception as exc:
            observations = [
                Observation(
                    scenario=name,
                    trial=-1,
                    passed=False,
                    latency_ms=0,
                    unsafe_writes=0,
                    details={"error_type": type(exc).__name__},
                )
            ]
        results[name] = _summarize(observations)
        all_observations.extend(observations)

    total_trials = len(all_observations)
    passed_trials = sum(item.passed for item in all_observations)
    unsafe_writes = sum(item.unsafe_writes for item in all_observations)
    correctness_rate = (
        passed_trials / total_trials if total_trials else 0.0
    )
    passed = correctness_rate == 1.0 and unsafe_writes == 0
    return {
        "schema_version": "sentinelops.production-readiness.v1",
        "run_id": run_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "postgresql": postgres_version,
        },
        "configuration": {
            "rounds_per_scenario": rounds,
            "concurrency": concurrency,
            "scenario_count": len(scenarios),
        },
        "thresholds": {
            "correctness_rate": 1.0,
            "unsafe_writes": 0,
        },
        "summary": {
            "passed": passed,
            "total_trials": total_trials,
            "passed_trials": passed_trials,
            "correctness_rate": round(correctness_rate, 6),
            "unsafe_writes": unsafe_writes,
            "duration_ms": round(
                (perf_counter() - started) * 1_000,
                3,
            ),
        },
        "scenarios": results,
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run reproducible PostgreSQL multi-replica and failover "
            "contracts for SentinelOps."
        )
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("SENTINELOPS_BENCHMARK_DATABASE_URL"),
    )
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/production-readiness.json"),
    )
    arguments = parser.parse_args()
    if not arguments.database_url:
        parser.error(
            "--database-url or SENTINELOPS_BENCHMARK_DATABASE_URL is required"
        )
    if not 1 <= arguments.rounds <= 1_000:
        parser.error("--rounds must be between 1 and 1000")
    if not 2 <= arguments.concurrency <= 128:
        parser.error("--concurrency must be between 2 and 128")
    return arguments


def main() -> None:
    arguments = _arguments()
    report = asyncio.run(
        run(
            database_url=arguments.database_url,
            rounds=arguments.rounds,
            concurrency=arguments.concurrency,
        )
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["summary"]["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
