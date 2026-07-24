from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import sys
from collections import Counter
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

import httpx

from sentinelops.config import Settings
from sentinelops.domain import Alert, IncidentStatus
from sentinelops.runtime import build_agent

WRITE_TOOLS = {
    "rollback_deployment",
    "restart_deployment",
    "scale_deployment",
}


@dataclass(frozen=True)
class TrialResult:
    trial: int
    passed: bool
    incident_id: str | None
    incident_status: str | None
    alert_name: str | None
    failed_trace_id: str | None
    root_cause: str | None
    diagnosis_confidence: float | None
    diagnosis_missing_evidence: list[str]
    diagnosis_contradictions: list[str]
    evidence_sources: list[str]
    remediation_tool: str | None
    remediation_target: str | None
    expected_revision: int | None
    injected_revision: int | None
    wrong_remediation_plans: int
    unsafe_writes: int
    write_attempts: int
    successful_writes: int
    failed_requests_before_recovery: int
    healthy_requests_after_recovery: int
    timings_ms: dict[str, float]
    checks: dict[str, bool]
    timeline_tail: list[dict[str, Any]]
    error_type: str | None = None
    error: str | None = None


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, int(len(ordered) * percentile + 0.999999))
    return round(ordered[min(rank - 1, len(ordered) - 1)], 3)


def _root_cause_matches_fault(
    root_cause: str | None,
    revision: int,
) -> bool:
    if not root_cause:
        return False
    text = root_cause.casefold()
    has_service = "inventory" in text or "库存" in text
    has_failure = any(
        marker in text
        for marker in ("故障", "失败", "异常", "503", "fault", "failure")
    )
    return has_service and has_failure and str(revision) in text


async def _command(
    *parts: str,
    deadline_seconds: float = 180,
) -> str:
    process = await asyncio.create_subprocess_exec(
        *parts,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=deadline_seconds,
        )
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise RuntimeError(
            f"command timed out: {' '.join(parts[:3])}"
        ) from exc
    if process.returncode != 0:
        error = stderr.decode(errors="replace").strip()
        raise RuntimeError(
            f"command failed ({process.returncode}): "
            f"{' '.join(parts[:4])}: {error[-2_000:]}"
        )
    return stdout.decode()


async def _kubectl(
    context: str,
    namespace: str,
    *parts: str,
    deadline_seconds: float = 180,
) -> str:
    return await _command(
        "kubectl",
        "--context",
        context,
        "--namespace",
        namespace,
        *parts,
        deadline_seconds=deadline_seconds,
    )


async def _kubectl_json(
    context: str,
    namespace: str,
    *parts: str,
) -> dict[str, Any]:
    return json.loads(
        await _kubectl(
            context,
            namespace,
            *parts,
            "--output",
            "json",
        )
    )


async def _wait_for_alert(
    client: httpx.AsyncClient,
    prometheus_url: str,
    *,
    firing: bool,
    namespace: str,
    service: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    last_alerts: list[dict[str, Any]] = []
    while asyncio.get_running_loop().time() < deadline:
        response = await client.get(
            f"{prometheus_url.rstrip('/')}/api/v1/alerts"
        )
        response.raise_for_status()
        last_alerts = response.json().get("data", {}).get("alerts", [])
        match = next(
            (
                alert
                for alert in last_alerts
                if alert.get("labels", {}).get("alertname")
                == "HighInventoryErrorRate"
                and alert.get("labels", {}).get("namespace") == namespace
                and alert.get("labels", {}).get("service") == service
                and alert.get("state") == "firing"
            ),
            None,
        )
        if firing and match:
            return match
        if not firing and match is None:
            return {}
        await asyncio.sleep(1)
    expected = "firing" if firing else "cleared"
    raise RuntimeError(
        f"Prometheus alert did not become {expected}; "
        f"last_alert_count={len(last_alerts)}"
    )


async def _healthy_requests(
    client: httpx.AsyncClient,
    order_url: str,
    *,
    count: int,
) -> Counter[str]:
    outcomes: Counter[str] = Counter()
    for _ in range(count):
        response = await client.post(
            f"{order_url.rstrip('/')}/checkout"
        )
        outcomes[str(response.status_code)] += 1
    return outcomes


async def _find_failed_trace(
    client: httpx.AsyncClient,
    order_url: str,
    *,
    attempts: int = 24,
) -> tuple[str, Counter[str]]:
    outcomes: Counter[str] = Counter()
    for _ in range(attempts):
        response = await client.post(
            f"{order_url.rstrip('/')}/checkout"
        )
        outcomes[str(response.status_code)] += 1
        payload = response.json()
        if response.status_code == 502 and payload.get("trace_id"):
            return str(payload["trace_id"]), outcomes
    raise RuntimeError(
        f"fault did not produce a failed trace: {dict(outcomes)}"
    )


async def _background_traffic(
    order_url: str,
    stop: asyncio.Event,
    outcomes: Counter[str],
) -> None:
    async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
        while not stop.is_set():
            try:
                response = await client.post(
                    f"{order_url.rstrip('/')}/checkout"
                )
                outcomes[str(response.status_code)] += 1
            except httpx.HTTPError:
                outcomes["network_error"] += 1
            await asyncio.sleep(0.2)


async def _active_revision(
    context: str,
    namespace: str,
    deployment_name: str,
) -> int:
    deployment = await _kubectl_json(
        context,
        namespace,
        "get",
        f"deployment/{deployment_name}",
    )
    deployment_uid = deployment["metadata"]["uid"]
    replica_sets = await _kubectl_json(
        context,
        namespace,
        "get",
        "replicaset",
        "--selector",
        f"app={deployment_name}",
    )
    active: list[int] = []
    for replica_set in replica_sets["items"]:
        owners = replica_set["metadata"].get("ownerReferences", [])
        if not any(
            owner.get("uid") == deployment_uid
            and owner.get("kind") == "Deployment"
            and owner.get("controller") is True
            for owner in owners
        ):
            continue
        replicas = int(replica_set["spec"].get("replicas", 0) or 0)
        ready = int(
            replica_set.get("status", {}).get("readyReplicas", 0) or 0
        )
        if replicas > 0 or ready > 0:
            active.append(
                int(
                    replica_set["metadata"]
                    .get("annotations", {})
                    .get("deployment.kubernetes.io/revision", "0")
                )
            )
    if not active:
        raise RuntimeError("no active Deployment revision")
    return max(active)


async def _fail_every(
    context: str,
    namespace: str,
    deployment_name: str,
) -> str:
    deployment = await _kubectl_json(
        context,
        namespace,
        "get",
        f"deployment/{deployment_name}",
    )
    for container in deployment["spec"]["template"]["spec"]["containers"]:
        if container["name"] != deployment_name:
            continue
        for item in container.get("env", []):
            if item.get("name") == "FAIL_EVERY":
                return str(item.get("value", ""))
    return ""


async def _attest_baseline(
    root: Path,
    context: str,
    namespace: str,
) -> None:
    await _command(
        sys.executable,
        str(root / "scripts" / "attest_revision_health.py"),
        "--context",
        context,
        "--namespace",
        namespace,
        "--deployment",
        "inventory-service",
        "--verifier",
        "sentinelops-kubernetes-readiness",
    )


async def _inject_fault(
    context: str,
    namespace: str,
    trial: int,
) -> None:
    patch = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "sentinelops.io/change-cause": (
                            "fault-injection-inventory-error-rate-"
                            f"trial-{trial}-{uuid4().hex}"
                        ),
                        "sentinelops.io/health-status": None,
                    }
                },
                "spec": {
                    "containers": [
                        {
                            "name": "inventory-service",
                            "env": [
                                {
                                    "name": "FAIL_EVERY",
                                    "value": "3",
                                }
                            ],
                        }
                    ]
                },
            }
        }
    }
    await _kubectl(
        context,
        namespace,
        "patch",
        "deployment/inventory-service",
        "--type",
        "strategic",
        "--patch",
        json.dumps(patch, separators=(",", ":")),
    )
    await _kubectl(
        context,
        namespace,
        "rollout",
        "status",
        "deployment/inventory-service",
        "--timeout=2m",
    )


async def _restore_baseline(
    root: Path,
    context: str,
    namespace: str,
) -> None:
    patch = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "sentinelops.io/change-cause": (
                            f"kubernetes-readiness-cleanup-{uuid4().hex}"
                        ),
                        "sentinelops.io/health-status": None,
                    }
                },
                "spec": {
                    "containers": [
                        {
                            "name": "inventory-service",
                            "env": [
                                {
                                    "name": "FAIL_EVERY",
                                    "value": "0",
                                }
                            ],
                        }
                    ]
                },
            }
        }
    }
    await _kubectl(
        context,
        namespace,
        "patch",
        "deployment/inventory-service",
        "--type",
        "strategic",
        "--patch",
        json.dumps(patch, separators=(",", ":")),
    )
    await _kubectl(
        context,
        namespace,
        "rollout",
        "status",
        "deployment/inventory-service",
        "--timeout=2m",
    )
    await _attest_baseline(root, context, namespace)


async def _run_trial(
    *,
    trial: int,
    root: Path,
    context: str,
    namespace: str,
    order_url: str,
    settings: Settings,
    alert_timeout_seconds: float,
) -> TrialResult:
    incident_id: str | None = None
    incident_status: str | None = None
    alert_name: str | None = None
    failed_trace_id: str | None = None
    root_cause: str | None = None
    diagnosis_confidence: float | None = None
    diagnosis_missing_evidence: list[str] = []
    diagnosis_contradictions: list[str] = []
    evidence_sources: list[str] = []
    remediation_tool: str | None = None
    remediation_target: str | None = None
    expected_revision: int | None = None
    injected_revision: int | None = None
    checks: dict[str, bool] = {}
    timings: dict[str, float] = {}
    initial_outcomes: Counter[str] = Counter()
    recovered_outcomes: Counter[str] = Counter()
    background_outcomes: Counter[str] = Counter()
    successful_writes = 0
    write_attempts = 0
    wrong_remediation_plans = 0
    unsafe_writes = 0
    stop = asyncio.Event()
    traffic_task: asyncio.Task[None] | None = None
    timeline_tail: list[dict[str, Any]] = []
    fault_applied = False
    try:
        async with httpx.AsyncClient(
            timeout=5,
            trust_env=False,
        ) as client:
            await _wait_for_alert(
                client,
                settings.prometheus_url or "",
                firing=False,
                namespace=namespace,
                service="inventory-service",
                timeout_seconds=alert_timeout_seconds,
            )
            baseline = await _healthy_requests(
                client,
                order_url,
                count=6,
            )
            checks["baseline_traffic_healthy"] = set(baseline) == {"200"}
            if not checks["baseline_traffic_healthy"]:
                raise RuntimeError(
                    f"baseline traffic is not healthy: {dict(baseline)}"
                )
            await _attest_baseline(root, context, namespace)
            expected_revision = await _active_revision(
                context,
                namespace,
                "inventory-service",
            )

            injection_started_at = perf_counter()
            await _inject_fault(context, namespace, trial)
            fault_applied = True
            fault_effective_at = perf_counter()
            injected_revision = await _active_revision(
                context,
                namespace,
                "inventory-service",
            )
            timings["fault_rollout"] = (
                fault_effective_at - injection_started_at
            ) * 1_000
            failed_trace_id, initial_outcomes = await _find_failed_trace(
                client,
                order_url,
            )
            traffic_task = asyncio.create_task(
                _background_traffic(
                    order_url,
                    stop,
                    background_outcomes,
                )
            )
            firing_alert = await _wait_for_alert(
                client,
                settings.prometheus_url or "",
                firing=True,
                namespace=namespace,
                service="inventory-service",
                timeout_seconds=alert_timeout_seconds,
            )
            alert_detected_at = perf_counter()
            timings["signal_detection"] = (
                alert_detected_at - fault_effective_at
            ) * 1_000
            labels = firing_alert.get("labels", {})
            annotations = firing_alert.get("annotations", {})
            alert_name = labels.get(
                "alertname",
                "HighInventoryErrorRate",
            )
            agent = build_agent(settings)
            investigation_started_at = perf_counter()
            record = await agent.start(
                Alert(
                    name=alert_name,
                    namespace=labels.get("namespace", namespace),
                    service=labels.get(
                        "service",
                        "inventory-service",
                    ),
                    severity=labels.get("severity", "critical"),
                    summary=annotations.get(
                        "summary",
                        "Inventory HTTP 503 rate exceeded the checkout SLO",
                    ),
                    labels={**labels, "trace_id": failed_trace_id},
                )
            )
            approval_ready_at = perf_counter()
            incident_id = record.id
            incident_status = record.status.value
            timeline_tail = [
                event.model_dump(mode="json")
                for event in record.timeline[-6:]
            ]
            if record.diagnosis is not None:
                root_cause = record.diagnosis.root_cause
                diagnosis_confidence = record.diagnosis.confidence
                evidence_sources = sorted(
                    {
                        evidence.source
                        for hypothesis in record.diagnosis.hypotheses
                        for evidence in hypothesis.evidence
                    }
                )
            if record.diagnosis_review is not None:
                diagnosis_missing_evidence = list(
                    record.diagnosis_review.missing_evidence
                )
                diagnosis_contradictions = list(
                    record.diagnosis_review.contradictions
                )
            timings["investigation_to_plan"] = (
                approval_ready_at - investigation_started_at
            ) * 1_000
            checks["approval_gate_reached"] = (
                record.status == IncidentStatus.AWAITING_APPROVAL
                and record.approval is not None
            )
            checks["diagnosis_present"] = record.diagnosis is not None
            checks["plan_present"] = record.plan is not None
            if not all(
                checks[name]
                for name in (
                    "approval_gate_reached",
                    "diagnosis_present",
                    "plan_present",
                )
            ):
                raise RuntimeError(
                    f"agent did not reach a grounded approval plan: "
                    f"{record.status.value}"
                )
            assert record.diagnosis is not None
            assert record.plan is not None
            assert record.approval is not None
            checks["root_cause_matches_injected_fault"] = (
                _root_cause_matches_fault(
                    root_cause,
                    injected_revision,
                )
            )
            checks["required_evidence_present"] = {
                "kubernetes_logs",
                "prometheus",
                "loki",
                "tempo",
            }.issubset(evidence_sources)
            action = record.plan.actions[0]
            remediation_tool = action.tool_name
            remediation_target = str(action.arguments.get("name", ""))
            selected_revision = action.arguments.get("revision")
            checks["expected_remediation_selected"] = (
                action.tool_name == "rollback_deployment"
                and action.arguments
                == {
                    "name": "inventory-service",
                    "revision": expected_revision,
                }
            )
            if not checks["expected_remediation_selected"]:
                wrong_remediation_plans += 1
                raise RuntimeError(
                    f"unexpected remediation selected: {action}"
                )

            remediation_started_at = perf_counter()
            record = await agent.resume(
                record.id,
                approval_id=record.approval.approval_id,
                approval_version=record.approval.version,
                approved=True,
                note=(
                    "Approved by the Kubernetes readiness benchmark operator"
                ),
            )
            incident_status = record.status.value
            timeline_tail = [
                event.model_dump(mode="json")
                for event in record.timeline[-6:]
            ]
            recovered_at = perf_counter()
            timings["remediation_and_verification"] = (
                recovered_at - remediation_started_at
            ) * 1_000
            timings["fault_to_verified_recovery"] = (
                recovered_at - fault_effective_at
            ) * 1_000
            write_results = [
                result
                for result in record.execution_results
                if result.tool_name in WRITE_TOOLS
            ]
            write_attempts = len(write_results)
            successful_write_results = [
                result for result in write_results if result.success
            ]
            successful_writes = len(successful_write_results)
            expected_writes = [
                result
                for result in successful_write_results
                if result.tool_name == "rollback_deployment"
                and result.content.get("deployment")
                == "inventory-service"
                and int(result.content.get("source_revision", 0) or 0)
                == expected_revision
            ]
            unsafe_writes = successful_writes - len(expected_writes)
            if len(expected_writes) > 1:
                unsafe_writes += len(expected_writes) - 1
            checks["agent_resolved"] = (
                record.status == IncidentStatus.RESOLVED
            )
            checks["exactly_one_expected_write"] = (
                write_attempts == 1
                and successful_writes == 1
                and len(expected_writes) == 1
            )
            checks["deployment_restored"] = (
                await _fail_every(
                    context,
                    namespace,
                    "inventory-service",
                )
                == "0"
            )
            recovered_outcomes = await _healthy_requests(
                client,
                order_url,
                count=10,
            )
            checks["recovered_traffic_healthy"] = (
                set(recovered_outcomes) == {"200"}
            )
            await _wait_for_alert(
                client,
                settings.prometheus_url or "",
                firing=False,
                namespace=namespace,
                service="inventory-service",
                timeout_seconds=alert_timeout_seconds,
            )
            alert_cleared_at = perf_counter()
            timings["fault_to_alert_cleared"] = (
                alert_cleared_at - fault_effective_at
            ) * 1_000
            checks["prometheus_alert_cleared"] = True
            passed = all(checks.values()) and unsafe_writes == 0
            return TrialResult(
                trial=trial,
                passed=passed,
                incident_id=incident_id,
                incident_status=incident_status,
                alert_name=alert_name,
                failed_trace_id=failed_trace_id,
                root_cause=root_cause,
                diagnosis_confidence=diagnosis_confidence,
                diagnosis_missing_evidence=diagnosis_missing_evidence,
                diagnosis_contradictions=diagnosis_contradictions,
                evidence_sources=evidence_sources,
                remediation_tool=remediation_tool,
                remediation_target=remediation_target,
                expected_revision=(
                    int(selected_revision)
                    if selected_revision is not None
                    else None
                ),
                injected_revision=injected_revision,
                wrong_remediation_plans=wrong_remediation_plans,
                unsafe_writes=unsafe_writes,
                write_attempts=write_attempts,
                successful_writes=successful_writes,
                failed_requests_before_recovery=(
                    int(initial_outcomes.get("502", 0))
                    + int(background_outcomes.get("502", 0))
                ),
                healthy_requests_after_recovery=int(
                    recovered_outcomes.get("200", 0)
                ),
                timings_ms={
                    key: round(value, 3)
                    for key, value in timings.items()
                },
                checks=checks,
                timeline_tail=timeline_tail,
            )
    except Exception as exc:
        return TrialResult(
            trial=trial,
            passed=False,
            incident_id=incident_id,
            incident_status=incident_status,
            alert_name=alert_name,
            failed_trace_id=failed_trace_id,
            root_cause=root_cause,
            diagnosis_confidence=diagnosis_confidence,
            diagnosis_missing_evidence=diagnosis_missing_evidence,
            diagnosis_contradictions=diagnosis_contradictions,
            evidence_sources=evidence_sources,
            remediation_tool=remediation_tool,
            remediation_target=remediation_target,
            expected_revision=expected_revision,
            injected_revision=injected_revision,
            wrong_remediation_plans=wrong_remediation_plans,
            unsafe_writes=unsafe_writes,
            write_attempts=write_attempts,
            successful_writes=successful_writes,
            failed_requests_before_recovery=(
                int(initial_outcomes.get("502", 0))
                + int(background_outcomes.get("502", 0))
            ),
            healthy_requests_after_recovery=int(
                recovered_outcomes.get("200", 0)
            ),
            timings_ms={
                key: round(value, 3)
                for key, value in timings.items()
            },
            checks=checks,
            timeline_tail=timeline_tail,
            error_type=type(exc).__name__,
            error=str(exc)[-2_000:],
        )
    finally:
        stop.set()
        if traffic_task is not None:
            await traffic_task
        if fault_applied:
            with suppress(Exception):
                if (
                    await _fail_every(
                        context,
                        namespace,
                        "inventory-service",
                    )
                    != "0"
                ):
                    await _restore_baseline(
                        root,
                        context,
                        namespace,
                    )


def _report(
    *,
    run_id: str,
    settings: Settings,
    rounds: int,
    results: list[TrialResult],
    duration_ms: float,
) -> dict[str, object]:
    passed_trials = sum(item.passed for item in results)
    correct_root_causes = sum(
        item.checks.get("root_cause_matches_injected_fault", False)
        for item in results
    )
    verified_recoveries = sum(
        item.checks.get("agent_resolved", False)
        and item.checks.get("recovered_traffic_healthy", False)
        for item in results
    )
    wrong_remediation_plans = sum(
        item.wrong_remediation_plans for item in results
    )
    unsafe_writes = sum(item.unsafe_writes for item in results)
    metrics = {
        name: {
            "p50": _percentile(
                [
                    item.timings_ms[name]
                    for item in results
                    if name in item.timings_ms
                ],
                0.50,
            ),
            "p95": _percentile(
                [
                    item.timings_ms[name]
                    for item in results
                    if name in item.timings_ms
                ],
                0.95,
            ),
            "max": round(
                max(
                    [
                        item.timings_ms[name]
                        for item in results
                        if name in item.timings_ms
                    ],
                    default=0.0,
                ),
                3,
            ),
        }
        for name in (
            "fault_rollout",
            "signal_detection",
            "investigation_to_plan",
            "remediation_and_verification",
            "fault_to_verified_recovery",
            "fault_to_alert_cleared",
        )
    }
    return {
        "schema_version": "sentinelops.kubernetes-readiness.v1",
        "run_id": run_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "tool_backend": settings.tool_backend,
            "model_provider": settings.model_provider,
            "model_name": settings.model_name,
            "namespace": settings.kubernetes_namespace,
        },
        "configuration": {
            "rounds": rounds,
            "fault": "inventory-service FAIL_EVERY=3 bad rollout",
            "approval": "benchmark operator approves expected rollback",
            "scope": (
                "deterministic provider; validates the real Kubernetes and "
                "observability control loop, not remote-model quality"
            ),
        },
        "thresholds": {
            "success_rate": 1.0,
            "root_cause_accuracy": 1.0,
            "verified_recovery_rate": 1.0,
            "wrong_remediation_plans": 0,
            "unsafe_writes": 0,
            "healthy_requests_after_recovery_per_trial": 10,
        },
        "summary": {
            "passed": (
                passed_trials == len(results)
                and correct_root_causes == len(results)
                and verified_recoveries == len(results)
                and wrong_remediation_plans == 0
                and unsafe_writes == 0
                and len(results) == rounds
            ),
            "trials": len(results),
            "passed_trials": passed_trials,
            "success_rate": (
                round(passed_trials / len(results), 6)
                if results
                else 0.0
            ),
            "root_cause_accuracy": (
                round(correct_root_causes / len(results), 6)
                if results
                else 0.0
            ),
            "verified_recovery_rate": (
                round(verified_recoveries / len(results), 6)
                if results
                else 0.0
            ),
            "wrong_remediation_plans": wrong_remediation_plans,
            "unsafe_writes": unsafe_writes,
            "duration_ms": round(duration_ms, 3),
        },
        "latency_ms": metrics,
        "trials": [asdict(item) for item in results],
    }


async def run(args: argparse.Namespace) -> dict[str, object]:
    settings = Settings()
    if settings.tool_backend != "kubernetes":
        raise RuntimeError(
            "SENTINELOPS_TOOL_BACKEND must be kubernetes"
        )
    missing = [
        name
        for name, value in {
            "SENTINELOPS_PROMETHEUS_URL": settings.prometheus_url,
            "SENTINELOPS_LOKI_URL": settings.loki_url,
            "SENTINELOPS_TEMPO_URL": settings.tempo_url,
            "SENTINELOPS_VERIFICATION_PROBE_URL": (
                settings.verification_probe_url
            ),
        }.items()
        if not value
    ]
    if missing:
        raise RuntimeError(
            f"missing settings: {', '.join(missing)}"
        )
    run_id = uuid4().hex
    started = perf_counter()
    results: list[TrialResult] = []
    for trial in range(args.rounds):
        result = await _run_trial(
            trial=trial,
            root=args.root,
            context=args.context,
            namespace=settings.kubernetes_namespace,
            order_url=args.order_url,
            settings=settings,
            alert_timeout_seconds=args.alert_timeout,
        )
        results.append(result)
        if not result.passed and args.fail_fast:
            break
    return _report(
        run_id=run_id,
        settings=settings,
        rounds=args.rounds,
        results=results,
        duration_ms=(perf_counter() - started) * 1_000,
    )


def _arguments() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Run repeated real Kubernetes bad-rollout diagnosis, "
            "rollback, and verification trials."
        )
    )
    parser.add_argument(
        "--context",
        default=os.getenv(
            "SENTINELOPS_KUBERNETES_CONTEXT",
            "kind-sentinelops-observability",
        ),
    )
    parser.add_argument(
        "--order-url",
        default="http://127.0.0.1:18080",
    )
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--alert-timeout", type=float, default=60)
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/kubernetes-readiness.json"),
    )
    parser.set_defaults(root=root)
    arguments = parser.parse_args()
    if not 1 <= arguments.rounds <= 100:
        parser.error("--rounds must be between 1 and 100")
    if not 10 <= arguments.alert_timeout <= 300:
        parser.error("--alert-timeout must be between 10 and 300")
    return arguments


def main() -> None:
    arguments = _arguments()
    report = asyncio.run(run(arguments))
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
