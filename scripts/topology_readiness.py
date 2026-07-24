from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import re
from collections import Counter
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

import httpx
from kubernetes_readiness import (
    _active_revision,
    _attest_baseline,
    _background_traffic,
    _fail_every,
    _find_failed_trace,
    _healthy_requests,
    _inject_fault,
    _kubectl_json,
    _percentile,
    _restore_baseline,
    _root_cause_matches_fault,
    _wait_for_alert,
)

from sentinelops.anchor_crypto import (
    load_ed25519_public_keyring,
    verify_receipt_signature,
)

INCIDENT_ID = re.compile(r"^[0-9a-f-]{36}$")


@dataclass(frozen=True)
class TopologyTrial:
    passed: bool
    incident_id: str | None
    incident_status: str | None
    injected_revision: int | None
    expected_revision: int | None
    root_cause: str | None
    evidence_sources: list[str]
    failed_trace_id: str | None
    approving_api_url: str | None
    executor_id: str | None
    action_intents: int
    audit_events: int
    failed_requests_before_recovery: int
    healthy_requests_after_recovery: int
    wrong_remediation_plans: int
    unsafe_writes: int
    timings_ms: dict[str, float]
    checks: dict[str, bool]
    database_snapshot: dict[str, Any]
    chaos: dict[str, Any] = field(default_factory=dict)
    security: dict[str, Any] = field(default_factory=dict)
    error_type: str | None = None
    error: str | None = None


async def _incident_list(
    client: httpx.AsyncClient,
    api_url: str,
) -> list[dict[str, Any]]:
    response = await client.get(
        f"{api_url.rstrip('/')}/api/v1/incidents",
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, list):
        raise RuntimeError("incident list response is not an array")
    return payload


async def _incident(
    client: httpx.AsyncClient,
    api_url: str,
    incident_id: str,
) -> dict[str, Any]:
    response = await client.get(
        f"{api_url.rstrip('/')}/api/v1/incidents/{incident_id}",
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("incident response is not an object")
    return payload


async def _wait_for_new_incident(
    client: httpx.AsyncClient,
    api_urls: list[str],
    *,
    existing_ids: set[str],
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        for api_url in api_urls:
            try:
                incidents = await _incident_list(client, api_url)
            except httpx.HTTPError:
                continue
            match = next(
                (
                    item
                    for item in incidents
                    if item.get("id") not in existing_ids
                    and item.get("alert", {}).get("name") == "HighInventoryErrorRate"
                    and item.get("alert", {}).get("namespace") == "sentinelops-demo"
                    and item.get("alert", {}).get("service") == "inventory-service"
                ),
                None,
            )
            if match is not None:
                return match
        await asyncio.sleep(0.5)
    raise RuntimeError("Alertmanager webhook did not create a durable incident")


async def _wait_for_status(
    client: httpx.AsyncClient,
    api_urls: list[str],
    incident_id: str,
    *,
    statuses: set[str],
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    last_status: str | None = None
    while asyncio.get_running_loop().time() < deadline:
        for api_url in api_urls:
            try:
                record = await _incident(client, api_url, incident_id)
            except httpx.HTTPError:
                continue
            last_status = str(record.get("status"))
            if last_status in statuses:
                return record
        await asyncio.sleep(0.5)
    raise RuntimeError(f"incident did not reach {sorted(statuses)}; last_status={last_status}")


async def _approve(
    client: httpx.AsyncClient,
    api_urls: list[str],
    record: dict[str, Any],
    *,
    authorization_token: str | None = None,
) -> tuple[dict[str, Any], str]:
    approval = record.get("approval")
    if not isinstance(approval, dict):
        raise RuntimeError("incident has no approval request")
    payload = {
        "approval_id": approval["approval_id"],
        "approval_version": approval["version"],
        "approved": True,
        "note": "Approved by the topology readiness benchmark operator",
    }
    conflicts: list[str] = []
    headers = {"Authorization": f"Bearer {authorization_token}"} if authorization_token else None
    for api_url in api_urls:
        response = await client.post(
            f"{api_url.rstrip('/')}/api/v1/incidents/{record['id']}/approval",
            json=payload,
            headers=headers,
            timeout=150,
        )
        if response.status_code == 200:
            result = response.json()
            if not isinstance(result, dict):
                raise RuntimeError("approval response is not an object")
            return result, api_url
        if response.status_code == 409:
            conflicts.append(str(response.json().get("detail", "")))
            continue
        raise RuntimeError(
            f"approval failed through {api_url}: "
            f"status={response.status_code}, body={response.text[-1000:]}"
        )
    raise RuntimeError(
        "no API replica could safely resume the durable approval: " + " | ".join(conflicts)
    )


async def _approve_with_retry(
    client: httpx.AsyncClient,
    api_url: str,
    record: dict[str, Any],
    *,
    timeout_seconds: float,
    authorization_token: str | None = None,
) -> tuple[dict[str, Any], str]:
    approval = record.get("approval")
    if not isinstance(approval, dict):
        raise RuntimeError("incident has no approval request")
    payload = {
        "approval_id": approval["approval_id"],
        "approval_version": approval["version"],
        "approved": True,
        "note": "Approved after API failover by the topology benchmark operator",
    }
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    last_conflict = ""
    headers = {"Authorization": f"Bearer {authorization_token}"} if authorization_token else None
    while asyncio.get_running_loop().time() < deadline:
        response = await client.post(
            f"{api_url.rstrip('/')}/api/v1/incidents/{record['id']}/approval",
            json=payload,
            headers=headers,
            timeout=timeout_seconds,
        )
        if response.status_code == 200:
            result = response.json()
            if not isinstance(result, dict):
                raise RuntimeError("approval response is not an object")
            return result, api_url
        if response.status_code != 409:
            raise RuntimeError(
                f"approval failed after API failover: "
                f"status={response.status_code}, body={response.text[-1000:]}"
            )
        last_conflict = str(response.json().get("detail", ""))
        await asyncio.sleep(0.5)
    raise RuntimeError(
        f"surviving API replica did not restore the durable approval: {last_conflict}"
    )


async def _database_snapshot(
    context: str,
    incident_id: str,
) -> dict[str, Any]:
    if not INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("invalid incident ID")
    sql = f"""
SELECT json_build_object(
  'schema_revision', (
    SELECT version_num FROM alembic_version LIMIT 1
  ),
  'action_intents', COALESCE((
    SELECT json_agg(json_build_object(
      'status', status,
      'executor_id', executor_id,
      'executor_generation', executor_generation,
      'attempt_id', attempt_id,
      'action', action,
      'result', result
    ) ORDER BY created_at)
    FROM sentinelops_action_intents
    WHERE incident_id = '{incident_id}'
  ), '[]'::json),
  'approval_status', (
    SELECT status FROM sentinelops_approvals
    WHERE incident_id = '{incident_id}'
    ORDER BY version DESC LIMIT 1
  ),
  'alert_binding_status', (
    SELECT status FROM sentinelops_alert_bindings
    WHERE incident_id = '{incident_id}'
    LIMIT 1
  ),
  'audit_events', (
    SELECT count(*) FROM sentinelops_audit_events
    WHERE incident_id = '{incident_id}'
  ),
  'hmac_audit_events', (
    SELECT count(*) FROM sentinelops_audit_events
    WHERE incident_id = '{incident_id}'
      AND auth_algorithm = 'hmac-sha256'
      AND key_id = 'topology-e2e-v1'
  ),
  'approval_audit_events', COALESCE((
    SELECT json_agg(json_build_object(
      'actor_id', actor_id,
      'actor_assurance', actor_assurance,
      'actor_type', actor_type
    ) ORDER BY sequence)
    FROM sentinelops_audit_events
    WHERE incident_id = '{incident_id}'
      AND event_type = 'approval.approved'
  ), '[]'::json),
  'audit_head_sequence', (
    SELECT last_sequence FROM sentinelops_audit_heads
    WHERE incident_id = '{incident_id}'
  ),
  'audit_head_hash', (
    SELECT last_hash FROM sentinelops_audit_heads
    WHERE incident_id = '{incident_id}'
  ),
  'anchor_outbox_total', (
    SELECT count(*) FROM sentinelops_audit_anchor_outbox
    WHERE incident_id = '{incident_id}'
  ),
  'anchor_outbox_undelivered', (
    SELECT count(*) FROM sentinelops_audit_anchor_outbox
    WHERE incident_id = '{incident_id}'
      AND status <> 'delivered'
  ),
  'latest_anchor_receipt', (
    SELECT receipt FROM sentinelops_audit_anchor_outbox
    WHERE incident_id = '{incident_id}'
      AND status = 'delivered'
    ORDER BY sequence DESC LIMIT 1
  ),
  'anchor_security_status', (
    SELECT status FROM sentinelops_audit_anchor_security_state
    WHERE scope_id = 'external-audit-anchor'
  ),
  'anchor_security_write_blocked', (
    SELECT write_blocked FROM sentinelops_audit_anchor_security_state
    WHERE scope_id = 'external-audit-anchor'
  ),
  'action_claim_events', COALESCE((
    SELECT json_agg(json_build_object(
      'actor_id', actor_id,
      'payload', payload
    ) ORDER BY sequence)
    FROM sentinelops_audit_events
    WHERE incident_id = '{incident_id}'
      AND event_type = 'action.claimed'
  ), '[]'::json),
  'action_requeue_events', COALESCE((
    SELECT json_agg(json_build_object(
      'actor_id', actor_id,
      'payload', payload
    ) ORDER BY sequence)
    FROM sentinelops_audit_events
    WHERE incident_id = '{incident_id}'
      AND event_type = 'action.requeued'
  ), '[]'::json)
)::text;
"""
    output = await _command(
        "kubectl",
        "--context",
        context,
        "--namespace",
        "sentinelops-system",
        "exec",
        "deployment/postgres",
        "--",
        "psql",
        "--username",
        "sentinelops",
        "--dbname",
        "sentinelops",
        "--tuples-only",
        "--no-align",
        "--command",
        sql,
    )
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"unexpected PostgreSQL snapshot output: {lines}")
    payload = json.loads(lines[0])
    if not isinstance(payload, dict):
        raise RuntimeError("PostgreSQL snapshot is not an object")
    return payload


async def _command(*parts: str, timeout_seconds: float = 180) -> str:
    process = await asyncio.create_subprocess_exec(
        *parts,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout_seconds,
        )
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise RuntimeError(f"command timed out: {' '.join(parts[:4])}") from exc
    if process.returncode != 0:
        raise RuntimeError(
            f"command failed ({process.returncode}): "
            f"{' '.join(parts[:5])}: "
            f"{stderr.decode(errors='replace')[-2000:]}"
        )
    return stdout.decode()


async def _postgres_command(context: str, sql: str) -> str:
    return await _command(
        "kubectl",
        "--context",
        context,
        "--namespace",
        "sentinelops-system",
        "exec",
        "deployment/postgres",
        "--",
        "psql",
        "--username",
        "sentinelops",
        "--dbname",
        "sentinelops",
        "--tuples-only",
        "--no-align",
        "--set",
        "ON_ERROR_STOP=1",
        "--command",
        sql,
    )


async def _arm_first_dispatch_delay(context: str) -> None:
    await _postgres_command(
        context,
        """
DROP TRIGGER IF EXISTS sentinelops_chaos_delay_dispatch
  ON sentinelops_action_intents;
DROP FUNCTION IF EXISTS sentinelops_chaos_delay_first_dispatch();
DROP SEQUENCE IF EXISTS sentinelops_chaos_dispatch_sequence;
CREATE SEQUENCE sentinelops_chaos_dispatch_sequence START 1;
CREATE FUNCTION sentinelops_chaos_delay_first_dispatch()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.status = 'claimed'
     AND NEW.status = 'dispatched'
     AND nextval('sentinelops_chaos_dispatch_sequence') = 1 THEN
    PERFORM pg_sleep(45);
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER sentinelops_chaos_delay_dispatch
BEFORE UPDATE ON sentinelops_action_intents
FOR EACH ROW
EXECUTE FUNCTION sentinelops_chaos_delay_first_dispatch();
""",
    )


async def _disarm_first_dispatch_delay(context: str) -> None:
    await _postgres_command(
        context,
        """
DROP TRIGGER IF EXISTS sentinelops_chaos_delay_dispatch
  ON sentinelops_action_intents;
DROP FUNCTION IF EXISTS sentinelops_chaos_delay_first_dispatch();
DROP SEQUENCE IF EXISTS sentinelops_chaos_dispatch_sequence;
""",
    )


async def _action_runtime_snapshot(
    context: str,
    incident_id: str,
) -> dict[str, Any] | None:
    if not INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("invalid incident ID")
    output = await _postgres_command(
        context,
        f"""
SELECT COALESCE((
  SELECT json_build_object(
    'status', status,
    'executor_id', executor_id,
    'executor_generation', executor_generation,
    'attempt_id', attempt_id
  )::text
  FROM sentinelops_action_intents
  WHERE incident_id = '{incident_id}'
  ORDER BY created_at DESC
  LIMIT 1
), 'null');
""",
    )
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"unexpected action snapshot output: {lines}")
    payload = json.loads(lines[0])
    if payload is not None and not isinstance(payload, dict):
        raise RuntimeError("action snapshot is not an object")
    return payload


async def _wait_for_claimed_action(
    context: str,
    incident_id: str,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    last: dict[str, Any] | None = None
    while asyncio.get_running_loop().time() < deadline:
        last = await _action_runtime_snapshot(context, incident_id)
        if last is not None and last.get("status") == "claimed":
            return last
        if last is not None and last.get("status") in {
            "dispatched",
            "succeeded",
            "failed",
            "unknown",
            "cancelled",
        }:
            raise RuntimeError(f"action crossed the chaos boundary before pod deletion: {last}")
        await asyncio.sleep(0.1)
    raise RuntimeError(f"action was not claimed before timeout: {last}")


async def _webhook_receiver_pod(
    context: str,
    pod_names: list[str],
) -> str:
    matches: list[str] = []
    for pod_name in pod_names:
        logs = await _command(
            "kubectl",
            "--context",
            context,
            "--namespace",
            "sentinelops-system",
            "logs",
            f"pod/{pod_name}",
            "--since=5m",
        )
        if "POST /api/v1/webhooks/alertmanager" in logs:
            matches.append(pod_name)
    if len(matches) != 1:
        raise RuntimeError(
            f"could not identify the single Alertmanager webhook receiver: {matches}"
        )
    return matches[0]


async def _delete_pod(
    context: str,
    namespace: str,
    pod_name: str,
) -> None:
    await _command(
        "kubectl",
        "--context",
        context,
        "--namespace",
        namespace,
        "delete",
        f"pod/{pod_name}",
        "--grace-period=0",
        "--force",
        "--wait=false",
    )


async def _wait_for_replacement_pods(
    context: str,
    selector: str,
    *,
    deleted_pod: str,
    timeout_seconds: float,
) -> list[str]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    last: list[str] = []
    while asyncio.get_running_loop().time() < deadline:
        last = await _ready_pod_names(
            context,
            "sentinelops-system",
            selector,
        )
        if len(last) == 2 and deleted_pod not in last:
            return last
        await asyncio.sleep(0.5)
    raise RuntimeError(f"deployment did not replace pod {deleted_pod}; ready={last}")


async def _incident_from_pod(
    context: str,
    pod_name: str,
    incident_id: str,
) -> dict[str, Any]:
    if not INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("invalid incident ID")
    code = (
        "import sys, urllib.request; "
        "url='http://127.0.0.1:8000/api/v1/incidents/'+sys.argv[1]; "
        "print(urllib.request.urlopen(url, timeout=10).read().decode())"
    )
    output = await _command(
        "kubectl",
        "--context",
        context,
        "--namespace",
        "sentinelops-system",
        "exec",
        f"pod/{pod_name}",
        "--",
        "python",
        "-c",
        code,
        incident_id,
    )
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"unexpected API pod response: {lines}")
    payload = json.loads(lines[0])
    if not isinstance(payload, dict):
        raise RuntimeError("API pod incident response is not an object")
    return payload


async def _ready_pod_names(
    context: str,
    namespace: str,
    selector: str,
) -> list[str]:
    pods = await _kubectl_json(
        context,
        namespace,
        "get",
        "pods",
        "--selector",
        selector,
    )
    names = []
    for pod in pods.get("items", []):
        conditions = pod.get("status", {}).get("conditions", [])
        if any(item.get("type") == "Ready" and item.get("status") == "True" for item in conditions):
            names.append(str(pod["metadata"]["name"]))
    return sorted(names)


def _evidence_sources(record: dict[str, Any]) -> list[str]:
    diagnosis = record.get("diagnosis") or {}
    return sorted(
        {
            str(evidence.get("source"))
            for hypothesis in diagnosis.get("hypotheses", [])
            for evidence in hypothesis.get("evidence", [])
            if evidence.get("source")
        }
    )


def _timeline_has(record: dict[str, Any], event_type: str) -> bool:
    return any(event.get("type") == event_type for event in record.get("timeline", []))


def _recovery_event(record: dict[str, Any]) -> dict[str, Any] | None:
    return next(
        (
            event
            for event in reversed(record.get("timeline", []))
            if event.get("type") == "recovery.verified"
        ),
        None,
    )


def _read_required_secret(path: Path | None, label: str) -> str:
    if path is None:
        raise RuntimeError(f"{label} file is required in security E2E mode")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"{label} file cannot be read") from exc
    if not value:
        raise RuntimeError(f"{label} file is empty")
    return value


def _approval_payload(record: dict[str, Any]) -> dict[str, Any]:
    approval = record.get("approval")
    if not isinstance(approval, dict):
        raise RuntimeError("incident has no approval request")
    return {
        "approval_id": approval["approval_id"],
        "approval_version": approval["version"],
        "approved": True,
        "note": "SentinelOps security readiness authorization check",
    }


async def _operator_auth_checks(
    api_url: str,
    record: dict[str, Any],
    *,
    viewer_token: str,
    invalid_token: str,
) -> dict[str, bool]:
    incident_url = f"{api_url.rstrip('/')}/api/v1/incidents/{record['id']}"
    approval_url = f"{incident_url}/approval"
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10),
        trust_env=False,
        headers={"Connection": "close"},
    ) as client:
        missing = await client.get(incident_url)
        invalid = await client.get(
            incident_url,
            headers={"Authorization": f"Bearer {invalid_token}"},
        )
        viewer_approval = await client.post(
            approval_url,
            headers={"Authorization": f"Bearer {viewer_token}"},
            json=_approval_payload(record),
        )
    return {
        "missing_operator_token_rejected": missing.status_code == 401,
        "invalid_oidc_token_rejected": invalid.status_code == 401,
        "viewer_cannot_approve": viewer_approval.status_code == 403,
    }


async def _wait_for_anchored_head(
    context: str,
    incident_id: str,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    latest: dict[str, Any] = {}
    while asyncio.get_running_loop().time() < deadline:
        latest = await _database_snapshot(context, incident_id)
        receipt = latest.get("latest_anchor_receipt")
        if (
            int(latest.get("anchor_outbox_total", 0) or 0) > 0
            and int(latest.get("anchor_outbox_undelivered", 0) or 0) == 0
            and isinstance(receipt, dict)
            and receipt.get("sequence") == latest.get("audit_head_sequence")
            and receipt.get("head_hash") == latest.get("audit_head_hash")
        ):
            return latest
        await asyncio.sleep(0.25)
    raise RuntimeError("audit anchor Publisher did not deliver the final local audit head")


async def _external_anchor_receipt(
    anchor_url: str,
    incident_id: str,
    *,
    inventory_token: str,
) -> dict[str, Any]:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10),
        trust_env=False,
        headers={
            "Authorization": f"Bearer {inventory_token}",
            "Accept": "application/json",
        },
    ) as client:
        response = await client.get(
            f"{anchor_url.rstrip('/')}/v1/anchors/latest",
            params={
                "source_id": "kind-security-e2e",
                "incident_id": incident_id,
            },
        )
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("external anchor receipt is not an object")
    return payload


async def _run_trial(args: argparse.Namespace) -> TopologyTrial:
    checks: dict[str, bool] = {}
    timings: dict[str, float] = {}
    incident_id: str | None = None
    incident_status: str | None = None
    injected_revision: int | None = None
    expected_revision: int | None = None
    root_cause: str | None = None
    evidence_sources: list[str] = []
    failed_trace_id: str | None = None
    approving_api_url: str | None = None
    executor_id: str | None = None
    action_intents = 0
    audit_events = 0
    wrong_remediation_plans = 0
    unsafe_writes = 0
    initial_outcomes: Counter[str] = Counter()
    background_outcomes: Counter[str] = Counter()
    recovered_outcomes: Counter[str] = Counter()
    database_snapshot: dict[str, Any] = {}
    chaos: dict[str, Any] = {}
    security: dict[str, Any] = {}
    viewer_token: str | None = None
    approver_token: str | None = None
    invalid_token: str | None = None
    anchor_inventory_token: str | None = None
    anchor_public_keys = None
    stop = asyncio.Event()
    traffic_task: asyncio.Task[None] | None = None
    approval_task: asyncio.Task[tuple[dict[str, Any], str]] | None = None
    chaos_trigger_armed = False
    fault_applied = False
    try:
        if args.security_e2e:
            security = {"enabled": True}
            viewer_token = _read_required_secret(
                args.viewer_token_file,
                "viewer token",
            )
            approver_token = _read_required_secret(
                args.approver_token_file,
                "approver token",
            )
            invalid_token = _read_required_secret(
                args.invalid_token_file,
                "invalid token",
            )
            anchor_inventory_token = _read_required_secret(
                args.anchor_inventory_token_file,
                "anchor inventory token",
            )
            if args.anchor_public_keys_file is None:
                raise RuntimeError("anchor public keyring is required in security E2E mode")
            anchor_public_keys = load_ed25519_public_keyring(str(args.anchor_public_keys_file))
            checks["anchor_gate_started_blocked"] = bool(args.anchor_gate_started_blocked)
            checks["anchor_outage_failed_closed"] = bool(args.anchor_outage_failed_closed)
        client_headers = {"Connection": "close"}
        if viewer_token:
            client_headers["Authorization"] = f"Bearer {viewer_token}"
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10),
            trust_env=False,
            headers=client_headers,
        ) as client:
            api_pods = await _ready_pod_names(
                args.context,
                "sentinelops-system",
                "app.kubernetes.io/name=sentinelops-api",
            )
            executor_pods = await _ready_pod_names(
                args.context,
                "sentinelops-system",
                "app.kubernetes.io/name=sentinelops-executor",
            )
            current_executor_pods = list(executor_pods)
            checks["two_api_replicas_ready"] = len(api_pods) == 2
            checks["two_executor_replicas_ready"] = len(executor_pods) == 2
            if args.security_e2e:
                publisher_pods = await _ready_pod_names(
                    args.context,
                    "sentinelops-system",
                    "app.kubernetes.io/name=sentinelops-anchor-publisher",
                )
                checks["two_anchor_publishers_ready"] = len(publisher_pods) == 2
                gate = await _postgres_command(
                    args.context,
                    (
                        "SELECT status || ':' || write_blocked::text "
                        "FROM sentinelops_audit_anchor_security_state "
                        "WHERE scope_id='external-audit-anchor';"
                    ),
                )
                checks["anchor_gate_healthy_before_remediation"] = gate.strip() == "healthy:0"
            if not all(checks.values()):
                raise RuntimeError(
                    f"control plane is not ready: api={api_pods}, executor={executor_pods}"
                )

            existing_ids: set[str] = set()
            for api_url in args.api_url:
                existing_ids.update(
                    str(item["id"]) for item in await _incident_list(client, api_url)
                )
            await _wait_for_alert(
                client,
                args.prometheus_url,
                firing=False,
                namespace=args.namespace,
                service="inventory-service",
                timeout_seconds=args.timeout,
            )
            baseline = await _healthy_requests(
                client,
                args.order_url,
                count=6,
            )
            checks["baseline_traffic_healthy"] = set(baseline) == {"200"}
            if not checks["baseline_traffic_healthy"]:
                raise RuntimeError(f"baseline traffic is not healthy: {dict(baseline)}")
            await _attest_baseline(
                args.root,
                args.context,
                args.namespace,
            )
            expected_revision = await _active_revision(
                args.context,
                args.namespace,
                "inventory-service",
            )

            injection_started_at = perf_counter()
            await _inject_fault(
                args.context,
                args.namespace,
                args.trial,
            )
            fault_applied = True
            fault_effective_at = perf_counter()
            injected_revision = await _active_revision(
                args.context,
                args.namespace,
                "inventory-service",
            )
            timings["fault_rollout"] = (fault_effective_at - injection_started_at) * 1000
            failed_trace_id, initial_outcomes = await _find_failed_trace(
                client,
                args.order_url,
            )
            traffic_task = asyncio.create_task(
                _background_traffic(
                    args.order_url,
                    stop,
                    background_outcomes,
                )
            )
            await _wait_for_alert(
                client,
                args.prometheus_url,
                firing=True,
                namespace=args.namespace,
                service="inventory-service",
                timeout_seconds=args.timeout,
            )
            alert_firing_at = perf_counter()
            timings["fault_to_prometheus_firing"] = (alert_firing_at - fault_effective_at) * 1000

            record = await _wait_for_new_incident(
                client,
                args.api_url,
                existing_ids=existing_ids,
                timeout_seconds=args.timeout,
            )
            webhook_received_at = perf_counter()
            incident_id = str(record["id"])
            timings["prometheus_firing_to_webhook_incident"] = (
                webhook_received_at - alert_firing_at
            ) * 1000
            checks["alertmanager_webhook_received"] = _timeline_has(
                record,
                "alertmanager.received",
            )

            record = await _wait_for_status(
                client,
                args.api_url,
                incident_id,
                statuses={"awaiting_approval", "escalated", "failed"},
                timeout_seconds=args.timeout,
            )
            approval_ready_at = perf_counter()
            incident_status = str(record.get("status"))
            timings["webhook_to_approval_plan"] = (approval_ready_at - webhook_received_at) * 1000
            checks["approval_gate_reached"] = incident_status == "awaiting_approval" and isinstance(
                record.get("approval"), dict
            )
            diagnosis = record.get("diagnosis") or {}
            root_cause = diagnosis.get("root_cause")
            evidence_sources = _evidence_sources(record)
            checks["root_cause_matches_injected_fault"] = (
                injected_revision is not None
                and _root_cause_matches_fault(
                    root_cause,
                    injected_revision,
                )
            )
            checks["grounded_observability_evidence"] = {
                "kubernetes_logs",
                "prometheus",
                "loki",
            }.issubset(evidence_sources)
            plan = record.get("plan") or {}
            actions = plan.get("actions") or []
            expected_action = (
                len(actions) == 1
                and actions[0].get("tool_name") == "rollback_deployment"
                and actions[0].get("arguments")
                == {
                    "name": "inventory-service",
                    "revision": expected_revision,
                }
            )
            checks["expected_remediation_selected"] = expected_action
            if not expected_action:
                wrong_remediation_plans += 1
            if not all(
                checks[name]
                for name in (
                    "alertmanager_webhook_received",
                    "approval_gate_reached",
                    "root_cause_matches_injected_fault",
                    "grounded_observability_evidence",
                    "expected_remediation_selected",
                )
            ):
                raise RuntimeError(
                    f"durable investigation did not produce the expected "
                    f"grounded plan: status={incident_status}"
                )

            replica_records = [
                await _incident(client, api_url, incident_id) for api_url in args.api_url
            ]
            checks["durable_snapshot_visible_on_all_api_replicas"] = all(
                item.get("id") == incident_id
                and item.get("status") == "awaiting_approval"
                and item.get("approval", {}).get("approval_id") == record["approval"]["approval_id"]
                for item in replica_records
            )
            if not checks["durable_snapshot_visible_on_all_api_replicas"]:
                raise RuntimeError("API replicas do not expose the same durable approval")

            approval_urls = list(args.api_url)
            current_api_pods = list(api_pods)
            if args.security_e2e:
                assert viewer_token is not None
                assert invalid_token is not None
                auth_checks = await _operator_auth_checks(
                    approval_urls[0],
                    record,
                    viewer_token=viewer_token,
                    invalid_token=invalid_token,
                )
                checks.update(auth_checks)
                if not all(auth_checks.values()):
                    raise RuntimeError(f"OIDC authorization boundary failed: {auth_checks}")
            if args.control_plane_chaos:
                webhook_pod = await _webhook_receiver_pod(
                    args.context,
                    api_pods,
                )
                webhook_pod_index = api_pods.index(webhook_pod)
                surviving_url = args.api_url[1 - webhook_pod_index]
                api_restart_started_at = perf_counter()
                await _delete_pod(
                    args.context,
                    "sentinelops-system",
                    webhook_pod,
                )
                current_api_pods = await _wait_for_replacement_pods(
                    args.context,
                    "app.kubernetes.io/name=sentinelops-api",
                    deleted_pod=webhook_pod,
                    timeout_seconds=args.timeout,
                )
                timings["api_pod_replacement"] = (perf_counter() - api_restart_started_at) * 1000
                replacement_api_pods = [
                    pod_name for pod_name in current_api_pods if pod_name not in api_pods
                ]
                replacement_records = [
                    await _incident_from_pod(
                        args.context,
                        pod_name,
                        incident_id,
                    )
                    for pod_name in replacement_api_pods
                ]
                checks["webhook_owner_api_pod_restarted"] = (
                    webhook_pod not in current_api_pods and len(replacement_api_pods) == 1
                )
                checks["approval_survived_api_restart"] = (
                    len(replacement_records) == 1
                    and replacement_records[0].get("status") == "awaiting_approval"
                    and replacement_records[0].get("approval", {}).get("approval_id")
                    == record["approval"]["approval_id"]
                )
                chaos.update(
                    {
                        "deleted_api_pod": webhook_pod,
                        "replacement_api_pod": (
                            replacement_api_pods[0] if len(replacement_api_pods) == 1 else None
                        ),
                        "surviving_api_url": surviving_url,
                    }
                )
                await _arm_first_dispatch_delay(args.context)
                chaos_trigger_armed = True
                approval_urls = [surviving_url]

            remediation_started_at = perf_counter()
            if args.control_plane_chaos:
                approval_task = asyncio.create_task(
                    _approve_with_retry(
                        client,
                        approval_urls[0],
                        record,
                        timeout_seconds=args.timeout + 60,
                        authorization_token=approver_token,
                    )
                )
                first_claim = await _wait_for_claimed_action(
                    args.context,
                    incident_id,
                    timeout_seconds=args.timeout,
                )
                first_executor_id = str(first_claim.get("executor_id") or "")
                first_executor_pod = first_executor_id.split(":", 1)[0]
                if first_executor_pod not in executor_pods:
                    raise RuntimeError(
                        f"claimed action is not owned by a ready Executor pod: {first_claim}"
                    )
                executor_restart_started_at = perf_counter()
                await _delete_pod(
                    args.context,
                    "sentinelops-system",
                    first_executor_pod,
                )
                replacement_executor_pods = await _wait_for_replacement_pods(
                    args.context,
                    "app.kubernetes.io/name=sentinelops-executor",
                    deleted_pod=first_executor_pod,
                    timeout_seconds=args.timeout,
                )
                timings["executor_pod_replacement"] = (
                    perf_counter() - executor_restart_started_at
                ) * 1000
                checks["claimed_executor_pod_restarted"] = (
                    first_executor_pod not in replacement_executor_pods
                )
                current_executor_pods = replacement_executor_pods
                chaos.update(
                    {
                        "first_executor_id": first_executor_id,
                        "first_executor_generation": first_claim.get("executor_generation"),
                        "deleted_executor_pod": first_executor_pod,
                        "replacement_executor_pods": (replacement_executor_pods),
                    }
                )
                record, approving_api_url = await approval_task
                approval_task = None
            else:
                record, approving_api_url = await _approve(
                    client,
                    approval_urls,
                    record,
                    authorization_token=approver_token,
                )
            verified_at = perf_counter()
            incident_status = str(record.get("status"))
            timings["approval_to_verified_recovery"] = (verified_at - remediation_started_at) * 1000
            timings["fault_to_verified_recovery"] = (verified_at - fault_effective_at) * 1000

            database_snapshot = await _database_snapshot(
                args.context,
                incident_id,
            )
            intents = database_snapshot.get("action_intents") or []
            action_intents = len(intents)
            audit_events = int(database_snapshot.get("audit_events", 0) or 0)
            successful_expected = [
                item
                for item in intents
                if item.get("status") == "succeeded"
                and item.get("action", {}).get("tool_name") == "rollback_deployment"
                and item.get("action", {}).get("arguments")
                == {
                    "name": "inventory-service",
                    "revision": expected_revision,
                }
                and item.get("result", {}).get("success") is True
            ]
            successful_writes = [
                item
                for item in intents
                if item.get("status") == "succeeded"
                and item.get("result", {}).get("success") is True
            ]
            unsafe_writes = len(successful_writes) - len(successful_expected)
            if len(successful_expected) > 1:
                unsafe_writes += len(successful_expected) - 1
            executor_id = str(intents[0].get("executor_id")) if len(intents) == 1 else None
            checks["one_succeeded_action_intent"] = (
                len(intents) == 1 and len(successful_expected) == 1 and unsafe_writes == 0
            )
            checks["independent_executor_claimed_action"] = bool(
                executor_id
                and any(
                    executor_id.startswith(f"{pod_name}:") for pod_name in current_executor_pods
                )
            )
            if args.control_plane_chaos:
                claim_events = database_snapshot.get("action_claim_events") or []
                requeue_events = database_snapshot.get("action_requeue_events") or []
                final_executor_generation = (
                    int(intents[0].get("executor_generation", 0)) if len(intents) == 1 else 0
                )
                checks["expired_claim_requeued_once"] = len(requeue_events) == 1
                checks["different_executor_claim_generation_took_over"] = (
                    len(claim_events) == 2
                    and claim_events[0].get("actor_id") == chaos.get("first_executor_id")
                    and bool(executor_id)
                    and executor_id != chaos.get("first_executor_id")
                    and final_executor_generation > int(chaos.get("first_executor_generation") or 0)
                )
                chaos.update(
                    {
                        "final_executor_id": executor_id,
                        "final_executor_generation": (final_executor_generation),
                        "claim_events": len(claim_events),
                        "requeue_events": len(requeue_events),
                    }
                )
            checks["approval_persisted"] = database_snapshot.get("approval_status") == "approved"
            checks["hmac_audit_chain_persisted"] = (
                audit_events > 0
                and int(database_snapshot.get("hmac_audit_events", 0) or 0) == audit_events
            )
            checks["migration_head_applied"] = (
                database_snapshot.get("schema_revision") == "0008_anchor_unlock_workflow"
            )
            checks["agent_resolved"] = incident_status == "resolved"
            checks["deployment_restored"] = (
                await _fail_every(
                    args.context,
                    args.namespace,
                    "inventory-service",
                )
                == "0"
            )
            recovered_outcomes = await _healthy_requests(
                client,
                args.order_url,
                count=10,
            )
            checks["recovered_traffic_healthy"] = set(recovered_outcomes) == {"200"}
            recovery = _recovery_event(record)
            recovery_data = recovery.get("data", {}) if isinstance(recovery, dict) else {}
            checks["strict_recovery_evidence_present"] = bool(
                recovery
                and recovery_data.get("request_error_rate") == 0.0
                and recovery_data.get("alert_firing") is False
                and recovery_data.get("successful_trace_verified") is True
            )
            await _wait_for_alert(
                client,
                args.prometheus_url,
                firing=False,
                namespace=args.namespace,
                service="inventory-service",
                timeout_seconds=args.timeout,
            )
            alert_cleared_at = perf_counter()
            timings["fault_to_alert_cleared"] = (alert_cleared_at - fault_effective_at) * 1000

            deadline = asyncio.get_running_loop().time() + args.timeout
            while asyncio.get_running_loop().time() < deadline:
                database_snapshot = await _database_snapshot(
                    args.context,
                    incident_id,
                )
                if database_snapshot.get("alert_binding_status") == "resolved":
                    break
                await asyncio.sleep(0.5)
            checks["resolved_webhook_persisted"] = (
                database_snapshot.get("alert_binding_status") == "resolved"
            )
            final_records = (
                [
                    await _incident_from_pod(
                        args.context,
                        pod_name,
                        incident_id,
                    )
                    for pod_name in current_api_pods
                ]
                if args.control_plane_chaos
                else [await _incident(client, api_url, incident_id) for api_url in args.api_url]
            )
            checks["final_state_visible_on_all_api_replicas"] = all(
                item.get("status") == "resolved" and _timeline_has(item, "recovery.verified")
                for item in final_records
            )
            if args.security_e2e:
                assert anchor_inventory_token is not None
                assert anchor_public_keys is not None
                database_snapshot = await _wait_for_anchored_head(
                    args.context,
                    incident_id,
                    timeout_seconds=args.timeout,
                )
                audit_events = int(database_snapshot.get("audit_events", 0) or 0)
                approval_events = database_snapshot.get("approval_audit_events") or []
                checks["verified_oidc_approval_audited"] = (
                    len(approval_events) == 1
                    and approval_events[0].get("actor_assurance") == "oidc-human"
                    and approval_events[0].get("actor_type") == "operator"
                    and bool(
                        re.fullmatch(
                            r"[0-9a-f]{64}",
                            str(approval_events[0].get("actor_id") or ""),
                        )
                    )
                )
                checks["all_audit_anchors_delivered"] = (
                    int(
                        database_snapshot.get(
                            "anchor_outbox_undelivered",
                            -1,
                        )
                        or 0
                    )
                    == 0
                    and int(database_snapshot.get("anchor_outbox_total", 0) or 0) == audit_events
                )
                external_receipt = await _external_anchor_receipt(
                    args.anchor_url,
                    incident_id,
                    inventory_token=anchor_inventory_token,
                )
                receipt_key_id = external_receipt.get("receipt_key_id")
                receipt_public_key = (
                    anchor_public_keys.get(receipt_key_id)
                    if isinstance(receipt_key_id, str)
                    else None
                )
                checks["signed_external_anchor_matches_local_head"] = bool(
                    external_receipt.get("source_id") == "kind-security-e2e"
                    and external_receipt.get("incident_id") == incident_id
                    and external_receipt.get("receiver_id") == "kind-security-anchor"
                    and external_receipt.get("status") in {"accepted", "duplicate"}
                    and external_receipt.get("sequence")
                    == database_snapshot.get("audit_head_sequence")
                    and external_receipt.get("head_hash")
                    == database_snapshot.get("audit_head_hash")
                    and receipt_public_key is not None
                    and verify_receipt_signature(
                        external_receipt,
                        public_key=receipt_public_key,
                    )
                )
                checks["anchor_gate_remained_healthy"] = (
                    database_snapshot.get("anchor_security_status") == "healthy"
                    and int(
                        database_snapshot.get(
                            "anchor_security_write_blocked",
                            1,
                        )
                        or 0
                    )
                    == 0
                )
                security.update(
                    {
                        "operator_auth_mode": "oidc",
                        "approval_actor_assurance": (
                            approval_events[0].get("actor_assurance")
                            if len(approval_events) == 1
                            else None
                        ),
                        "approval_actor_id": (
                            approval_events[0].get("actor_id")
                            if len(approval_events) == 1
                            else None
                        ),
                        "anchor_source_id": external_receipt.get("source_id"),
                        "anchor_receiver_id": external_receipt.get("receiver_id"),
                        "anchor_receipt_key_id": receipt_key_id,
                        "anchor_sequence": external_receipt.get("sequence"),
                        "anchor_head_hash": external_receipt.get("head_hash"),
                    }
                )

            passed = all(checks.values()) and wrong_remediation_plans == 0 and unsafe_writes == 0
            return TopologyTrial(
                passed=passed,
                incident_id=incident_id,
                incident_status=incident_status,
                injected_revision=injected_revision,
                expected_revision=expected_revision,
                root_cause=root_cause,
                evidence_sources=evidence_sources,
                failed_trace_id=failed_trace_id,
                approving_api_url=approving_api_url,
                executor_id=executor_id,
                action_intents=action_intents,
                audit_events=audit_events,
                failed_requests_before_recovery=(
                    int(initial_outcomes.get("502", 0)) + int(background_outcomes.get("502", 0))
                ),
                healthy_requests_after_recovery=int(recovered_outcomes.get("200", 0)),
                wrong_remediation_plans=wrong_remediation_plans,
                unsafe_writes=unsafe_writes,
                timings_ms={key: round(value, 3) for key, value in timings.items()},
                checks=checks,
                database_snapshot=database_snapshot,
                chaos=chaos,
                security=security,
            )
    except Exception as exc:
        return TopologyTrial(
            passed=False,
            incident_id=incident_id,
            incident_status=incident_status,
            injected_revision=injected_revision,
            expected_revision=expected_revision,
            root_cause=root_cause,
            evidence_sources=evidence_sources,
            failed_trace_id=failed_trace_id,
            approving_api_url=approving_api_url,
            executor_id=executor_id,
            action_intents=action_intents,
            audit_events=audit_events,
            failed_requests_before_recovery=(
                int(initial_outcomes.get("502", 0)) + int(background_outcomes.get("502", 0))
            ),
            healthy_requests_after_recovery=int(recovered_outcomes.get("200", 0)),
            wrong_remediation_plans=wrong_remediation_plans,
            unsafe_writes=unsafe_writes,
            timings_ms={key: round(value, 3) for key, value in timings.items()},
            checks=checks,
            database_snapshot=database_snapshot,
            chaos=chaos,
            security=security,
            error_type=type(exc).__name__,
            error=str(exc)[-2000:],
        )
    finally:
        stop.set()
        if traffic_task is not None:
            await traffic_task
        if approval_task is not None:
            approval_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await approval_task
        if chaos_trigger_armed:
            with suppress(Exception):
                await _disarm_first_dispatch_delay(args.context)
        if fault_applied:
            with suppress(Exception):
                if (
                    await _fail_every(
                        args.context,
                        args.namespace,
                        "inventory-service",
                    )
                    != "0"
                ):
                    await _restore_baseline(
                        args.root,
                        args.context,
                        args.namespace,
                    )


def _report(
    trial: TopologyTrial,
    *,
    duration_ms: float,
) -> dict[str, Any]:
    thresholds_passed = (
        trial.passed
        and trial.wrong_remediation_plans == 0
        and trial.unsafe_writes == 0
        and trial.action_intents == 1
        and bool(trial.checks)
        and all(trial.checks.values())
    )
    return {
        "schema_version": (
            "sentinelops.security-readiness.v1"
            if trial.security
            else (
                "sentinelops.control-plane-chaos.v1"
                if trial.chaos
                else "sentinelops.topology-readiness.v1"
            )
        ),
        "run_id": uuid4().hex,
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "kubernetes": "kind",
            "api_replicas": 2,
            "executor_replicas": 2,
            "database": "PostgreSQL 16",
            "model_provider": "rule_based",
            "control_plane_chaos": bool(trial.chaos),
            "security_e2e": bool(trial.security),
        },
        "scope": (
            (
                "staging security acceptance topology with an ephemeral "
                "signed OIDC issuer and an independently persisted, signed "
                "audit anchor"
            )
            if trial.security
            else (
                "staging acceptance topology with ephemeral credentials; "
                "enterprise OIDC and external audit anchoring remain "
                "production deployment requirements"
            )
        ),
        "thresholds": {
            "passed": True,
            "wrong_remediation_plans": 0,
            "unsafe_writes": 0,
            "action_intents": 1,
        },
        "summary": {
            "passed": thresholds_passed,
            "wrong_remediation_plans": trial.wrong_remediation_plans,
            "unsafe_writes": trial.unsafe_writes,
            "action_intents": trial.action_intents,
            "audit_events": trial.audit_events,
            "control_plane_chaos": bool(trial.chaos),
            "security_e2e": bool(trial.security),
            "duration_ms": round(duration_ms, 3),
        },
        "latency_ms": {
            key: {
                "p50": _percentile([value], 0.5),
                "p95": _percentile([value], 0.95),
                "max": round(value, 3),
            }
            for key, value in trial.timings_ms.items()
        },
        "trial": asdict(trial),
    }


async def run(args: argparse.Namespace) -> dict[str, Any]:
    started = perf_counter()
    trial = await _run_trial(args)
    return _report(
        trial,
        duration_ms=(perf_counter() - started) * 1000,
    )


def _arguments() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Validate Alertmanager -> two API replicas -> PostgreSQL -> "
            "two independent Executors -> Kubernetes recovery."
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
        "--namespace",
        default="sentinelops-demo",
    )
    parser.add_argument(
        "--api-url",
        action="append",
        required=True,
    )
    parser.add_argument(
        "--order-url",
        default="http://127.0.0.1:18080",
    )
    parser.add_argument(
        "--prometheus-url",
        default="http://127.0.0.1:19090",
    )
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--trial", type=int, default=0)
    parser.add_argument(
        "--control-plane-chaos",
        action="store_true",
        help=(
            "Restart the webhook-owning API pod and the first Executor "
            "before its write transaction crosses the dispatch boundary."
        ),
    )
    parser.add_argument(
        "--security-e2e",
        action="store_true",
        help=(
            "Require signed OIDC operator authorization and independently "
            "verified signed audit-anchor receipts."
        ),
    )
    parser.add_argument(
        "--anchor-gate-started-blocked",
        action="store_true",
        help=(
            "Record that the bootstrap script observed the audit gate "
            "blocked before the Publisher was started."
        ),
    )
    parser.add_argument(
        "--anchor-outage-failed-closed",
        action="store_true",
        help=(
            "Record that the bootstrap script stopped the external Anchor "
            "and observed the durable write gate close after staleness."
        ),
    )
    parser.add_argument("--viewer-token-file", type=Path)
    parser.add_argument("--approver-token-file", type=Path)
    parser.add_argument("--invalid-token-file", type=Path)
    parser.add_argument(
        "--anchor-url",
        default="http://127.0.0.1:18200",
    )
    parser.add_argument("--anchor-inventory-token-file", type=Path)
    parser.add_argument("--anchor-public-keys-file", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/topology-readiness.json"),
    )
    parser.set_defaults(root=root)
    arguments = parser.parse_args()
    if len(arguments.api_url) != 2:
        parser.error("exactly two --api-url values are required")
    if not 30 <= arguments.timeout <= 300:
        parser.error("--timeout must be between 30 and 300")
    if arguments.control_plane_chaos and arguments.security_e2e:
        parser.error("--control-plane-chaos and --security-e2e must run separately")
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
