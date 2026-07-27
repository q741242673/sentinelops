from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sentinelops import __version__
from sentinelops.agent.execution import (
    ActionExecutionRejected,
    ActionExecutor,
    ActionOutcomeUnknown,
)
from sentinelops.domain import RemediationAction, ToolResult
from sentinelops.remediation_controller import RemediationGateway
from sentinelops.storage.base import (
    ActionIntentConflictError,
    ActionReconciliationClaim,
    ClusterAgentLeaseConflictError,
    ClusterAgentLeaseToken,
    IncidentStore,
    LeaseToken,
)
from sentinelops.tools.registry import ToolRegistry


class DirectActionExecutor(ActionExecutor):
    """Development-only executor used when no durable store is configured."""

    def __init__(self, tools: ToolRegistry) -> None:
        self.tools = tools

    async def execute(
        self,
        incident_id: str,
        *,
        idempotency_key: str | None,
        action: RemediationAction,
        precondition: dict[str, object],
    ) -> ToolResult:
        del incident_id, idempotency_key
        return await self.tools.call_guarded(
            action.tool_name,
            action.arguments,
            precondition,
        )


class QueuedActionExecutor(ActionExecutor):
    """API-side dispatcher: enqueue immutable intent and wait for an Executor result."""

    def __init__(
        self,
        store: IncidentStore,
        token: LeaseToken,
        *,
        poll_interval_seconds: float = 0.1,
        result_timeout_seconds: float = 120,
    ) -> None:
        self.store = store
        self.token = token
        self.poll_interval_seconds = poll_interval_seconds
        self.result_timeout_seconds = result_timeout_seconds

    async def execute(
        self,
        incident_id: str,
        *,
        idempotency_key: str | None,
        action: RemediationAction,
        precondition: dict[str, object],
    ) -> ToolResult:
        del action, precondition
        if incident_id != self.token.incident_id:
            raise RuntimeError("Action Intent 与 Worker Lease 的事故标识不一致")
        if idempotency_key is None:
            raise RuntimeError("持久化执行必须绑定 Action Intent")
        await self.store.enqueue_action(
            self.token,
            idempotency_key=idempotency_key,
        )

        async def wait_for_result() -> ToolResult:
            while True:
                intent = await self.store.latest_action_intent(incident_id)
                if intent is None or intent.idempotency_key != idempotency_key:
                    raise ActionIntentConflictError("等待中的 Action Intent 已丢失")
                if intent.status in {"succeeded", "failed"} and intent.result is not None:
                    return intent.result
                if intent.status == "cancelled":
                    raise ActionExecutionRejected(
                        intent.error or "Action Intent 已在执行前取消"
                    )
                if intent.status == "unknown":
                    raise ActionOutcomeUnknown(
                        intent.error or "外部写入结果未知，禁止自动重放"
                    )
                await asyncio.sleep(self.poll_interval_seconds)

        try:
            return await asyncio.wait_for(
                wait_for_result(),
                timeout=self.result_timeout_seconds,
            )
        except TimeoutError as exc:
            current = await self.store.latest_action_intent(incident_id)
            if (
                current is not None
                and current.status in {"succeeded", "failed"}
                and current.result is not None
            ):
                return current.result
            try:
                await self.store.cancel_action(
                    self.token,
                    idempotency_key=idempotency_key,
                    reason="等待独立 Executor 超时，已在写入分界前取消",
                )
            except ActionIntentConflictError:
                raise ActionOutcomeUnknown(
                    "等待独立 Executor 结果超时，操作可能已跨过写入分界且不会重放"
                ) from exc
            raise ActionExecutionRejected(
                "等待独立 Executor 超时，操作已在写入分界前取消"
            ) from exc


class ExecutorWorker:
    """Independent worker that submits the only Controller execution contract."""

    def __init__(
        self,
        store: IncidentStore,
        tools: ToolRegistry | None,
        *,
        owner_id: str,
        cluster_id: str,
        cluster_display_name: str | None = None,
        default_namespace: str | None = None,
        instance_id: str | None = None,
        session_id: str | None = None,
        version: str = __version__,
        capabilities: tuple[str, ...] | None = None,
        remediation_gateway: RemediationGateway | None = None,
        claim_ttl_seconds: float = 60,
        poll_interval_seconds: float = 0.5,
        missing_contract_grace_seconds: float = 30,
        registry_ttl_seconds: float = 60,
        registry_heartbeat_seconds: float = 15,
        health_callback: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.tools = tools
        self.remediation_gateway = remediation_gateway
        if self.tools is None and self.remediation_gateway is None:
            raise ValueError("Executor requires a direct tool registry or Controller gateway")
        cluster_id = cluster_id.strip()
        if not cluster_id:
            raise ValueError("Executor requires a non-empty cluster_id")
        self.owner_id = owner_id
        self.cluster_id = cluster_id
        self.cluster_display_name = (
            cluster_display_name or cluster_id
        ).strip()
        self.default_namespace = (
            default_namespace
            or getattr(remediation_gateway, "namespace", None)
            or "sentinelops-demo"
        ).strip()
        self.instance_id = (instance_id or owner_id).strip()
        self.session_id = (session_id or str(uuid4())).strip()
        self.version = version.strip()
        if capabilities is None:
            capabilities = (
                (
                    "action.execute",
                    "action.reconcile",
                    "backend.controller",
                )
                if remediation_gateway is not None
                else ("action.execute", "backend.direct")
            )
        self.capabilities = tuple(sorted(set(capabilities)))
        if not self.cluster_display_name:
            raise ValueError("Executor requires a non-empty cluster display name")
        if not self.default_namespace:
            raise ValueError("Executor requires a non-empty default namespace")
        if not self.instance_id:
            raise ValueError("Executor requires a non-empty instance_id")
        if not self.session_id:
            raise ValueError("Executor requires a non-empty session_id")
        if not self.version:
            raise ValueError("Executor requires a non-empty version")
        required_capabilities = {"action.execute"}
        if remediation_gateway is not None:
            required_capabilities.update(
                {"action.reconcile", "backend.controller"}
            )
        if not required_capabilities.issubset(self.capabilities):
            raise ValueError("Executor capabilities do not match its backend")
        self.claim_ttl_seconds = claim_ttl_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self.missing_contract_grace_seconds = missing_contract_grace_seconds
        self.registry_ttl_seconds = registry_ttl_seconds
        self.registry_heartbeat_seconds = registry_heartbeat_seconds
        if registry_ttl_seconds <= 0:
            raise ValueError("Executor registry TTL must be positive")
        if not 0 < registry_heartbeat_seconds <= registry_ttl_seconds / 3:
            raise ValueError(
                "Executor registry heartbeat must not exceed one third of TTL"
            )
        self.health_callback = health_callback
        self._agent_lease: ClusterAgentLeaseToken | None = None
        self._registry_ready = asyncio.Event()
        self._registration_lock = asyncio.Lock()

    async def run_once(self) -> bool:
        agent_lease = await self._refresh_registration_once()
        reconciled = await self._reconcile_once(agent_lease)
        executed = await self._execute_once(agent_lease)
        return reconciled or executed

    async def _execute_once(
        self,
        agent_lease: ClusterAgentLeaseToken,
    ) -> bool:
        claim = await self.store.claim_action_execution(
            agent_lease=agent_lease,
            owner_id=self.owner_id,
            attempt_id=str(uuid4()),
            ttl_seconds=self.claim_ttl_seconds,
        )
        if claim is None:
            return False
        if claim.cluster_id != self.cluster_id:
            raise RuntimeError(
                "Store returned an action claim for a different cluster"
            )

        async def heartbeat() -> None:
            while True:
                await asyncio.sleep(max(0.1, self.claim_ttl_seconds / 3))
                await self.store.heartbeat_action_claim(
                    claim,
                    agent_lease=agent_lease,
                    ttl_seconds=self.claim_ttl_seconds,
                )

        heartbeat_task = asyncio.create_task(heartbeat())
        try:
            dispatched = await self.store.mark_action_dispatched(
                claim,
                agent_lease=agent_lease,
            )
            if (
                dispatched.cluster_id != self.cluster_id
                or dispatched.precondition.get("cluster_id") != self.cluster_id
            ):
                raise RuntimeError(
                    "Action Intent cluster identity changed after claim"
                )
            if self.remediation_gateway is not None:
                result = await self.remediation_gateway.execute(dispatched)
            else:
                assert self.tools is not None
                result = await self.tools.call_guarded(
                    dispatched.action.tool_name,
                    dispatched.action.arguments,
                    dispatched.precondition,
                )
        except BaseException as exc:
            with suppress(Exception):
                await self.store.mark_action_unknown(
                    claim=claim,
                    agent_lease=agent_lease,
                    reason=f"Executor 调用没有返回可信结果：{exc}",
                )
            raise
        finally:
            heartbeat_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await heartbeat_task
        await self.store.complete_action(
            claim=claim,
            agent_lease=agent_lease,
            result=result,
        )
        return True

    async def _reconcile_once(
        self,
        agent_lease: ClusterAgentLeaseToken,
    ) -> bool:
        if self.remediation_gateway is None:
            return False
        claim = await self.store.claim_action_reconciliation(
            agent_lease=agent_lease,
            owner_id=self.owner_id,
            ttl_seconds=self.claim_ttl_seconds,
        )
        if claim is None:
            return False
        if (
            claim.cluster_id != self.cluster_id
            or claim.intent.cluster_id != self.cluster_id
            or claim.intent.precondition.get("cluster_id") != self.cluster_id
        ):
            raise RuntimeError(
                "Store returned a reconciliation claim for a different cluster"
            )
        retry_after = min(
            30.0,
            max(1.0, float(2 ** min(claim.attempt_count - 1, 5))),
        )
        try:
            observation = await self.remediation_gateway.observe(claim.intent)
            if observation.state == "terminal" and observation.result is not None:
                await self.store.complete_action_reconciliation(
                    claim,
                    agent_lease=agent_lease,
                    result=observation.result,
                )
                return True
            error = (
                observation.reason
                or f"Controller observation state={observation.state}"
            )
            if (
                not observation.retryable
                or (
                    observation.state == "not_found"
                    and self._reconciliation_deadline_elapsed(claim)
                )
            ):
                await self.store.dead_letter_action_reconciliation(
                    claim,
                    agent_lease=agent_lease,
                    error=error,
                )
                return True
            await self.store.retry_action_reconciliation(
                claim,
                agent_lease=agent_lease,
                error=error,
                retry_after_seconds=retry_after,
            )
        except asyncio.CancelledError:
            raise
        except ValueError as exc:
            with suppress(Exception):
                error = f"Controller 结果对账失败：{exc}"
                await self.store.dead_letter_action_reconciliation(
                    claim,
                    agent_lease=agent_lease,
                    error=error,
                )
        except Exception as exc:
            with suppress(Exception):
                await self.store.retry_action_reconciliation(
                    claim,
                    agent_lease=agent_lease,
                    error=f"Controller 结果对账失败：{exc}",
                    retry_after_seconds=retry_after,
                )
        return True

    def _reconciliation_deadline_elapsed(
        self,
        claim: ActionReconciliationClaim,
    ) -> bool:
        value = claim.intent.precondition.get("expires_at")
        if not isinstance(value, str):
            return True
        try:
            expires_at = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError:
            return True
        if expires_at.tzinfo is None:
            return True
        deadline = expires_at.astimezone(UTC) + timedelta(
            seconds=max(0, self.missing_contract_grace_seconds)
        )
        database_now = claim.expires_at - timedelta(
            seconds=max(0.1, self.claim_ttl_seconds)
        )
        return database_now >= deadline

    async def run_forever(self) -> None:
        try:
            async with asyncio.TaskGroup() as tasks:
                tasks.create_task(self._run_registry_loop())
                tasks.create_task(self._run_execution_loop())
                tasks.create_task(self._run_reconciliation_loop())
        finally:
            self._registry_ready.clear()
            lease = self._agent_lease
            self._agent_lease = None
            if lease is not None:
                with suppress(Exception):
                    await self.store.close_cluster_agent(lease)

    async def _ensure_registered(self) -> ClusterAgentLeaseToken:
        if self._registry_ready.is_set() and self._agent_lease is not None:
            return self._agent_lease
        async with self._registration_lock:
            if self._registry_ready.is_set() and self._agent_lease is not None:
                return self._agent_lease
            await self.store.ensure_cluster_registration(
                cluster_id=self.cluster_id,
                display_name=self.cluster_display_name,
                default_namespace=self.default_namespace,
            )
            lease = await self.store.register_cluster_agent(
                cluster_id=self.cluster_id,
                instance_id=self.instance_id,
                session_id=self.session_id,
                capabilities=self.capabilities,
                version=self.version,
                ttl_seconds=self.registry_ttl_seconds,
            )
            self._agent_lease = lease
            self._registry_ready.set()
            self._record_registry_success()
            return lease

    async def _refresh_registration_once(self) -> ClusterAgentLeaseToken:
        lease = self._agent_lease if self._registry_ready.is_set() else None
        if lease is None:
            return await self._ensure_registered()
        try:
            refreshed = await self.store.heartbeat_cluster_agent(
                lease,
                ttl_seconds=self.registry_ttl_seconds,
            )
        except ClusterAgentLeaseConflictError:
            self._registry_ready.clear()
            self._agent_lease = None
            self.session_id = str(uuid4())
            return await self._ensure_registered()
        except Exception:
            self._registry_ready.clear()
            self._agent_lease = None
            return await self._ensure_registered()
        self._agent_lease = refreshed
        self._registry_ready.set()
        self._record_registry_success()
        return refreshed

    async def _run_registry_loop(self) -> None:
        retry_seconds = max(
            self.poll_interval_seconds,
            min(self.registry_heartbeat_seconds, 5.0),
        )
        while True:
            try:
                lease = await self._ensure_registered()
                await asyncio.sleep(self.registry_heartbeat_seconds)
                refreshed = await self.store.heartbeat_cluster_agent(
                    lease,
                    ttl_seconds=self.registry_ttl_seconds,
                )
                if self._agent_lease == lease:
                    self._agent_lease = refreshed
                    self._registry_ready.set()
                    self._record_registry_success()
            except asyncio.CancelledError:
                raise
            except ClusterAgentLeaseConflictError:
                self._registry_ready.clear()
                self._agent_lease = None
                self.session_id = str(uuid4())
                await asyncio.sleep(retry_seconds)
            except Exception:
                self._registry_ready.clear()
                self._agent_lease = None
                await asyncio.sleep(retry_seconds)

    def _record_registry_success(self) -> None:
        if self.health_callback is not None:
            self.health_callback()

    async def _ready_agent_lease(self) -> ClusterAgentLeaseToken:
        while True:
            await self._registry_ready.wait()
            lease = self._agent_lease
            if lease is not None:
                return lease
            self._registry_ready.clear()

    async def _run_execution_loop(self) -> None:
        while True:
            try:
                agent_lease = await self._ready_agent_lease()
                worked = await self._execute_once(agent_lease)
            except asyncio.CancelledError:
                raise
            except Exception:
                worked = False
            if not worked:
                await asyncio.sleep(self.poll_interval_seconds)

    async def _run_reconciliation_loop(self) -> None:
        while True:
            try:
                agent_lease = await self._ready_agent_lease()
                worked = await self._reconcile_once(agent_lease)
            except asyncio.CancelledError:
                raise
            except Exception:
                worked = False
            if not worked:
                await asyncio.sleep(self.poll_interval_seconds)
