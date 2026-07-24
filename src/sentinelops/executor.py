from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from uuid import uuid4

from sentinelops.agent.execution import (
    ActionExecutionRejected,
    ActionExecutor,
    ActionOutcomeUnknown,
)
from sentinelops.domain import RemediationAction, ToolResult
from sentinelops.storage.base import (
    ActionIntentConflictError,
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
    """Independent worker that is the sole owner of Kubernetes write credentials."""

    def __init__(
        self,
        store: IncidentStore,
        tools: ToolRegistry,
        *,
        owner_id: str,
        claim_ttl_seconds: float = 60,
        poll_interval_seconds: float = 0.5,
        health_callback: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.tools = tools
        self.owner_id = owner_id
        self.claim_ttl_seconds = claim_ttl_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self.health_callback = health_callback

    async def run_once(self) -> bool:
        claim = await self.store.claim_action_execution(
            owner_id=self.owner_id,
            attempt_id=str(uuid4()),
            ttl_seconds=self.claim_ttl_seconds,
        )
        if claim is None:
            return False

        async def heartbeat() -> None:
            while True:
                await asyncio.sleep(max(0.1, self.claim_ttl_seconds / 3))
                await self.store.heartbeat_action_claim(
                    claim,
                    ttl_seconds=self.claim_ttl_seconds,
                )

        heartbeat_task = asyncio.create_task(heartbeat())
        try:
            dispatched = await self.store.mark_action_dispatched(claim)
            result = await self.tools.call_guarded(
                dispatched.action.tool_name,
                dispatched.action.arguments,
                dispatched.precondition,
            )
        except BaseException as exc:
            with suppress(Exception):
                await self.store.mark_action_unknown(
                    claim=claim,
                    reason=f"Executor 调用没有返回可信结果：{exc}",
                )
            raise
        finally:
            heartbeat_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await heartbeat_task
        await self.store.complete_action(claim=claim, result=result)
        return True

    async def run_forever(self) -> None:
        while True:
            if self.health_callback is not None:
                self.health_callback()
            try:
                worked = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                worked = False
            if self.health_callback is not None:
                self.health_callback()
            if not worked:
                await asyncio.sleep(self.poll_interval_seconds)
