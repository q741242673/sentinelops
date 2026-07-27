from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI

from sentinelops.control_gateway import build_executor_control_router
from sentinelops.domain import RemediationAction, RiskLevel, ToolResult
from sentinelops.executor_control import (
    ExecutorControlAuthenticationError,
    HttpExecutorControlPlane,
)
from sentinelops.storage.base import (
    ClusterAgentLeaseToken,
    ClusterRegistration,
    ExecutorClaim,
    StoredActionIntent,
)
from sentinelops.workload_identity import WorkloadIdentity, WorkloadTrust

CLUSTER_ID = "cluster-a"
POD_UID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SESSION_ID = "session-a"


class _Authenticator:
    def __init__(self) -> None:
        self.trusts = {
            CLUSTER_ID: WorkloadTrust(
                cluster_id=CLUSTER_ID,
                display_name="Cluster A",
                default_namespace="sentinelops-workloads",
                issuer="https://issuer.example.test",
                audience="sentinelops-control-gateway",
                jwks_url="https://issuer.example.test/jwks",
                namespace="sentinelops-system",
                service_account="sentinelops-executor",
                service_account_uid="service-account-uid",
                allowed_capabilities=(
                    "agent.register",
                    "agent.heartbeat",
                    "action.execute",
                    "action.reconcile",
                    "backend.controller",
                ),
            )
        }

    async def authenticate(
        self,
        _request,
        *,
        required_capability: str,
        expected_pod_uid: str | None = None,
    ) -> WorkloadIdentity:
        identity = WorkloadIdentity(
            cluster_id=CLUSTER_ID,
            subject_hash="a" * 64,
            pod_uid=POD_UID,
            allowed_capabilities=frozenset(
                self.trusts[CLUSTER_ID].allowed_capabilities
            ),
        )
        if required_capability not in identity.allowed_capabilities:
            raise AssertionError("test requested an unauthorized capability")
        if expected_pod_uid is not None and expected_pod_uid != POD_UID:
            from fastapi import HTTPException

            raise HTTPException(status_code=403, detail="Pod UID mismatch")
        return identity


class _Store:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.intent: StoredActionIntent | None = None

    async def ensure_cluster_registration(
        self,
        *,
        cluster_id: str,
        display_name: str,
        default_namespace: str,
    ) -> ClusterRegistration:
        self.calls.append("ensure")
        now = datetime.now(UTC)
        return ClusterRegistration(
            cluster_id=cluster_id,
            display_name=display_name,
            default_namespace=default_namespace,
            routing_generation=1,
            lifecycle="active",
            metadata_state="configured",
            created_at=now,
            updated_at=now,
        )

    async def register_cluster_agent(self, **values) -> ClusterAgentLeaseToken:
        self.calls.append("register")
        now = datetime.now(UTC)
        return ClusterAgentLeaseToken(
            cluster_id=values["cluster_id"],
            instance_id=values["instance_id"],
            session_id=values["session_id"],
            generation=1,
            routing_generation=1,
            capabilities=values["capabilities"],
            version=values["version"],
            registered_at=now,
            last_seen_at=now,
            lease_until=now + timedelta(seconds=values["ttl_seconds"]),
        )

    async def claim_action_execution(self, **values) -> ExecutorClaim:
        self.calls.append("claim")
        lease = values["agent_lease"]
        return ExecutorClaim(
            idempotency_key="a" * 64,
            incident_id="incident-a",
            cluster_id=CLUSTER_ID,
            cluster_generation=1,
            owner_id=values["owner_id"],
            generation=1,
            attempt_id=values["attempt_id"],
            session_id=lease.session_id,
            session_generation=lease.generation,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=values["ttl_seconds"]),
        )

    async def mark_action_dispatched(
        self,
        claim: ExecutorClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
    ) -> StoredActionIntent:
        self.calls.append("dispatch")
        assert claim.session_id == agent_lease.session_id
        self.intent = StoredActionIntent(
            idempotency_key=claim.idempotency_key,
            incident_id=claim.incident_id,
            cluster_id=claim.cluster_id,
            cluster_generation=claim.cluster_generation,
            lease_generation=1,
            approval_id=None,
            approval_version=None,
            action=RemediationAction(
                tool_name="restart_deployment",
                arguments={"name": "order-service"},
                rationale="recover",
                expected_outcome="healthy",
                risk=RiskLevel.LOW,
            ),
            precondition={"cluster_id": CLUSTER_ID},
            status="dispatched",
            result=None,
            error=None,
            executor_id=claim.owner_id,
            executor_generation=claim.generation,
            executor_lease_until=claim.expires_at,
            attempt_id=claim.attempt_id,
            executor_session_id=claim.session_id,
            executor_session_generation=claim.session_generation,
        )
        return self.intent

    async def complete_action(
        self,
        *,
        claim: ExecutorClaim,
        agent_lease: ClusterAgentLeaseToken,
        result: ToolResult,
    ) -> StoredActionIntent:
        self.calls.append("complete")
        assert claim.session_id == agent_lease.session_id
        assert self.intent is not None
        self.intent = replace(
            self.intent,
            status="succeeded" if result.success else "failed",
            result=result,
            error=result.error,
        )
        return self.intent


def _app(store: _Store, authenticator: _Authenticator) -> FastAPI:
    app = FastAPI()
    app.include_router(
        build_executor_control_router(
            store_provider=lambda: store,
            authenticator_provider=lambda: authenticator,
        )
    )
    return app


@pytest.mark.asyncio
async def test_http_executor_uses_authenticated_gateway_contract(tmp_path) -> None:
    store = _Store()
    authenticator = _Authenticator()
    token = tmp_path / "token"
    token.write_text("projected-token", encoding="utf-8")
    control = HttpExecutorControlPlane(
        "http://control.test",
        cluster_id=CLUSTER_ID,
        token_file=token,
        transport=httpx.ASGITransport(app=_app(store, authenticator)),
    )
    try:
        registration = await control.ensure_cluster_registration(
            cluster_id=CLUSTER_ID,
            display_name="Cluster A",
            default_namespace="sentinelops-workloads",
        )
        lease = await control.register_cluster_agent(
            cluster_id=CLUSTER_ID,
            instance_id=POD_UID,
            session_id=SESSION_ID,
            capabilities=(
                "action.execute",
                "action.reconcile",
                "backend.controller",
            ),
            version="test",
            ttl_seconds=60,
        )
        claim = await control.claim_action_execution(
            agent_lease=lease,
            owner_id=POD_UID,
            attempt_id="attempt-a",
            ttl_seconds=60,
        )
        assert claim is not None
        intent = await control.mark_action_dispatched(
            claim,
            agent_lease=lease,
        )
        completed = await control.complete_action(
            claim=claim,
            agent_lease=lease,
            result=ToolResult(
                tool_name=intent.action.tool_name,
                success=True,
                content={"gateway_contract": True},
            ),
        )
    finally:
        await control.aclose()

    assert registration.cluster_id == CLUSTER_ID
    assert lease.instance_id == POD_UID
    assert intent.status == "dispatched"
    assert completed.status == "succeeded"
    assert store.calls == ["ensure", "register", "claim", "dispatch", "complete"]


@pytest.mark.asyncio
async def test_gateway_rejects_spoofed_pod_owner_before_store_claim(tmp_path) -> None:
    store = _Store()
    authenticator = _Authenticator()
    token = tmp_path / "token"
    token.write_text("projected-token", encoding="utf-8")
    control = HttpExecutorControlPlane(
        "http://control.test",
        cluster_id=CLUSTER_ID,
        token_file=token,
        transport=httpx.ASGITransport(app=_app(store, authenticator)),
    )
    try:
        lease = await control.register_cluster_agent(
            cluster_id=CLUSTER_ID,
            instance_id=POD_UID,
            session_id=SESSION_ID,
            capabilities=("action.execute",),
            version="test",
            ttl_seconds=60,
        )
        with pytest.raises(ExecutorControlAuthenticationError):
            await control.claim_action_execution(
                agent_lease=lease,
                owner_id="another-pod",
                attempt_id="spoofed-attempt",
                ttl_seconds=60,
            )
    finally:
        await control.aclose()

    assert store.calls == ["register"]


@pytest.mark.asyncio
async def test_gateway_rejects_executor_cluster_metadata_poisoning() -> None:
    store = _Store()
    authenticator = _Authenticator()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(store, authenticator)),
        base_url="http://control.test",
    ) as client:
        response = await client.put(
            f"/internal/v1/executor/clusters/{CLUSTER_ID}",
            headers={
                "Authorization": "Bearer projected-token",
                "X-SentinelOps-Cluster-ID": CLUSTER_ID,
            },
            json={
                "cluster_id": CLUSTER_ID,
                "display_name": "Poisoned cluster",
                "default_namespace": "sentinelops-workloads",
            },
        )

    assert response.status_code == 403
    assert store.calls == []
