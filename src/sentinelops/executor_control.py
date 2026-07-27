from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Protocol, TypeVar
from urllib.parse import quote, urlsplit

import httpx
from pydantic import TypeAdapter, ValidationError

from sentinelops.domain import ToolResult
from sentinelops.storage.base import (
    ActionIntentConflictError,
    ActionReconciliationClaim,
    ClusterAgentLeaseConflictError,
    ClusterAgentLeaseToken,
    ClusterRegistration,
    ClusterRegistrationConflictError,
    ExecutorClaim,
    LeaseConflictError,
    StoredActionIntent,
)

EXECUTOR_CONTROL_PREFIX = "/internal/v1/executor"
MAX_EXECUTOR_TOKEN_BYTES = 16_384
MAX_EXECUTOR_RESPONSE_BYTES = 1_048_576


class ExecutorControlAuthenticationError(RuntimeError):
    """The Executor service identity is missing, invalid, or unauthorized."""


class ExecutorControlUnavailableError(RuntimeError):
    """The control gateway could not provide a trustworthy response."""


class ExecutorControlProtocolError(RuntimeError):
    """The control gateway response violated the Executor protocol."""


class ExecutorControlPlane(Protocol):
    async def ensure_cluster_registration(
        self,
        *,
        cluster_id: str,
        display_name: str,
        default_namespace: str,
    ) -> ClusterRegistration: ...

    async def register_cluster_agent(
        self,
        *,
        cluster_id: str,
        instance_id: str,
        session_id: str,
        capabilities: tuple[str, ...],
        version: str,
        ttl_seconds: float,
    ) -> ClusterAgentLeaseToken: ...

    async def heartbeat_cluster_agent(
        self,
        token: ClusterAgentLeaseToken,
        *,
        ttl_seconds: float,
    ) -> ClusterAgentLeaseToken: ...

    async def close_cluster_agent(
        self,
        token: ClusterAgentLeaseToken,
    ) -> None: ...

    async def claim_action_execution(
        self,
        *,
        agent_lease: ClusterAgentLeaseToken,
        owner_id: str,
        attempt_id: str,
        ttl_seconds: float,
    ) -> ExecutorClaim | None: ...

    async def heartbeat_action_claim(
        self,
        claim: ExecutorClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
        ttl_seconds: float,
    ) -> ExecutorClaim: ...

    async def mark_action_dispatched(
        self,
        claim: ExecutorClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
    ) -> StoredActionIntent: ...

    async def complete_action(
        self,
        *,
        claim: ExecutorClaim,
        agent_lease: ClusterAgentLeaseToken,
        result: ToolResult,
    ) -> StoredActionIntent: ...

    async def mark_action_unknown(
        self,
        *,
        claim: ExecutorClaim,
        agent_lease: ClusterAgentLeaseToken,
        reason: str,
    ) -> StoredActionIntent: ...

    async def claim_action_reconciliation(
        self,
        *,
        agent_lease: ClusterAgentLeaseToken,
        owner_id: str,
        ttl_seconds: float,
    ) -> ActionReconciliationClaim | None: ...

    async def complete_action_reconciliation(
        self,
        claim: ActionReconciliationClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
        result: ToolResult,
    ) -> StoredActionIntent: ...

    async def retry_action_reconciliation(
        self,
        claim: ActionReconciliationClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
        error: str,
        retry_after_seconds: float,
    ) -> StoredActionIntent: ...

    async def dead_letter_action_reconciliation(
        self,
        claim: ActionReconciliationClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
        error: str,
    ) -> StoredActionIntent: ...


_T = TypeVar("_T")
_CLUSTER_REGISTRATION = TypeAdapter(ClusterRegistration)
_CLUSTER_AGENT_LEASE = TypeAdapter(ClusterAgentLeaseToken)
_EXECUTOR_CLAIM = TypeAdapter(ExecutorClaim)
_RECONCILIATION_CLAIM = TypeAdapter(ActionReconciliationClaim)
_STORED_ACTION = TypeAdapter(StoredActionIntent)
_TOOL_RESULT = TypeAdapter(ToolResult)

_CONFLICT_ERRORS: dict[str, type[RuntimeError]] = {
    "cluster_registration_conflict": ClusterRegistrationConflictError,
    "cluster_agent_lease_conflict": ClusterAgentLeaseConflictError,
    "lease_conflict": LeaseConflictError,
    "action_intent_conflict": ActionIntentConflictError,
}


class HttpExecutorControlPlane:
    """Fail-closed HTTP adapter for the narrow Executor control-plane contract."""

    def __init__(
        self,
        base_url: str,
        *,
        cluster_id: str,
        token_file: str | Path,
        deadline_seconds: float = 10,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed_base_url = urlsplit(base_url)
        if (
            parsed_base_url.scheme.casefold() not in {"http", "https"}
            or not parsed_base_url.hostname
            or parsed_base_url.username is not None
            or parsed_base_url.password is not None
            or parsed_base_url.query
            or parsed_base_url.fragment
            or parsed_base_url.path not in {"", "/"}
        ):
            raise ValueError("Executor control base_url must be a fixed HTTP(S) origin")
        normalized_cluster_id = cluster_id.strip()
        if not normalized_cluster_id:
            raise ValueError("Executor control cluster_id must not be empty")
        if deadline_seconds <= 0:
            raise ValueError("Executor control deadline must be positive")
        self.cluster_id = normalized_cluster_id
        self.token_file = Path(token_file)
        self.deadline_seconds = deadline_seconds
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(deadline_seconds),
            transport=transport,
        )

    async def __aenter__(self) -> HttpExecutorControlPlane:
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def ensure_cluster_registration(
        self,
        *,
        cluster_id: str,
        display_name: str,
        default_namespace: str,
    ) -> ClusterRegistration:
        self._require_request_cluster(cluster_id)
        response = await self._request(
            "PUT",
            f"/clusters/{_url_part(cluster_id)}",
            json_body={
                "cluster_id": cluster_id,
                "display_name": display_name,
                "default_namespace": default_namespace,
            },
        )
        registration = self._decode(response, _CLUSTER_REGISTRATION)
        self._require_response_cluster(registration.cluster_id)
        return registration

    async def register_cluster_agent(
        self,
        *,
        cluster_id: str,
        instance_id: str,
        session_id: str,
        capabilities: tuple[str, ...],
        version: str,
        ttl_seconds: float,
    ) -> ClusterAgentLeaseToken:
        self._require_request_cluster(cluster_id)
        response = await self._request(
            "POST",
            "/sessions",
            json_body={
                "cluster_id": cluster_id,
                "instance_id": instance_id,
                "session_id": session_id,
                "capabilities": list(capabilities),
                "version": version,
                "ttl_seconds": ttl_seconds,
            },
        )
        lease = self._decode(response, _CLUSTER_AGENT_LEASE)
        self._require_response_cluster(lease.cluster_id)
        return lease

    async def heartbeat_cluster_agent(
        self,
        token: ClusterAgentLeaseToken,
        *,
        ttl_seconds: float,
    ) -> ClusterAgentLeaseToken:
        self._require_response_cluster(token.cluster_id)
        response = await self._request(
            "PUT",
            f"/sessions/{_url_part(token.session_id)}/heartbeat",
            json_body={
                "token": _dump_json_value(_CLUSTER_AGENT_LEASE, token),
                "ttl_seconds": ttl_seconds,
            },
        )
        lease = self._decode(response, _CLUSTER_AGENT_LEASE)
        self._require_response_cluster(lease.cluster_id)
        return lease

    async def close_cluster_agent(
        self,
        token: ClusterAgentLeaseToken,
    ) -> None:
        self._require_response_cluster(token.cluster_id)
        await self._request(
            "DELETE",
            f"/sessions/{_url_part(token.session_id)}",
            json_body={"token": _dump_json_value(_CLUSTER_AGENT_LEASE, token)},
            expected_empty=True,
        )

    async def claim_action_execution(
        self,
        *,
        agent_lease: ClusterAgentLeaseToken,
        owner_id: str,
        attempt_id: str,
        ttl_seconds: float,
    ) -> ExecutorClaim | None:
        self._require_response_cluster(agent_lease.cluster_id)
        response = await self._request(
            "POST",
            "/action-claims",
            json_body={
                "agent_lease": _dump_json_value(
                    _CLUSTER_AGENT_LEASE,
                    agent_lease,
                ),
                "owner_id": owner_id,
                "attempt_id": attempt_id,
                "ttl_seconds": ttl_seconds,
            },
            allow_no_content=True,
        )
        if response is None:
            return None
        claim = self._decode(response, _EXECUTOR_CLAIM)
        self._require_response_cluster(claim.cluster_id)
        return claim

    async def heartbeat_action_claim(
        self,
        claim: ExecutorClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
        ttl_seconds: float,
    ) -> ExecutorClaim:
        self._require_response_cluster(claim.cluster_id)
        self._require_response_cluster(agent_lease.cluster_id)
        response = await self._request(
            "PUT",
            f"/action-claims/{_url_part(claim.attempt_id)}/heartbeat",
            json_body={
                "claim": _dump_json_value(_EXECUTOR_CLAIM, claim),
                "agent_lease": _dump_json_value(
                    _CLUSTER_AGENT_LEASE,
                    agent_lease,
                ),
                "ttl_seconds": ttl_seconds,
            },
        )
        refreshed = self._decode(response, _EXECUTOR_CLAIM)
        self._require_response_cluster(refreshed.cluster_id)
        return refreshed

    async def mark_action_dispatched(
        self,
        claim: ExecutorClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
    ) -> StoredActionIntent:
        self._require_response_cluster(claim.cluster_id)
        self._require_response_cluster(agent_lease.cluster_id)
        response = await self._request(
            "POST",
            f"/action-claims/{_url_part(claim.attempt_id)}/dispatch",
            json_body={
                "claim": _dump_json_value(_EXECUTOR_CLAIM, claim),
                "agent_lease": _dump_json_value(
                    _CLUSTER_AGENT_LEASE,
                    agent_lease,
                ),
            },
        )
        return self._decode_action(response)

    async def complete_action(
        self,
        *,
        claim: ExecutorClaim,
        agent_lease: ClusterAgentLeaseToken,
        result: ToolResult,
    ) -> StoredActionIntent:
        self._require_response_cluster(claim.cluster_id)
        self._require_response_cluster(agent_lease.cluster_id)
        response = await self._request(
            "PUT",
            f"/action-claims/{_url_part(claim.attempt_id)}/result",
            json_body={
                "claim": _dump_json_value(_EXECUTOR_CLAIM, claim),
                "agent_lease": _dump_json_value(
                    _CLUSTER_AGENT_LEASE,
                    agent_lease,
                ),
                "result": _dump_json_value(_TOOL_RESULT, result),
            },
        )
        return self._decode_action(response)

    async def mark_action_unknown(
        self,
        *,
        claim: ExecutorClaim,
        agent_lease: ClusterAgentLeaseToken,
        reason: str,
    ) -> StoredActionIntent:
        self._require_response_cluster(claim.cluster_id)
        self._require_response_cluster(agent_lease.cluster_id)
        response = await self._request(
            "PUT",
            f"/action-claims/{_url_part(claim.attempt_id)}/unknown",
            json_body={
                "claim": _dump_json_value(_EXECUTOR_CLAIM, claim),
                "agent_lease": _dump_json_value(
                    _CLUSTER_AGENT_LEASE,
                    agent_lease,
                ),
                "reason": reason,
            },
        )
        return self._decode_action(response)

    async def claim_action_reconciliation(
        self,
        *,
        agent_lease: ClusterAgentLeaseToken,
        owner_id: str,
        ttl_seconds: float,
    ) -> ActionReconciliationClaim | None:
        self._require_response_cluster(agent_lease.cluster_id)
        response = await self._request(
            "POST",
            "/reconciliation-claims",
            json_body={
                "agent_lease": _dump_json_value(
                    _CLUSTER_AGENT_LEASE,
                    agent_lease,
                ),
                "owner_id": owner_id,
                "ttl_seconds": ttl_seconds,
            },
            allow_no_content=True,
        )
        if response is None:
            return None
        claim = self._decode(response, _RECONCILIATION_CLAIM)
        self._require_reconciliation_cluster(claim)
        return claim

    async def complete_action_reconciliation(
        self,
        claim: ActionReconciliationClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
        result: ToolResult,
    ) -> StoredActionIntent:
        self._require_reconciliation_cluster(claim)
        self._require_response_cluster(agent_lease.cluster_id)
        response = await self._request(
            "PUT",
            f"/reconciliation-claims/{_url_part(claim.attempt_id)}/complete",
            json_body={
                "claim": _dump_json_value(_RECONCILIATION_CLAIM, claim),
                "agent_lease": _dump_json_value(
                    _CLUSTER_AGENT_LEASE,
                    agent_lease,
                ),
                "result": _dump_json_value(_TOOL_RESULT, result),
            },
        )
        return self._decode_action(response)

    async def retry_action_reconciliation(
        self,
        claim: ActionReconciliationClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
        error: str,
        retry_after_seconds: float,
    ) -> StoredActionIntent:
        self._require_reconciliation_cluster(claim)
        self._require_response_cluster(agent_lease.cluster_id)
        response = await self._request(
            "PUT",
            f"/reconciliation-claims/{_url_part(claim.attempt_id)}/retry",
            json_body={
                "claim": _dump_json_value(_RECONCILIATION_CLAIM, claim),
                "agent_lease": _dump_json_value(
                    _CLUSTER_AGENT_LEASE,
                    agent_lease,
                ),
                "error": error,
                "retry_after_seconds": retry_after_seconds,
            },
        )
        return self._decode_action(response)

    async def dead_letter_action_reconciliation(
        self,
        claim: ActionReconciliationClaim,
        *,
        agent_lease: ClusterAgentLeaseToken,
        error: str,
    ) -> StoredActionIntent:
        self._require_reconciliation_cluster(claim)
        self._require_response_cluster(agent_lease.cluster_id)
        response = await self._request(
            "PUT",
            f"/reconciliation-claims/{_url_part(claim.attempt_id)}/dead-letter",
            json_body={
                "claim": _dump_json_value(_RECONCILIATION_CLAIM, claim),
                "agent_lease": _dump_json_value(
                    _CLUSTER_AGENT_LEASE,
                    agent_lease,
                ),
                "error": error,
            },
        )
        return self._decode_action(response)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, object],
        allow_no_content: bool = False,
        expected_empty: bool = False,
    ) -> httpx.Response | None:
        token = self._read_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "X-SentinelOps-Cluster-ID": self.cluster_id,
            "Accept": "application/json",
        }
        try:
            async with asyncio.timeout(self.deadline_seconds):
                response = await self._client.request(
                    method,
                    f"{EXECUTOR_CONTROL_PREFIX}{path}",
                    headers=headers,
                    json=json_body,
                )
        except (TimeoutError, httpx.HTTPError, OSError) as exc:
            raise ExecutorControlUnavailableError(
                "Executor control gateway is unavailable"
            ) from exc

        self._validate_response_bounds(response)
        if response.status_code in {401, 403}:
            raise ExecutorControlAuthenticationError(
                self._error_message(response, "Executor service identity was rejected")
            )
        if response.status_code in {409, 410}:
            self._raise_conflict(response)
        if response.status_code >= 500:
            raise ExecutorControlUnavailableError(
                self._error_message(response, "Executor control gateway failed")
            )
        if response.is_redirect:
            raise ExecutorControlProtocolError("Executor control gateway redirects are forbidden")
        if response.status_code == 204:
            if allow_no_content or expected_empty:
                return None
            raise ExecutorControlProtocolError(
                "Executor control gateway returned unexpected empty response"
            )
        if not 200 <= response.status_code < 300:
            raise ExecutorControlProtocolError(
                self._error_message(
                    response,
                    f"Unexpected Executor control status {response.status_code}",
                )
            )
        if expected_empty:
            return None
        content_type = response.headers.get("content-type", "")
        media_type = content_type.split(";", 1)[0].strip().casefold()
        if media_type != "application/json" and not media_type.endswith("+json"):
            raise ExecutorControlProtocolError(
                "Executor control gateway returned a non-JSON response"
            )
        return response

    def _read_token(self) -> str:
        try:
            payload = self.token_file.read_bytes()
        except OSError as exc:
            raise ExecutorControlAuthenticationError(
                "Executor service token is unavailable"
            ) from exc
        if len(payload) > MAX_EXECUTOR_TOKEN_BYTES:
            raise ExecutorControlAuthenticationError(
                "Executor service token exceeds the size limit"
            )
        try:
            token = payload.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise ExecutorControlAuthenticationError(
                "Executor service token is not ASCII"
            ) from exc
        if not token:
            raise ExecutorControlAuthenticationError("Executor service token is empty")
        if any(character.isspace() for character in token):
            raise ExecutorControlAuthenticationError(
                "Executor service token contains whitespace"
            )
        return token

    @staticmethod
    def _validate_response_bounds(response: httpx.Response) -> None:
        content_encoding = response.headers.get("content-encoding", "identity")
        if content_encoding.strip().casefold() not in {"", "identity"}:
            raise ExecutorControlProtocolError(
                "Compressed Executor control responses are forbidden"
            )
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise ExecutorControlProtocolError(
                    "Executor control response has an invalid Content-Length"
                ) from exc
            if declared_length < 0 or declared_length > MAX_EXECUTOR_RESPONSE_BYTES:
                raise ExecutorControlProtocolError(
                    "Executor control response exceeds the size limit"
                )
        if len(response.content) > MAX_EXECUTOR_RESPONSE_BYTES:
            raise ExecutorControlProtocolError(
                "Executor control response exceeds the size limit"
            )

    def _decode(
        self,
        response: httpx.Response,
        adapter: TypeAdapter[_T],
    ) -> _T:
        try:
            return adapter.validate_json(response.content, strict=True)
        except ValidationError as exc:
            raise ExecutorControlProtocolError(
                "Executor control gateway returned invalid JSON contract"
            ) from exc

    def _decode_action(self, response: httpx.Response) -> StoredActionIntent:
        action = self._decode(response, _STORED_ACTION)
        self._require_response_cluster(action.cluster_id)
        precondition_cluster = action.precondition.get("cluster_id")
        if precondition_cluster is not None and precondition_cluster != self.cluster_id:
            raise ExecutorControlProtocolError(
                "Executor control action precondition crossed cluster boundary"
            )
        return action

    def _require_reconciliation_cluster(
        self,
        claim: ActionReconciliationClaim,
    ) -> None:
        self._require_response_cluster(claim.cluster_id)
        self._require_response_cluster(claim.intent.cluster_id)
        precondition_cluster = claim.intent.precondition.get("cluster_id")
        if precondition_cluster is not None and precondition_cluster != self.cluster_id:
            raise ExecutorControlProtocolError(
                "Executor reconciliation precondition crossed cluster boundary"
            )

    def _require_request_cluster(self, cluster_id: str) -> None:
        if cluster_id != self.cluster_id:
            raise ExecutorControlAuthenticationError(
                "Executor request cluster does not match its fixed identity"
            )

    def _require_response_cluster(self, cluster_id: str) -> None:
        if cluster_id != self.cluster_id:
            raise ExecutorControlProtocolError(
                "Executor control gateway returned a cross-cluster response"
            )

    @staticmethod
    def _error_message(response: httpx.Response, fallback: str) -> str:
        try:
            payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return fallback
        if not isinstance(payload, dict):
            return fallback
        detail = payload.get("detail")
        if isinstance(detail, str) and detail:
            return detail
        error = payload.get("error")
        if isinstance(error, str) and error:
            return error
        return fallback

    @staticmethod
    def _raise_conflict(response: httpx.Response) -> None:
        try:
            payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ExecutorControlProtocolError(
                "Executor control conflict response is not JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise ExecutorControlProtocolError(
                "Executor control conflict response is not an object"
            )
        error_code = payload.get("error_code")
        error_type = _CONFLICT_ERRORS.get(error_code) if isinstance(error_code, str) else None
        if error_type is None:
            raise ExecutorControlProtocolError(
                "Executor control conflict response has an unknown error_code"
            )
        message = HttpExecutorControlPlane._error_message(
            response,
            str(error_code),
        )
        raise error_type(message)


def _dump_json_value(adapter: TypeAdapter[_T], value: _T) -> object:
    try:
        validated = adapter.validate_python(value, strict=True)
        return json.loads(adapter.dump_json(validated, warnings="error"))
    except (ValidationError, ValueError, TypeError) as exc:
        raise ExecutorControlProtocolError(
            "Executor attempted to send an invalid JSON contract"
        ) from exc


def _url_part(value: str) -> str:
    return quote(value, safe="")
