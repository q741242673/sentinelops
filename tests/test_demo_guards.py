from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

import sentinelops.demo as demo_module
from sentinelops.config import Settings

DemoWrite = Callable[[Settings], Awaitable[dict[str, Any]]]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    [
        demo_module.inject_demo_fault,
        demo_module.inject_auto_demo_fault,
        demo_module.reset_demo_environment,
    ],
)
async def test_demo_write_helpers_fail_closed_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
    operation: DemoWrite,
) -> None:
    def unexpected_backend(*args: object, **kwargs: object) -> None:
        raise AssertionError("Kubernetes backend must not be constructed")

    def unexpected_client(*args: object, **kwargs: object) -> None:
        raise AssertionError("HTTP client must not be constructed")

    monkeypatch.setattr(demo_module, "KubernetesBackend", unexpected_backend)
    monkeypatch.setattr(demo_module.httpx, "AsyncClient", unexpected_client)
    settings = Settings(
        tool_backend="kubernetes",
        demo_enabled=False,
        demo_inventory_url="http://inventory.test",
    )

    with pytest.raises(RuntimeError, match="disabled"):
        await operation(settings)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    [
        demo_module.inject_demo_fault,
        demo_module.inject_auto_demo_fault,
        demo_module.reset_demo_environment,
    ],
)
async def test_demo_write_helpers_are_forbidden_in_production(
    monkeypatch: pytest.MonkeyPatch,
    operation: DemoWrite,
) -> None:
    def unexpected_backend(*args: object, **kwargs: object) -> None:
        raise AssertionError("Kubernetes backend must not be constructed")

    def unexpected_client(*args: object, **kwargs: object) -> None:
        raise AssertionError("HTTP client must not be constructed")

    monkeypatch.setattr(demo_module, "KubernetesBackend", unexpected_backend)
    monkeypatch.setattr(demo_module.httpx, "AsyncClient", unexpected_client)
    settings = Settings(
        environment="production",
        tool_backend="kubernetes",
        demo_enabled=True,
        demo_inventory_url="http://inventory.test",
    )

    with pytest.raises(RuntimeError, match="forbidden in production"):
        await operation(settings)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    [
        demo_module.inject_demo_fault,
        demo_module.inject_auto_demo_fault,
        demo_module.reset_demo_environment,
    ],
)
async def test_kubernetes_demo_writes_require_exact_demo_namespace(
    monkeypatch: pytest.MonkeyPatch,
    operation: DemoWrite,
) -> None:
    def unexpected_backend(*args: object, **kwargs: object) -> None:
        raise AssertionError("Kubernetes backend must not be constructed")

    def unexpected_client(*args: object, **kwargs: object) -> None:
        raise AssertionError("HTTP client must not be constructed")

    monkeypatch.setattr(demo_module, "KubernetesBackend", unexpected_backend)
    monkeypatch.setattr(demo_module.httpx, "AsyncClient", unexpected_client)
    settings = Settings(
        tool_backend="kubernetes",
        demo_enabled=True,
        kubernetes_namespace="payments-prod",
        demo_namespace="sentinelops-demo",
        demo_inventory_url="http://inventory.test",
    )

    with pytest.raises(RuntimeError, match="exactly match"):
        await operation(settings)


@pytest.mark.asyncio
async def test_enabled_non_production_simulator_demo_still_runs() -> None:
    settings = Settings(
        environment="development",
        tool_backend="simulator",
        demo_enabled=True,
    )

    result = await demo_module.inject_demo_fault(settings)

    assert result["fault_active"] is True
