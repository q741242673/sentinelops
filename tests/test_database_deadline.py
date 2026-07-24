from __future__ import annotations

import pytest

from sentinelops.storage import sqlalchemy as store_module


def test_asyncpg_store_configures_pool_query_and_lock_deadlines(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_create_async_engine(url: str, **options):
        captured["url"] = url
        captured["options"] = options
        return object()

    monkeypatch.setattr(
        store_module,
        "create_async_engine",
        fake_create_async_engine,
    )

    store_module.SqlIncidentStore(
        "postgresql+asyncpg://sentinelops:secret@postgres/sentinelops",
        operation_timeout_seconds=12.5,
    )

    assert captured["options"] == {
        "pool_pre_ping": True,
        "pool_timeout": 12.5,
        "connect_args": {
            "command_timeout": 12.5,
            "server_settings": {
                "statement_timeout": "12500",
                "lock_timeout": "12500",
            },
        },
    }


def test_sqlite_store_does_not_receive_asyncpg_only_options(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_create_async_engine(url: str, **options):
        captured["url"] = url
        captured["options"] = options
        return object()

    monkeypatch.setattr(
        store_module,
        "create_async_engine",
        fake_create_async_engine,
    )

    store_module.SqlIncidentStore(
        "sqlite+aiosqlite:///sentinelops.db",
        operation_timeout_seconds=12.5,
    )

    assert captured["options"] == {"pool_pre_ping": True}


def test_database_deadline_must_be_positive() -> None:
    with pytest.raises(ValueError, match="timeout must be positive"):
        store_module.SqlIncidentStore(
            "sqlite+aiosqlite:///sentinelops.db",
            operation_timeout_seconds=0,
        )
