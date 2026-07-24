from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from sentinelops.cli import (
    _touch_executor_health_file,
    check_executor_health,
)
from sentinelops.config import Settings


def test_secret_files_are_read_without_trailing_newlines(tmp_path: Path) -> None:
    database_file = tmp_path / "database-url"
    database_file.write_text("sqlite+aiosqlite:///state.db\n")
    model_file = tmp_path / "model-key"
    model_file.write_text("model-secret\r\n")
    webhook_file = tmp_path / "webhook-token"
    webhook_file.write_text("webhook-secret\n")
    audit_file = tmp_path / "audit-key"
    audit_file.write_text("audit-secret\n")
    anchor_file = tmp_path / "anchor-token"
    anchor_file.write_text("anchor-secret\n")

    settings = Settings(
        database_url_file=str(database_file),
        model_api_key_file=str(model_file),
        alertmanager_webhook_bearer_token_file=str(webhook_file),
        audit_hmac_key_file=str(audit_file),
        audit_anchor_bearer_token_file=str(anchor_file),
    )

    assert settings.resolved_database_url() == "sqlite+aiosqlite:///state.db"
    assert settings.resolved_model_api_key() == "model-secret"
    assert settings.resolved_webhook_bearer_token() == "webhook-secret"
    assert settings.resolved_audit_hmac_key() == "audit-secret"
    assert settings.resolved_audit_anchor_bearer_token() == "anchor-secret"


def test_secret_value_and_file_cannot_both_be_configured(tmp_path: Path) -> None:
    secret_file = tmp_path / "database-url"
    secret_file.write_text("sqlite+aiosqlite:///state.db")
    settings = Settings(
        database_url="sqlite+aiosqlite:///other.db",
        database_url_file=str(secret_file),
    )

    with pytest.raises(ValueError, match="不能同时"):
        settings.resolved_database_url()


def test_secret_file_errors_are_bounded_and_do_not_include_contents(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"s" * 65_537)
    settings = Settings(model_api_key_file=str(oversized))

    with pytest.raises(ValueError, match="超过 64 KiB") as exc_info:
        settings.resolved_model_api_key()

    assert "ssss" not in str(exc_info.value)


def test_executor_health_file_detects_fresh_missing_and_stale(
    tmp_path: Path,
) -> None:
    health_file = tmp_path / "health" / "heartbeat"
    _touch_executor_health_file(str(health_file))
    check_executor_health(str(health_file), max_age_seconds=10)

    old_timestamp = time.time() - 30
    os.utime(health_file, (old_timestamp, old_timestamp))
    with pytest.raises(SystemExit, match="stale"):
        check_executor_health(str(health_file), max_age_seconds=10)

    with pytest.raises(SystemExit, match="missing"):
        check_executor_health(str(tmp_path / "missing"), max_age_seconds=10)
