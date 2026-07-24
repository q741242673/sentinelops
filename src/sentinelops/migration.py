from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from sentinelops.storage.base import IncidentStore

HEAD_REVISIONS = ("0008_anchor_unlock_workflow",)


class SchemaRevisionError(RuntimeError):
    """The database schema does not match the application contract."""


def alembic_config(database_url: str) -> Config:
    config = Config()
    config.set_main_option(
        "script_location",
        str(Path(__file__).resolve().parent / "migrations"),
    )
    # Avoid ConfigParser interpolation of credentials containing percent signs.
    config.attributes["database_url"] = database_url
    return config


def upgrade_database(database_url: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(database_url), revision)


async def require_current_schema(store: IncidentStore) -> str:
    current = await store.schema_revisions()
    if current != HEAD_REVISIONS:
        current_label = ", ".join(current) if current else "未初始化"
        expected_label = ", ".join(HEAD_REVISIONS)
        raise SchemaRevisionError(
            "数据库版本不匹配："
            f"当前 {current_label}，程序需要 {expected_label}。"
            "请先运行 sentinelops db-init。"
        )
    return current[0]
