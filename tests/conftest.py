from __future__ import annotations

from sentinelops.config import Settings

# Developer credentials in the project .env must never leak into deterministic tests.
Settings.model_config["env_file"] = None
