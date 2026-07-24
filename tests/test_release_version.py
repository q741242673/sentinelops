from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/release_version.py"
SPEC = importlib.util.spec_from_file_location(
    "sentinelops_release_version_script",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _fixture(root: Path, *, runtime_version: str = "0.1.0rc1") -> None:
    (root / "src/sentinelops").mkdir(parents=True)
    (root / "deploy/production/base").mkdir(parents=True)
    (root / "web").mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "sentinelops"\nversion = "0.1.0rc1"\n',
        encoding="utf-8",
    )
    (root / "src/sentinelops/__init__.py").write_text(
        f'__version__ = "{runtime_version}"\n',
        encoding="utf-8",
    )
    (root / "web/package.json").write_text(
        json.dumps({"version": "0.1.0-rc.1"}),
        encoding="utf-8",
    )
    (root / "web/package-lock.json").write_text(
        json.dumps(
            {
                "version": "0.1.0-rc.1",
                "packages": {"": {"version": "0.1.0-rc.1"}},
            }
        ),
        encoding="utf-8",
    )
    (root / "deploy/production/base/api.yaml").write_text(
        "image: ghcr.io/your-org/sentinelops:0.1.0-rc.1\n",
        encoding="utf-8",
    )


def test_rc_version_is_normalized_across_package_formats(tmp_path: Path) -> None:
    _fixture(tmp_path)

    report = MODULE.build_report(
        tmp_path,
        expected_release_version="0.1.0-rc.1",
    )

    assert report["passed"] is True
    assert report["python_version"] == "0.1.0rc1"
    assert report["release_version"] == "0.1.0-rc.1"
    assert report["problems"] == []


def test_release_version_check_fails_on_runtime_drift(tmp_path: Path) -> None:
    _fixture(tmp_path, runtime_version="0.1.0")

    report = MODULE.build_report(tmp_path)

    assert report["passed"] is False
    assert report["problems"] == [
        "Python package metadata and runtime __version__ differ"
    ]


def test_repository_release_versions_are_consistent() -> None:
    root = Path(__file__).resolve().parents[1]

    report = MODULE.build_report(root)

    assert report["passed"] is True
    assert report["release_version"] == "0.1.0-rc.1"
