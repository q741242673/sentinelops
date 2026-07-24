from __future__ import annotations

import argparse
import json
import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PEP440_RC = re.compile(r"^(?P<base>\d+\.\d+\.\d+)rc(?P<number>\d+)$")
INIT_VERSION = re.compile(r'^__version__\s*=\s*"(?P<version>[^"]+)"\s*$', re.MULTILINE)
IMAGE_VERSION = re.compile(r"ghcr\.io/your-org/sentinelops:(?P<version>[^\s]+)")


def release_version(python_version: str) -> str:
    match = PEP440_RC.fullmatch(python_version)
    if match is None:
        return python_version
    return f"{match.group('base')}-rc.{match.group('number')}"


def _python_version(root: Path) -> str:
    with (root / "pyproject.toml").open("rb") as stream:
        return str(tomllib.load(stream)["project"]["version"])


def _init_version(root: Path) -> str:
    content = (root / "src/sentinelops/__init__.py").read_text(encoding="utf-8")
    match = INIT_VERSION.search(content)
    if match is None:
        raise ValueError("src/sentinelops/__init__.py does not declare __version__")
    return match.group("version")


def _web_versions(root: Path) -> tuple[str, str, str]:
    package = json.loads((root / "web/package.json").read_text(encoding="utf-8"))
    lock = json.loads((root / "web/package-lock.json").read_text(encoding="utf-8"))
    return (
        str(package["version"]),
        str(lock["version"]),
        str(lock["packages"][""]["version"]),
    )


def _image_versions(root: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for path in sorted((root / "deploy/production/base").glob("*.yaml")):
        match = IMAGE_VERSION.search(path.read_text(encoding="utf-8"))
        if match is not None:
            versions[str(path.relative_to(root))] = match.group("version")
    return versions


def build_report(
    root: Path,
    *,
    expected_release_version: str | None = None,
) -> dict[str, Any]:
    python_version = _python_version(root)
    expected = release_version(python_version)
    init_version = _init_version(root)
    web_versions = _web_versions(root)
    image_versions = _image_versions(root)
    problems: list[str] = []

    if init_version != python_version:
        problems.append("Python package metadata and runtime __version__ differ")
    if any(version != expected for version in web_versions):
        problems.append("Web package versions do not match the release version")
    if not image_versions:
        problems.append("Production manifests do not declare a SentinelOps image")
    elif any(version != expected for version in image_versions.values()):
        problems.append("Production image tags do not match the release version")
    if expected_release_version is not None and expected_release_version != expected:
        problems.append("Requested release version does not match repository metadata")

    return {
        "schema_version": "sentinelops.release-version.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "passed": not problems,
        "python_version": python_version,
        "release_version": expected,
        "requested_release_version": expected_release_version,
        "components": {
            "runtime": init_version,
            "web_package": web_versions[0],
            "web_lock": web_versions[1],
            "web_lock_root": web_versions[2],
            "production_images": image_versions,
        },
        "problems": problems,
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify one version across Python, web, and release manifests.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--release-version")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    report = build_report(
        arguments.root,
        expected_release_version=arguments.release_version,
    )
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
