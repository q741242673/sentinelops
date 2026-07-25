from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/release_manifest.py"
SPEC = importlib.util.spec_from_file_location(
    "sentinelops_release_manifest_script",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

COMMIT = "a" * 40
DIGEST = f"sha256:{'b' * 64}"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _artifacts(root: Path) -> tuple[Path, Path]:
    package_dir = root / "package"
    package_dir.mkdir()
    packages = {
        "sentinelops-0.1.0rc1-py3-none-any.whl": b"wheel",
        "sentinelops-0.1.0rc1.tar.gz": b"source",
    }
    for name, content in packages.items():
        (package_dir / name).write_bytes(content)
    (package_dir / "SHA256SUMS").write_text(
        "".join(f"{_sha256(content)}  {name}\n" for name, content in packages.items()),
        encoding="utf-8",
    )
    sbom = root / "sentinelops-0.1.0-rc.1-sbom.spdx.json"
    sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8")
    return package_dir, sbom


def _manifest(root: Path) -> dict:
    package_dir, sbom = _artifacts(root)
    return MODULE.build_manifest(
        release_version="0.1.0-rc.1",
        tag="v0.1.0-rc.1",
        commit=COMMIT,
        repository="q741242673/sentinelops",
        image_name="ghcr.io/q741242673/sentinelops",
        image_digest=DIGEST,
        soak_run_id="30109865038",
        github_run_id="30110700700",
        package_dir=package_dir,
        sbom_path=sbom,
    )


def test_release_manifest_binds_all_immutable_outputs(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["release"] == {
        "version": "0.1.0-rc.1",
        "tag": "v0.1.0-rc.1",
        "prerelease": True,
    }
    assert manifest["container"]["immutable_reference"] == (
        f"ghcr.io/q741242673/sentinelops@{DIGEST}"
    )
    assert manifest["container"]["tags"] == [
        "ghcr.io/q741242673/sentinelops:0.1.0-rc.1",
        f"ghcr.io/q741242673/sentinelops:sha-{COMMIT[:12]}",
    ]
    assert len(manifest["python_packages"]) == 2
    assert manifest["evidence"]["soak_run_id"] == "30109865038"


def test_release_manifest_rejects_tag_version_mismatch(tmp_path: Path) -> None:
    package_dir, sbom = _artifacts(tmp_path)

    with pytest.raises(ValueError, match="tag does not match"):
        MODULE.build_manifest(
            release_version="0.1.0-rc.1",
            tag="v0.1.0-rc.2",
            commit=COMMIT,
            repository="q741242673/sentinelops",
            image_name="ghcr.io/q741242673/sentinelops",
            image_digest=DIGEST,
            soak_run_id="1",
            github_run_id="2",
            package_dir=package_dir,
            sbom_path=sbom,
        )


def test_release_manifest_rejects_tampered_package(tmp_path: Path) -> None:
    package_dir, sbom = _artifacts(tmp_path)
    (package_dir / "sentinelops-0.1.0rc1.tar.gz").write_bytes(b"tampered")

    with pytest.raises(ValueError, match="checksum mismatch"):
        MODULE.build_manifest(
            release_version="0.1.0-rc.1",
            tag="v0.1.0-rc.1",
            commit=COMMIT,
            repository="q741242673/sentinelops",
            image_name="ghcr.io/q741242673/sentinelops",
            image_digest=DIGEST,
            soak_run_id="1",
            github_run_id="2",
            package_dir=package_dir,
            sbom_path=sbom,
        )


def test_release_manifest_rejects_cross_repository_image(tmp_path: Path) -> None:
    package_dir, sbom = _artifacts(tmp_path)

    with pytest.raises(ValueError, match="image name"):
        MODULE.build_manifest(
            release_version="0.1.0-rc.1",
            tag="v0.1.0-rc.1",
            commit=COMMIT,
            repository="q741242673/sentinelops",
            image_name="ghcr.io/attacker/sentinelops",
            image_digest=DIGEST,
            soak_run_id="1",
            github_run_id="2",
            package_dir=package_dir,
            sbom_path=sbom,
        )
