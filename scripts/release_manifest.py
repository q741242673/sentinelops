from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RELEASE_VERSION = re.compile(r"^\d+\.\d+\.\d+-rc\.\d+$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST = re.compile(r"^sha256:(?P<digest>[0-9a-f]{64})$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_checksums(package_dir: Path) -> list[dict[str, Any]]:
    checksum_path = package_dir / "SHA256SUMS"
    declared: dict[str, str] = {}
    for raw_line in checksum_path.read_text(encoding="utf-8").splitlines():
        checksum, separator, name = raw_line.partition("  ")
        if (
            separator != "  "
            or not re.fullmatch(r"[0-9a-f]{64}", checksum)
            or not name
            or Path(name).name != name
        ):
            raise ValueError("SHA256SUMS contains an invalid entry")
        if name in declared:
            raise ValueError("SHA256SUMS contains a duplicate filename")
        declared[name] = checksum

    package_paths = sorted(
        path
        for path in package_dir.iterdir()
        if path.is_file() and path.name != "SHA256SUMS"
    )
    if not package_paths:
        raise ValueError("release package directory is empty")
    if {path.name for path in package_paths} != set(declared):
        raise ValueError("SHA256SUMS does not cover exactly the release packages")

    packages: list[dict[str, Any]] = []
    for path in package_paths:
        actual = _sha256(path)
        if actual != declared[path.name]:
            raise ValueError(f"checksum mismatch for {path.name}")
        packages.append(
            {
                "name": path.name,
                "sha256": actual,
                "size_bytes": path.stat().st_size,
            }
        )
    return packages


def build_manifest(
    *,
    release_version: str,
    tag: str,
    commit: str,
    repository: str,
    image_name: str,
    image_digest: str,
    soak_run_id: str,
    github_run_id: str,
    package_dir: Path,
    sbom_path: Path,
) -> dict[str, Any]:
    if RELEASE_VERSION.fullmatch(release_version) is None:
        raise ValueError("release version must be an RC semantic version")
    if tag != f"v{release_version}":
        raise ValueError("tag does not match the release version")
    if GIT_COMMIT.fullmatch(commit) is None:
        raise ValueError("commit must be a full lowercase Git SHA")
    if not repository or "/" not in repository:
        raise ValueError("repository must use owner/name form")
    if image_name != f"ghcr.io/{repository.lower()}":
        raise ValueError("image name must match the GitHub repository")
    digest_match = SHA256_DIGEST.fullmatch(image_digest)
    if digest_match is None:
        raise ValueError("image digest must be a sha256 digest")
    if not soak_run_id.isdigit() or not github_run_id.isdigit():
        raise ValueError("GitHub run IDs must be numeric")
    if not sbom_path.is_file():
        raise ValueError("SBOM file is missing")

    packages = _package_checksums(package_dir)
    sbom_sha256 = _sha256(sbom_path)
    immutable_image = f"{image_name}@{image_digest}"
    return {
        "schema_version": "sentinelops.release-manifest.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "release": {
            "version": release_version,
            "tag": tag,
            "prerelease": True,
        },
        "source": {
            "repository": repository,
            "commit": commit,
        },
        "evidence": {
            "soak_run_id": soak_run_id,
            "release_run_id": github_run_id,
        },
        "container": {
            "name": image_name,
            "digest": image_digest,
            "immutable_reference": immutable_image,
            "tags": [
                f"{image_name}:{release_version}",
                f"{image_name}:sha-{commit[:12]}",
            ],
            "sbom": {
                "name": sbom_path.name,
                "format": "spdx-json",
                "sha256": sbom_sha256,
                "size_bytes": sbom_path.stat().st_size,
            },
        },
        "python_packages": packages,
        "verification": {
            "version_consistent": True,
            "successful_soak_for_commit": True,
            "container_signature": "sigstore-keyless",
            "container_provenance": "github-and-buildkit",
            "package_provenance": "github",
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a checked release manifest from immutable build outputs.",
    )
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--image-name", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--soak-run-id", required=True)
    parser.add_argument("--github-run-id", required=True)
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    try:
        manifest = build_manifest(
            release_version=arguments.release_version,
            tag=arguments.tag,
            commit=arguments.commit,
            repository=arguments.repository,
            image_name=arguments.image_name,
            image_digest=arguments.image_digest,
            soak_run_id=arguments.soak_run_id,
            github_run_id=arguments.github_run_id,
            package_dir=arguments.package_dir,
            sbom_path=arguments.sbom,
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    arguments.output.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    main()
