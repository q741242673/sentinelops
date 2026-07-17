from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

PREFIX = "sentinelops.io/health-proof-"
VERSION_KEY = f"{PREFIX}version"
STATUS_KEY = f"{PREFIX}status"
SUBJECT_KEY = f"{PREFIX}subject"
DEPLOYMENT_UID_KEY = f"{PREFIX}deployment-uid"
REPLICA_SET_UID_KEY = f"{PREFIX}replicaset-uid"
REVISION_KEY = f"{PREFIX}revision"
TEMPLATE_HASH_KEY = f"{PREFIX}template-hash"
IMAGES_KEY = f"{PREFIX}images"
RUNTIME_IMAGES_KEY = f"{PREFIX}runtime-images"
GIT_COMMIT_KEY = f"{PREFIX}git-commit"
VERIFIED_AT_KEY = f"{PREFIX}verified-at"
VERIFIER_KEY = f"{PREFIX}verifier"

PROOF_VERSION = "v1"
PROOF_STATUS = "healthy"
MAX_CLOCK_SKEW = timedelta(minutes=5)


def _digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def image_reference_fingerprint(containers: list[tuple[str, str]]) -> str:
    items = [{"name": name, "image": image} for name, image in containers]
    return _digest(sorted(items, key=lambda item: item["name"]))


def runtime_image_fingerprint(image_ids: list[tuple[str, str]]) -> str:
    items = [{"name": name, "image_id": image_id} for name, image_id in image_ids]
    return _digest(sorted(items, key=lambda item: item["name"]))


def revision_subject(
    *,
    deployment_uid: str,
    replica_set_uid: str,
    revision: str,
    template_hash: str,
    containers: list[tuple[str, str]],
    runtime_images: str,
    git_commit: str = "",
) -> dict[str, str]:
    return {
        "deployment_uid": deployment_uid,
        "replica_set_uid": replica_set_uid,
        "revision": revision,
        "template_hash": template_hash,
        "images": image_reference_fingerprint(containers),
        "runtime_images": runtime_images,
        "git_commit": git_commit,
    }


def build_health_proof_annotations(
    subject: dict[str, str],
    *,
    verified_at: datetime,
    verifier: str,
) -> dict[str, str]:
    if verified_at.tzinfo is None:
        raise ValueError("verified_at must include a timezone")
    if not verifier.strip():
        raise ValueError("verifier must not be empty")
    normalized_time = verified_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return {
        VERSION_KEY: PROOF_VERSION,
        STATUS_KEY: PROOF_STATUS,
        SUBJECT_KEY: _digest(subject),
        DEPLOYMENT_UID_KEY: subject["deployment_uid"],
        REPLICA_SET_UID_KEY: subject["replica_set_uid"],
        REVISION_KEY: subject["revision"],
        TEMPLATE_HASH_KEY: subject["template_hash"],
        IMAGES_KEY: subject["images"],
        RUNTIME_IMAGES_KEY: subject["runtime_images"],
        GIT_COMMIT_KEY: subject["git_commit"] or "none",
        VERIFIED_AT_KEY: normalized_time,
        VERIFIER_KEY: verifier.strip(),
    }


def verify_health_proof(
    annotations: dict[str, str],
    *,
    deployment_uid: str,
    replica_set_uid: str,
    revision: str,
    template_hash: str,
    containers: list[tuple[str, str]],
    git_commit: str = "",
    now: datetime | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    runtime_images = annotations.get(RUNTIME_IMAGES_KEY, "")
    subject = revision_subject(
        deployment_uid=deployment_uid,
        replica_set_uid=replica_set_uid,
        revision=revision,
        template_hash=template_hash,
        containers=containers,
        runtime_images=runtime_images,
        git_commit=git_commit,
    )
    expected = {
        VERSION_KEY: PROOF_VERSION,
        STATUS_KEY: PROOF_STATUS,
        SUBJECT_KEY: _digest(subject),
        DEPLOYMENT_UID_KEY: subject["deployment_uid"],
        REPLICA_SET_UID_KEY: subject["replica_set_uid"],
        REVISION_KEY: subject["revision"],
        TEMPLATE_HASH_KEY: subject["template_hash"],
        IMAGES_KEY: subject["images"],
        GIT_COMMIT_KEY: subject["git_commit"] or "none",
    }
    for key, value in expected.items():
        if annotations.get(key) != value:
            reasons.append(f"{key} mismatch")
    if not runtime_images.startswith("sha256:"):
        reasons.append(f"{RUNTIME_IMAGES_KEY} is missing or invalid")
    if not annotations.get(VERIFIER_KEY, "").strip():
        reasons.append(f"{VERIFIER_KEY} is missing")

    verified_at = annotations.get(VERIFIED_AT_KEY)
    parsed_time: datetime | None = None
    if verified_at:
        try:
            parsed_time = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
            if parsed_time.tzinfo is None:
                raise ValueError
        except ValueError:
            reasons.append(f"{VERIFIED_AT_KEY} is invalid")
    else:
        reasons.append(f"{VERIFIED_AT_KEY} is missing")
    reference_time = (now or datetime.now(UTC)).astimezone(UTC)
    if parsed_time and parsed_time.astimezone(UTC) > reference_time + MAX_CLOCK_SKEW:
        reasons.append(f"{VERIFIED_AT_KEY} is in the future")

    valid = not reasons
    return {
        "valid": valid,
        "status": PROOF_STATUS if valid else "unknown",
        "version": annotations.get(VERSION_KEY),
        "verified_at": verified_at,
        "verifier": annotations.get(VERIFIER_KEY),
        "subject": annotations.get(SUBJECT_KEY),
        "invalid_reasons": reasons,
    }
