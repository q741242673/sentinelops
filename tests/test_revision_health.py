from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinelops.revision_health import (
    STATUS_KEY,
    VERIFIED_AT_KEY,
    build_health_proof_annotations,
    revision_subject,
    runtime_image_fingerprint,
    verify_health_proof,
)

NOW = datetime(2026, 7, 17, 0, 0, tzinfo=UTC)
CONTAINERS = [("order-service", "registry/order@sha256:abc")]


def subject(**overrides: str) -> dict[str, str]:
    values = {
        "deployment_uid": "deployment-a",
        "replica_set_uid": "replica-set-a",
        "revision": "7",
        "template_hash": "template-a",
        "runtime_images": runtime_image_fingerprint(
            [("order-service", "docker-pullable://registry/order@sha256:abc")]
        ),
        "git_commit": "deadbeef",
    }
    values.update(overrides)
    return revision_subject(containers=CONTAINERS, **values)


def validate(annotations: dict[str, str], **overrides: str):
    values = {
        "deployment_uid": "deployment-a",
        "replica_set_uid": "replica-set-a",
        "revision": "7",
        "template_hash": "template-a",
        "git_commit": "deadbeef",
    }
    values.update(overrides)
    return verify_health_proof(
        annotations,
        containers=CONTAINERS,
        now=NOW,
        **values,
    )


def test_valid_proof_is_bound_to_exact_revision() -> None:
    annotations = build_health_proof_annotations(
        subject(), verified_at=NOW, verifier="release-pipeline"
    )

    proof = validate(annotations)

    assert proof["valid"] is True
    assert proof["status"] == "healthy"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("deployment_uid", "deployment-b"),
        ("replica_set_uid", "replica-set-b"),
        ("revision", "8"),
        ("template_hash", "template-b"),
        ("git_commit", "cafebabe"),
    ],
)
def test_copied_proof_is_rejected_on_a_different_subject(
    field: str, replacement: str
) -> None:
    annotations = build_health_proof_annotations(
        subject(), verified_at=NOW, verifier="release-pipeline"
    )

    proof = validate(annotations, **{field: replacement})

    assert proof["valid"] is False
    assert proof["status"] == "unknown"


def test_plain_healthy_marker_is_not_a_health_proof() -> None:
    proof = validate({STATUS_KEY: "healthy"})

    assert proof["valid"] is False
    assert proof["invalid_reasons"]


def test_tampered_image_reference_invalidates_proof() -> None:
    annotations = build_health_proof_annotations(
        subject(), verified_at=NOW, verifier="release-pipeline"
    )

    proof = verify_health_proof(
        annotations,
        deployment_uid="deployment-a",
        replica_set_uid="replica-set-a",
        revision="7",
        template_hash="template-a",
        containers=[("order-service", "registry/order@sha256:different")],
        git_commit="deadbeef",
        now=NOW,
    )

    assert proof["valid"] is False


def test_future_or_malformed_verification_time_is_rejected() -> None:
    future = build_health_proof_annotations(
        subject(), verified_at=NOW + timedelta(minutes=6), verifier="release-pipeline"
    )
    malformed = dict(future)
    malformed[VERIFIED_AT_KEY] = "not-a-time"

    assert validate(future)["valid"] is False
    assert validate(malformed)["valid"] is False


def test_proof_builder_rejects_an_unidentified_verifier() -> None:
    with pytest.raises(ValueError, match="verifier"):
        build_health_proof_annotations(subject(), verified_at=NOW, verifier=" ")
