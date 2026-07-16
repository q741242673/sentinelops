#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinelops.revision_health import (  # noqa: E402
    build_health_proof_annotations,
    revision_subject,
    runtime_image_fingerprint,
    verify_health_proof,
)


def kubectl(args: argparse.Namespace, *parts: str) -> str:
    command = ["kubectl"]
    if args.context:
        command.extend(["--context", args.context])
    command.extend(["--namespace", args.namespace, *parts])
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def kubectl_json(args: argparse.Namespace, *parts: str) -> dict[str, Any]:
    return json.loads(kubectl(args, *parts, "--output", "json"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Attest the exact ready ReplicaSet revision as healthy."
    )
    parser.add_argument("--context")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--verifier", default="sentinelops-release-verifier")
    args = parser.parse_args()

    deployment = kubectl_json(args, "get", f"deployment/{args.deployment}")
    deployment_uid = deployment["metadata"]["uid"]
    template_annotations = deployment["spec"]["template"]["metadata"].get(
        "annotations", {}
    )
    if "sentinelops.io/health-status" in template_annotations:
        raise SystemExit(
            "Refusing to attest: remove sentinelops.io/health-status from the "
            "Deployment Pod template first"
        )

    replica_sets = kubectl_json(args, "get", "replicaset", "--selector", f"app={args.deployment}")
    owned = []
    for replica_set in replica_sets["items"]:
        owners = replica_set["metadata"].get("ownerReferences", [])
        if any(
            owner.get("uid") == deployment_uid
            and owner.get("kind") == "Deployment"
            and owner.get("controller") is True
            for owner in owners
        ):
            owned.append(replica_set)
    if not owned:
        raise SystemExit(f"No owned ReplicaSet found for {args.deployment}")
    target = max(
        owned,
        key=lambda item: int(
            item["metadata"].get("annotations", {}).get(
                "deployment.kubernetes.io/revision", "0"
            )
        ),
    )
    desired = target["spec"].get("replicas", 0)
    ready = target.get("status", {}).get("readyReplicas", 0)
    if desired <= 0 or ready != desired:
        raise SystemExit("Current ReplicaSet is not fully ready; proof was not written")

    metadata = target["metadata"]
    template = target["spec"]["template"]
    template_hash = metadata.get("labels", {}).get("pod-template-hash", "")
    if not template_hash:
        raise SystemExit("Current ReplicaSet has no pod-template-hash")
    pods = kubectl_json(
        args,
        "get",
        "pods",
        "--selector",
        f"app={args.deployment},pod-template-hash={template_hash}",
    )
    image_ids: dict[str, set[str]] = {}
    ready_pods = 0
    for pod in pods["items"]:
        owners = pod["metadata"].get("ownerReferences", [])
        if not any(
            owner.get("uid") == metadata["uid"]
            and owner.get("kind") == "ReplicaSet"
            and owner.get("controller") is True
            for owner in owners
        ):
            continue
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if not statuses or not all(item.get("ready") and item.get("imageID") for item in statuses):
            continue
        ready_pods += 1
        for status in statuses:
            image_ids.setdefault(status["name"], set()).add(status["imageID"])
    containers = template["spec"].get("containers", [])
    expected_names = {container["name"] for container in containers}
    if (
        ready_pods < desired
        or set(image_ids) != expected_names
        or any(len(values) != 1 for values in image_ids.values())
    ):
        raise SystemExit("Ready Pods do not provide one consistent runtime image per container")

    annotations = metadata.get("annotations", {})
    subject = revision_subject(
        deployment_uid=deployment_uid,
        replica_set_uid=metadata["uid"],
        revision=annotations["deployment.kubernetes.io/revision"],
        template_hash=template_hash,
        containers=[(container["name"], container["image"]) for container in containers],
        runtime_images=runtime_image_fingerprint(
            [(name, next(iter(values))) for name, values in image_ids.items()]
        ),
        git_commit=template.get("metadata", {}).get("annotations", {}).get(
            "sentinelops.io/git-commit", ""
        ),
    )
    proof = build_health_proof_annotations(
        subject,
        verified_at=datetime.now(UTC),
        verifier=args.verifier,
    )
    kubectl(
        args,
        "annotate",
        f"replicaset/{metadata['name']}",
        "--overwrite",
        *[f"{key}={value}" for key, value in proof.items()],
    )
    saved = kubectl_json(args, "get", f"replicaset/{metadata['name']}")
    validation = verify_health_proof(
        saved["metadata"].get("annotations", {}),
        deployment_uid=deployment_uid,
        replica_set_uid=metadata["uid"],
        revision=subject["revision"],
        template_hash=template_hash,
        containers=[(container["name"], container["image"]) for container in containers],
        git_commit=subject["git_commit"],
    )
    if not validation["valid"]:
        raise SystemExit(f"Saved health proof failed validation: {validation['invalid_reasons']}")
    print(
        json.dumps(
            {
                "deployment": args.deployment,
                "replica_set": metadata["name"],
                "revision": int(subject["revision"]),
                "health_proof": validation,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
