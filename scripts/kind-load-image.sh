#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: kind-load-image.sh CLUSTER_NAME IMAGE" >&2
  exit 2
fi

CLUSTER_NAME="$1"
IMAGE="$2"

if kind load docker-image --name "${CLUSTER_NAME}" "${IMAGE}"; then
  exit 0
fi

# Docker Desktop can retain a valid single-platform image behind an incomplete
# OCI index. kind's all-platform import then fails even though the runnable
# image is present. Import the host platform explicitly as a safe fallback.
architecture="$(docker image inspect "${IMAGE}" --format '{{.Architecture}}')"
case "${architecture}" in
  arm64 | aarch64)
    platform="linux/arm64"
    ;;
  amd64 | x86_64)
    platform="linux/amd64"
    ;;
  *)
    echo "unsupported Docker image architecture: ${architecture}" >&2
    exit 1
    ;;
esac

while IFS= read -r node; do
  docker save "${IMAGE}" |
    docker exec --privileged -i "${node}" \
      ctr --namespace=k8s.io images import \
      --platform "${platform}" \
      --snapshotter=overlayfs \
      -
done < <(kind get nodes --name "${CLUSTER_NAME}")
