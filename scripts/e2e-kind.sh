#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
  if [[ "${SENTINELOPS_KEEP_KIND_CLUSTER:-false}" != "true" ]]; then
    "${ROOT_DIR}/scripts/kind-down.sh"
  fi
}
trap cleanup EXIT

"${ROOT_DIR}/scripts/kind-up.sh"
"${ROOT_DIR}/scripts/inject-bad-rollout.sh"

export SENTINELOPS_TOOL_BACKEND=kubernetes
export SENTINELOPS_MODEL_PROVIDER=rule_based
export SENTINELOPS_KUBERNETES_NAMESPACE=sentinelops-demo

sentinelops investigate --approve

