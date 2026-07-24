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

OUTPUT_FILE="$(mktemp)"
trap 'rm -f "${OUTPUT_FILE}"; cleanup' EXIT

set +e
sentinelops investigate --approve | tee "${OUTPUT_FILE}"
INVESTIGATE_STATUS=${PIPESTATUS[0]}
set -e

if [[ "${INVESTIGATE_STATUS}" -ne 2 ]]; then
  echo "Expected strict verification to escalate without observability, exit=${INVESTIGATE_STATUS}" >&2
  exit 1
fi

grep --quiet '"tool_name": "rollback_deployment"' "${OUTPUT_FILE}"
grep --quiet '"type": "action.executed"' "${OUTPUT_FILE}"
grep --quiet '"type": "recovery.verification_incomplete"' "${OUTPUT_FILE}"
