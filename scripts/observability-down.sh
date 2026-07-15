#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${SENTINELOPS_OBSERVABILITY_CLUSTER:-sentinelops-observability}"

if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  kind delete cluster --name "${CLUSTER_NAME}"
fi
