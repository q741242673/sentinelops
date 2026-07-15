#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${SENTINELOPS_OBSERVABILITY_CLUSTER:-sentinelops-observability}"
CONTEXT="kind-${CLUSTER_NAME}"

kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  patch deployment inventory-service \
  --type strategic \
  --patch-file "${ROOT_DIR}/deploy/observability/faults/inventory-error-rate.yaml"
kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  rollout status deployment/inventory-service --timeout=2m
kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  rollout history deployment/inventory-service
