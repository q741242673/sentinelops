#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${SENTINELOPS_OBSERVABILITY_CLUSTER:-sentinelops-observability}"
CONTEXT="kind-${CLUSTER_NAME}"
IMAGE="sentinelops-demo-services:local"

if ! kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  kind create cluster \
    --name "${CLUSTER_NAME}" \
    --config "${ROOT_DIR}/deploy/kind/kind-config.yaml"
fi

docker build --tag "${IMAGE}" "${ROOT_DIR}/demo/services"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

kubectl --context "${CONTEXT}" apply -f "${ROOT_DIR}/deploy/observability/stack.yaml"
kubectl --context "${CONTEXT}" apply -f "${ROOT_DIR}/deploy/observability/services.yaml"

for deployment in loki tempo prometheus otel-collector inventory-service order-service; do
  kubectl --context "${CONTEXT}" \
    --namespace sentinelops-demo \
    rollout status "deployment/${deployment}" \
    --timeout=5m
done

kubectl --context "${CONTEXT}" --namespace sentinelops-demo get pods
