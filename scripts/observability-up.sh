#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${SENTINELOPS_OBSERVABILITY_CLUSTER:-sentinelops-observability}"
CONTEXT="kind-${CLUSTER_NAME}"
IMAGE="sentinelops-demo-services:local"
ALERTMANAGER_IMAGE="prom/alertmanager:v0.28.1"

diagnose_deployment() {
  local deployment="$1"
  echo "Deployment ${deployment} did not become ready; collecting diagnostics" >&2
  kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
    get pods --selector "app=${deployment}" --output wide || true
  kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
    describe pods --selector "app=${deployment}" || true
  kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
    logs --selector "app=${deployment}" --all-containers --prefix --tail=200 || true
  kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
    get events --sort-by=.lastTimestamp || true
}

wait_for_deployment() {
  local deployment="$1"
  if ! kubectl --context "${CONTEXT}" \
    --namespace sentinelops-demo \
    rollout status "deployment/${deployment}" \
    --timeout=5m; then
    diagnose_deployment "${deployment}"
    return 1
  fi
}

if ! kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  kind create cluster \
    --name "${CLUSTER_NAME}" \
    --config "${ROOT_DIR}/deploy/kind/kind-config.yaml"
fi

docker build --tag "${IMAGE}" "${ROOT_DIR}/demo/services"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"
NODE_CONTAINER="${CLUSTER_NAME}-control-plane"
case "$(docker exec "${NODE_CONTAINER}" uname -m)" in
  aarch64) NODE_PLATFORM="linux/arm64" ;;
  x86_64) NODE_PLATFORM="linux/amd64" ;;
  *) echo "Unsupported kind node architecture" >&2; exit 1 ;;
esac
docker pull --platform "${NODE_PLATFORM}" "${ALERTMANAGER_IMAGE}"
docker save "${ALERTMANAGER_IMAGE}" | docker exec --privileged -i "${NODE_CONTAINER}" \
  ctr --namespace=k8s.io images import \
  --platform "${NODE_PLATFORM}" --digests --snapshotter=overlayfs -

kubectl --context "${CONTEXT}" apply -f "${ROOT_DIR}/deploy/observability/stack.yaml"
kubectl --context "${CONTEXT}" apply -f "${ROOT_DIR}/deploy/observability/services.yaml"
kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  rollout restart deployment/prometheus
kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  rollout restart deployment/alertmanager

for deployment in loki tempo alertmanager prometheus otel-collector inventory-service order-service; do
  wait_for_deployment "${deployment}"
done

kubectl --context "${CONTEXT}" --namespace sentinelops-demo get pods
