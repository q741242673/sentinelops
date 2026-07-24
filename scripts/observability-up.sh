#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${SENTINELOPS_OBSERVABILITY_CLUSTER:-sentinelops-observability}"
CONTEXT="kind-${CLUSTER_NAME}"
IMAGE="sentinelops-demo-services:local"
ALERTMANAGER_IMAGE="prom/alertmanager:v0.28.1"
OBSERVABILITY_IMAGES=(
  "prom/prometheus:v3.13.1"
  "${ALERTMANAGER_IMAGE}"
  "grafana/loki:3.7.3"
  "grafana/tempo:3.0.2"
  "otel/opentelemetry-collector-contrib:0.156.0"
)

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
for observability_image in "${OBSERVABILITY_IMAGES[@]}"; do
  docker pull --platform "${NODE_PLATFORM}" "${observability_image}"
  docker save "${observability_image}" |
    docker exec --privileged -i "${NODE_CONTAINER}" \
      ctr --namespace=k8s.io images import \
      --platform "${NODE_PLATFORM}" --digests --snapshotter=overlayfs -
done

INVENTORY_DEPLOYMENT_EXISTS=false
ORDER_DEPLOYMENT_EXISTS=false
if kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  get deployment/inventory-service >/dev/null 2>&1; then
  INVENTORY_DEPLOYMENT_EXISTS=true
fi
if kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  get deployment/order-service >/dev/null 2>&1; then
  ORDER_DEPLOYMENT_EXISTS=true
fi

kubectl --context "${CONTEXT}" apply -f "${ROOT_DIR}/deploy/observability/stack.yaml"
kubectl --context "${CONTEXT}" apply -f "${ROOT_DIR}/deploy/observability/services.yaml"
GIT_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
REPOSITORY="$(basename "${ROOT_DIR}")"
for deployment in inventory-service order-service; do
  kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
    patch "deployment/${deployment}" --type merge \
    --patch "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"sentinelops.io/git-commit\":\"${GIT_COMMIT}\",\"sentinelops.io/repository\":\"${REPOSITORY}\",\"sentinelops.io/source-path\":\"demo/services\",\"sentinelops.io/health-status\":null}}}}}"
done
kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  rollout restart deployment/prometheus
kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  rollout restart deployment/alertmanager
if [[ "${INVENTORY_DEPLOYMENT_EXISTS}" == "true" ]]; then
  kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
    rollout restart deployment/inventory-service
fi
if [[ "${ORDER_DEPLOYMENT_EXISTS}" == "true" ]]; then
  kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
    rollout restart deployment/order-service
fi

for deployment in loki tempo alertmanager prometheus otel-collector inventory-service order-service; do
  wait_for_deployment "${deployment}"
done

for deployment in inventory-service order-service; do
  python3 "${ROOT_DIR}/scripts/attest_revision_health.py" \
    --context "${CONTEXT}" \
    --namespace sentinelops-demo \
    --deployment "${deployment}" \
    --verifier sentinelops-observability-bootstrap
done

kubectl --context "${CONTEXT}" --namespace sentinelops-demo get pods
