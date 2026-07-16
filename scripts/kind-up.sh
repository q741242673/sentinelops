#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${SENTINELOPS_KIND_CLUSTER:-sentinelops}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

clusters="$(kind get clusters 2>/dev/null || true)"
if ! grep -Fxq "${CLUSTER_NAME}" <<<"${clusters}"; then
  kind create cluster \
    --name "${CLUSTER_NAME}" \
    --config "${ROOT_DIR}/deploy/kind/kind-config.yaml" \
    --wait 120s
fi

kubectl config use-context "kind-${CLUSTER_NAME}"
kubectl apply -f "${ROOT_DIR}/deploy/kind/workload.yaml"
kubectl patch deployment/order-service \
  --namespace sentinelops-demo \
  --type merge \
  --patch '{"spec":{"template":{"metadata":{"annotations":{"sentinelops.io/health-status":null}}}}}'
kubectl rollout status deployment/order-service \
  --namespace sentinelops-demo \
  --timeout 120s
python3 "${ROOT_DIR}/scripts/attest_revision_health.py" \
  --context "kind-${CLUSTER_NAME}" \
  --namespace sentinelops-demo \
  --deployment order-service \
  --verifier sentinelops-kind-bootstrap

echo "SentinelOps kind lab is ready on context kind-${CLUSTER_NAME}"
