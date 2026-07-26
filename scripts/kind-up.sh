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

WORKLOAD_IMAGE="${SENTINELOPS_KIND_WORKLOAD_IMAGE:-nginx:1.27-alpine}"
if ! docker image inspect "${WORKLOAD_IMAGE}" >/dev/null 2>&1; then
  docker pull "${WORKLOAD_IMAGE}"
fi
"${ROOT_DIR}/scripts/kind-load-image.sh" \
  "${CLUSTER_NAME}" \
  "${WORKLOAD_IMAGE}"

kubectl apply -f "${ROOT_DIR}/deploy/kind/workload.yaml"
kubectl patch deployment/order-service \
  --namespace sentinelops-demo \
  --type strategic \
  --patch '{
    "spec": {
      "template": {
        "metadata": {
          "annotations": {
            "ops.sentinelops.io/action-id": null,
            "ops.sentinelops.io/fence-generation": null,
            "sentinelops.io/change-cause": "healthy-baseline",
            "sentinelops.io/fault": null,
            "sentinelops.io/health-status": null,
            "sentinelops.io/rolledBackAt": null,
            "sentinelops.io/version": "1.0.0"
          }
        },
        "spec": {
          "containers": [
            {
              "name": "order-service",
              "command": null,
              "args": null
            }
          ]
        }
      }
    }
  }'
kubectl rollout status deployment/order-service \
  --namespace sentinelops-demo \
  --timeout 120s
python3 "${ROOT_DIR}/scripts/attest_revision_health.py" \
  --context "kind-${CLUSTER_NAME}" \
  --namespace sentinelops-demo \
  --deployment order-service \
  --verifier sentinelops-kind-bootstrap

echo "SentinelOps kind lab is ready on context kind-${CLUSTER_NAME}"
