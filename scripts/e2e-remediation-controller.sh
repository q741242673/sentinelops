#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${SENTINELOPS_KIND_CLUSTER:-sentinelops}"
IMAGE="sentinelops-remediation-controller:e2e"

docker build \
  --tag "${IMAGE}" \
  "${ROOT_DIR}/controller"
"${ROOT_DIR}/scripts/kind-load-image.sh" \
  "${CLUSTER_NAME}" \
  "${IMAGE}"

kubectl apply \
  -f "${ROOT_DIR}/deploy/production/crds/sentinelremediations.yaml" \
  -f "${ROOT_DIR}/deploy/kind/remediation-controller.yaml"
kubectl rollout restart \
  deployment/sentinelops-remediation-controller \
  --namespace sentinelops-system
kubectl rollout status \
  deployment/sentinelops-remediation-controller \
  --namespace sentinelops-system \
  --timeout 120s

PYTHON="${SENTINELOPS_PYTHON:-python3}"
if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  PYTHON="${ROOT_DIR}/.venv/bin/python"
fi
executor_token="$(
  kubectl create token sentinelops-executor \
    --namespace sentinelops-system \
    --duration 10m
)"
SENTINELOPS_E2E_EXECUTOR_TOKEN="${executor_token}" \
  "${PYTHON}" "${ROOT_DIR}/scripts/e2e-remediation-controller.py"
kubectl rollout status \
  deployment/order-service \
  --namespace sentinelops-demo \
  --timeout 120s
"${PYTHON}" "${ROOT_DIR}/scripts/attest_revision_health.py" \
  --context "kind-${CLUSTER_NAME}" \
  --namespace sentinelops-demo \
  --deployment order-service \
  --verifier sentinelops-remediation-controller-e2e

kubectl auth can-i update deployments \
  --as system:serviceaccount:sentinelops-system:sentinelops-remediation-controller \
  --namespace sentinelops-demo \
  | grep --quiet '^yes$'
executor_can_update="$(kubectl auth can-i update deployments \
  --as system:serviceaccount:sentinelops-system:sentinelops-executor \
  --namespace sentinelops-demo || true)"
[[ "${executor_can_update}" == "no" ]]
kubectl auth can-i create sentinelremediations.ops.sentinelops.io \
  --as system:serviceaccount:sentinelops-system:sentinelops-executor \
  --namespace sentinelops-demo \
  | grep --quiet '^yes$'
executor_can_mutate_contract="$(
  kubectl auth can-i update sentinelremediations.ops.sentinelops.io \
    --as system:serviceaccount:sentinelops-system:sentinelops-executor \
    --namespace sentinelops-demo || true
)"
[[ "${executor_can_mutate_contract}" == "no" ]]
