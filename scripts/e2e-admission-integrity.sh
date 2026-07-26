#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="sentinelops-demo"
POLICY_NAME="sentinelops-workload-write-fence"
CONTROLLER_DEPLOYMENT="sentinelops-remediation-controller"
POLICY_MANAGER="system:serviceaccount:sentinelops-system:sentinelops-admission-admin"
E2E_ADMIN_BINDING="sentinelops-admission-integrity-e2e-admin"
EXPECTED_GUARD_SPEC='{"allowedPolicyManagers":["system:serviceaccount:sentinelops-system:sentinelops-admission-admin"],"allowedDeploymentWriters":["system:serviceaccount:sentinelops-system:sentinelops-remediation-controller"],"allowedRemediationCreators":["system:serviceaccount:sentinelops-system:sentinelops-executor"],"allowedRemediationStatusWriters":["system:serviceaccount:sentinelops-system:sentinelops-remediation-controller"],"allowedRemediationDeleters":[]}'

restore_policy() {
  sed \
    -e "s/namespace: sentinelops-workloads/namespace: ${NAMESPACE}/g" \
    "${ROOT_DIR}/deploy/production/admission/workload-write-fence.yaml" \
    | kubectl apply -f - >/dev/null 2>&1 || true
}
cleanup() {
  restore_policy
  kubectl label namespace "${NAMESPACE}" \
    sentinelops.io/admission-audit- \
    sentinelops.io/admission-protected- \
    --overwrite \
    --as "${POLICY_MANAGER}" >/dev/null 2>&1 || true
  kubectl delete clusterrolebinding "${E2E_ADMIN_BINDING}" \
    --ignore-not-found >/dev/null
}
trap cleanup EXIT

kubectl apply \
  -f "${ROOT_DIR}/deploy/production/crds/sentineladmissionguards.yaml"
kubectl wait \
  --for=condition=Established \
  crd/sentineladmissionguards.ops.sentinelops.io \
  --timeout=60s
sed \
  -e "s/namespace: sentinelops-workloads/namespace: ${NAMESPACE}/g" \
  "${ROOT_DIR}/deploy/production/admission/workload-write-fence-guard.yaml" \
  | kubectl apply -f -
kubectl label namespace "${NAMESPACE}" \
  sentinelops.io/admission-audit- \
  sentinelops.io/admission-protected=true \
  --overwrite
restore_policy
kubectl wait \
  --for=jsonpath='{.status.observedGeneration}'=1 \
  "validatingadmissionpolicy/${POLICY_NAME}" \
  --timeout=60s
kubectl create clusterrolebinding "${E2E_ADMIN_BINDING}" \
  --clusterrole=cluster-admin \
  --serviceaccount=sentinelops-system:sentinelops-admission-admin
kubectl wait \
  --for=jsonpath='{.status.observedGeneration}'=1 \
  validatingadmissionpolicy/sentinelops-admission-governance \
  --timeout=60s

sed \
  -e "s/namespace: sentinelops-workloads/namespace: ${NAMESPACE}/g" \
  "${ROOT_DIR}/deploy/production/access/workload-rbac.yaml" \
  | kubectl apply -f -
sed \
  -e "s/sentinelops-workloads/${NAMESPACE}/g" \
  "${ROOT_DIR}/deploy/production/base/remediation-controller-rbac.yaml" \
  | kubectl apply -f -

kubectl set env \
  --namespace sentinelops-system \
  "deployment/${CONTROLLER_DEPLOYMENT}" \
  SENTINELOPS_ADMISSION_INTEGRITY_REQUIRED=true \
  SENTINELOPS_ADMISSION_POLICY_NAME="${POLICY_NAME}" \
  SENTINELOPS_ADMISSION_GOVERNANCE_POLICY_NAME=sentinelops-admission-governance \
  SENTINELOPS_ADMISSION_GUARD_NAME="${POLICY_NAME}" \
  SENTINELOPS_ADMISSION_REQUEST_TIMEOUT=5s \
  SENTINELOPS_ADMISSION_RECONCILE_INTERVAL=2s \
  SENTINELOPS_ADMISSION_EXPECTED_GUARD_SPEC="${EXPECTED_GUARD_SPEC}"
kubectl rollout status \
  "deployment/${CONTROLLER_DEPLOYMENT}" \
  --namespace sentinelops-system \
  --timeout=120s

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
SENTINELOPS_E2E_SINGLE_CONTROLLER_ACTION=true \
  "${PYTHON}" "${ROOT_DIR}/scripts/e2e-remediation-controller.py"

kubectl label namespace "${NAMESPACE}" \
  sentinelops.io/admission-protected- \
  sentinelops.io/admission-audit=true \
  --overwrite \
  --as "${POLICY_MANAGER}"
SENTINELOPS_E2E_EXECUTOR_TOKEN="${executor_token}" \
SENTINELOPS_E2E_EXPECT_CONTROLLER_REJECTION=AdmissionFenceNotEnforced \
  "${PYTHON}" "${ROOT_DIR}/scripts/e2e-remediation-controller.py"
kubectl label namespace "${NAMESPACE}" \
  sentinelops.io/admission-audit- \
  sentinelops.io/admission-protected=true \
  --overwrite \
  --as "${POLICY_MANAGER}"

kubectl delete validatingadmissionpolicybinding "${POLICY_NAME}"
SENTINELOPS_E2E_EXECUTOR_TOKEN="${executor_token}" \
SENTINELOPS_E2E_EXPECT_CONTROLLER_REJECTION=AdmissionIntegrityUnknown \
  "${PYTHON}" "${ROOT_DIR}/scripts/e2e-remediation-controller.py"

restore_policy
SENTINELOPS_E2E_EXECUTOR_TOKEN="${executor_token}" \
SENTINELOPS_E2E_SINGLE_CONTROLLER_ACTION=true \
  "${PYTHON}" "${ROOT_DIR}/scripts/e2e-remediation-controller.py"

cleanup
trap - EXIT
echo "Admission integrity E2E passed: healthy, drift-blocked, and restored writes."
