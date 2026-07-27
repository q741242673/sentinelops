#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${SENTINELOPS_ADMISSION_E2E_NAMESPACE:-sentinelops-admission-e2e}"
POLICY_NAME="sentinelops-admission-e2e"
ACTION_ID="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
INTRUDER_ACTION_ID="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
CONTROLLER_USER="system:serviceaccount:sentinelops-system:sentinelops-remediation-controller"
EXECUTOR_USER="system:serviceaccount:sentinelops-system:sentinelops-executor"
INTRUDER_USER="system:serviceaccount:sentinelops-system:sentinelops-admission-intruder"
GC_USER="system:serviceaccount:sentinelops-system:sentinelops-remediation-gc"
PLATFORM_ADMIN_USER="system:serviceaccount:sentinelops-system:sentinelops-admission-admin"
CREATED_GUARD_CRD=false

cleanup() {
  kubectl delete validatingadmissionpolicybinding \
    "${POLICY_NAME}-governance" \
    --ignore-not-found >/dev/null
  kubectl delete validatingadmissionpolicy \
    "${POLICY_NAME}-governance" \
    --ignore-not-found >/dev/null
  kubectl delete validatingadmissionpolicybinding \
    "${POLICY_NAME}-audit" \
    --ignore-not-found >/dev/null
  kubectl delete validatingadmissionpolicybinding "${POLICY_NAME}" \
    --ignore-not-found >/dev/null
  kubectl delete validatingadmissionpolicy "${POLICY_NAME}" \
    --ignore-not-found >/dev/null
  kubectl delete clusterrolebinding \
    "${POLICY_NAME}-namespace-writers" \
    --ignore-not-found >/dev/null
  kubectl delete clusterrole \
    "${POLICY_NAME}-namespace-writer" \
    --ignore-not-found >/dev/null
  kubectl delete namespace "${NAMESPACE}" \
    --ignore-not-found \
    --wait=true >/dev/null
  if [[ "${CREATED_GUARD_CRD}" == "true" ]]; then
    kubectl delete crd sentineladmissionguards.ops.sentinelops.io \
      --ignore-not-found \
      --wait=true >/dev/null
  fi
}
trap cleanup EXIT

if ! kubectl get crd sentineladmissionguards.ops.sentinelops.io \
  >/dev/null 2>&1; then
  kubectl apply \
    -f "${ROOT_DIR}/deploy/production/crds/sentineladmissionguards.yaml"
  CREATED_GUARD_CRD=true
fi
kubectl wait \
  --for=condition=Established \
  crd/sentineladmissionguards.ops.sentinelops.io \
  --timeout=60s

kubectl delete namespace "${NAMESPACE}" \
  --ignore-not-found \
  --wait=true >/dev/null
kubectl create namespace "${NAMESPACE}"
kubectl create deployment admission-target \
  --namespace "${NAMESPACE}" \
  --image=nginx:1.27 \
  --replicas=1

kubectl apply -f - <<YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: admission-e2e-writer
  namespace: ${NAMESPACE}
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "create", "update", "patch", "delete"]
  - apiGroups: ["ops.sentinelops.io"]
    resources: ["sentinelremediations"]
    verbs: ["get", "create", "update", "patch", "delete"]
  - apiGroups: ["ops.sentinelops.io"]
    resources: ["sentinelremediations/status"]
    verbs: ["get", "update", "patch"]
  - apiGroups: ["ops.sentinelops.io"]
    resources: ["sentineladmissionguards"]
    verbs: ["get", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: admission-e2e-writers
  namespace: ${NAMESPACE}
subjects:
  - kind: ServiceAccount
    name: sentinelops-remediation-controller
    namespace: sentinelops-system
  - kind: ServiceAccount
    name: sentinelops-executor
    namespace: sentinelops-system
  - kind: ServiceAccount
    name: sentinelops-admission-intruder
    namespace: sentinelops-system
  - kind: ServiceAccount
    name: sentinelops-remediation-gc
    namespace: sentinelops-system
  - kind: ServiceAccount
    name: sentinelops-admission-admin
    namespace: sentinelops-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: admission-e2e-writer
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${POLICY_NAME}-namespace-writer
rules:
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${POLICY_NAME}-namespace-writers
subjects:
  - kind: ServiceAccount
    name: sentinelops-admission-intruder
    namespace: sentinelops-system
  - kind: ServiceAccount
    name: sentinelops-admission-admin
    namespace: sentinelops-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ${POLICY_NAME}-namespace-writer
---
apiVersion: ops.sentinelops.io/v1alpha1
kind: SentinelAdmissionGuard
metadata:
  name: ${POLICY_NAME}
  namespace: ${NAMESPACE}
spec:
  allowedPolicyManagers:
    - ${PLATFORM_ADMIN_USER}
  allowedDeploymentWriters:
    - ${CONTROLLER_USER}
  allowedRemediationCreators:
    - ${EXECUTOR_USER}
  allowedRemediationStatusWriters:
    - ${CONTROLLER_USER}
  allowedRemediationDeleters:
    - ${GC_USER}
YAML

sed \
  -e "s/sentinelops-workload-write-fence/${POLICY_NAME}/g" \
  -e "s/sentinelops-admission-governance/${POLICY_NAME}-governance/g" \
  -e "s/namespace: sentinelops-workloads/namespace: ${NAMESPACE}/g" \
  -e "s/sentinelops.io\\/admission-protected/sentinelops.io\\/admission-e2e-protected/g" \
  "${ROOT_DIR}/deploy/production/admission/workload-write-fence.yaml" \
  | kubectl apply -f -
kubectl wait \
  --for=jsonpath='{.status.observedGeneration}'=1 \
  "validatingadmissionpolicy/${POLICY_NAME}" \
  --timeout=60s
kubectl wait \
  --for=jsonpath='{.status.observedGeneration}'=1 \
  "validatingadmissionpolicy/${POLICY_NAME}-governance" \
  --timeout=60s

warnings="$(
  kubectl get validatingadmissionpolicy "${POLICY_NAME}" \
    -o jsonpath='{.status.typeChecking.expressionWarnings}'
)"
[[ -z "${warnings}" || "${warnings}" == "[]" ]]
governance_warnings="$(
  kubectl get validatingadmissionpolicy "${POLICY_NAME}-governance" \
    -o jsonpath='{.status.typeChecking.expressionWarnings}'
)"
[[ -z "${governance_warnings}" || "${governance_warnings}" == "[]" ]]

kubectl label namespace "${NAMESPACE}" \
  sentinelops.io/admission-audit=true \
  --overwrite
sleep 2

kubectl auth can-i update deployments \
  --as "${INTRUDER_USER}" \
  --namespace "${NAMESPACE}" \
  | grep --quiet '^yes$'

set +e
audit_output="$(
  kubectl patch deployment admission-target \
    --namespace "${NAMESPACE}" \
    --type merge \
    --patch '{"metadata":{"annotations":{"sentinelops.io/audit-write":"true"}}}' \
    --as "${INTRUDER_USER}" 2>&1
)"
audit_status=$?
set -e
[[ "${audit_status}" -eq 0 ]]
grep --quiet "Warning.*protected Deployment writes" <<<"${audit_output}"

set +e
intruder_guard_output="$(
  kubectl patch sentineladmissionguard "${POLICY_NAME}" \
    --namespace "${NAMESPACE}" \
    --type merge \
    --patch '{"metadata":{"annotations":{"sentinelops.io/intruder":"true"}}}' \
    --as "${INTRUDER_USER}" 2>&1
)"
intruder_guard_status=$?
set -e
[[ "${intruder_guard_status}" -ne 0 ]]
grep --quiet "changes require an explicitly allowed policy manager" \
  <<<"${intruder_guard_output}"

kubectl patch sentineladmissionguard "${POLICY_NAME}" \
  --namespace "${NAMESPACE}" \
  --type merge \
  --patch '{"metadata":{"annotations":{"sentinelops.io/managed":"true"}}}' \
  --as "${PLATFORM_ADMIN_USER}"

kubectl label namespace "${NAMESPACE}" \
  sentinelops.io/admission-audit- \
  --overwrite
kubectl label namespace "${NAMESPACE}" \
  sentinelops.io/admission-e2e-protected=true \
  --overwrite \
  --as "${PLATFORM_ADMIN_USER}"
sleep 2

set +e
intruder_label_output="$(
  kubectl label namespace "${NAMESPACE}" \
    sentinelops.io/admission-e2e-protected- \
    --as "${INTRUDER_USER}" 2>&1
)"
intruder_label_status=$?
set -e
[[ "${intruder_label_status}" -ne 0 ]]
grep --quiet "enforcement label can only be changed" \
  <<<"${intruder_label_output}"

kubectl patch deployment admission-target \
  --namespace "${NAMESPACE}" \
  --type merge \
  --patch '{"metadata":{"annotations":{"sentinelops.io/allowed-write":"true"}}}' \
  --as "${CONTROLLER_USER}"

set +e
intruder_deployment_output="$(
  kubectl patch deployment admission-target \
    --namespace "${NAMESPACE}" \
    --type merge \
    --patch '{"metadata":{"annotations":{"sentinelops.io/intruder-write":"true"}}}' \
    --as "${INTRUDER_USER}" 2>&1
)"
intruder_deployment_status=$?
set -e
[[ "${intruder_deployment_status}" -ne 0 ]]
grep --quiet "protected Deployment writes" \
  <<<"${intruder_deployment_output}"

kubectl create --as "${EXECUTOR_USER}" -f - <<YAML
apiVersion: ops.sentinelops.io/v1alpha1
kind: SentinelRemediation
metadata:
  name: ${ACTION_ID}
  namespace: ${NAMESPACE}
spec:
  actionId: ${ACTION_ID}
  incidentId: admission-e2e
  action:
    plugin: restart_deployment
    catalogDigest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    parameters:
      name: admission-target
  target:
    apiVersion: apps/v1
    kind: Deployment
    clusterId: local-kind
    namespace: ${NAMESPACE}
    name: admission-target
    uid: admission-test-deployment-uid
  precondition:
    clusterId: local-kind
    snapshotDigest: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    resourceVersion: "1"
    generation: 1
    desiredReplicas: 1
    paused: false
    currentRevision: 1
    currentReplicaSetUid: admission-test-replicaset-uid
    currentTemplateHash: admission-test-template-hash
    capturedAt: "2026-01-01T00:00:00Z"
  authorization:
    decision: risk_policy
    policyDigest: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  fence:
    generation: 1
    expiresAt: "2099-01-01T00:00:00Z"
YAML

set +e
intruder_contract_output="$(
  kubectl create --as "${INTRUDER_USER}" -f - 2>&1 <<YAML
apiVersion: ops.sentinelops.io/v1alpha1
kind: SentinelRemediation
metadata:
  name: ${INTRUDER_ACTION_ID}
  namespace: ${NAMESPACE}
spec:
  actionId: ${INTRUDER_ACTION_ID}
  incidentId: admission-e2e-intruder
  action:
    plugin: restart_deployment
    catalogDigest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    parameters:
      name: admission-target
  target:
    apiVersion: apps/v1
    kind: Deployment
    clusterId: local-kind
    namespace: ${NAMESPACE}
    name: admission-target
    uid: admission-test-deployment-uid
  precondition:
    clusterId: local-kind
    snapshotDigest: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    resourceVersion: "1"
    generation: 1
    desiredReplicas: 1
    paused: false
    currentRevision: 1
    currentReplicaSetUid: admission-test-replicaset-uid
    currentTemplateHash: admission-test-template-hash
    capturedAt: "2026-01-01T00:00:00Z"
  authorization:
    decision: risk_policy
    policyDigest: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  fence:
    generation: 1
    expiresAt: "2099-01-01T00:00:00Z"
YAML
)"
intruder_contract_status=$?
set -e
[[ "${intruder_contract_status}" -ne 0 ]]
grep --quiet "contracts can only be created" \
  <<<"${intruder_contract_output}"

kubectl patch sentinelremediation "${ACTION_ID}" \
  --namespace "${NAMESPACE}" \
  --subresource status \
  --type merge \
  --patch '{"status":{"phase":"Pending","observedGeneration":1}}' \
  --as "${CONTROLLER_USER}"

set +e
executor_status_output="$(
  kubectl patch sentinelremediation "${ACTION_ID}" \
    --namespace "${NAMESPACE}" \
    --subresource status \
    --type merge \
    --patch '{"status":{"phase":"Executing","observedGeneration":1}}' \
    --as "${EXECUTOR_USER}" 2>&1
)"
executor_status=$?
set -e
[[ "${executor_status}" -ne 0 ]]
grep --quiet "status can only be written" \
  <<<"${executor_status_output}"

set +e
executor_delete_output="$(
  kubectl delete sentinelremediation "${ACTION_ID}" \
    --namespace "${NAMESPACE}" \
    --as "${EXECUTOR_USER}" 2>&1
)"
executor_delete_status=$?
set -e
[[ "${executor_delete_status}" -ne 0 ]]
grep --quiet "deletion requires" <<<"${executor_delete_output}"

kubectl delete sentinelremediation "${ACTION_ID}" \
  --namespace "${NAMESPACE}" \
  --as "${GC_USER}" \
  --wait=true

echo "Admission fence E2E passed: RBAC-authorized intruders were denied."
