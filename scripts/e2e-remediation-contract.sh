#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${SENTINELOPS_CONTRACT_TEST_NAMESPACE:-sentinelops-contract-e2e}"
ACTION_ID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CREATED_NAMESPACE=false

if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
  kubectl create namespace "${NAMESPACE}"
  CREATED_NAMESPACE=true
fi

cleanup() {
  kubectl delete sentinelremediation "${ACTION_ID}" \
    --namespace "${NAMESPACE}" \
    --ignore-not-found \
    --wait=true >/dev/null
  if [[ "${CREATED_NAMESPACE}" == "true" ]]; then
    kubectl delete namespace "${NAMESPACE}" --wait=true >/dev/null
  fi
}
trap cleanup EXIT

kubectl apply \
  -f "${ROOT_DIR}/deploy/production/crds/sentinelremediations.yaml"

kubectl apply -f - <<YAML
apiVersion: ops.sentinelops.io/v1alpha1
kind: SentinelRemediation
metadata:
  name: ${ACTION_ID}
  namespace: ${NAMESPACE}
spec:
  actionId: ${ACTION_ID}
  incidentId: contract-e2e
  action:
    plugin: restart_deployment
    catalogDigest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    parameters:
      name: inventory-service
  target:
    apiVersion: apps/v1
    kind: Deployment
    clusterId: local-kind
    namespace: ${NAMESPACE}
    name: inventory-service
    uid: contract-test-deployment-uid
  precondition:
    clusterId: local-kind
    snapshotDigest: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    resourceVersion: "1"
    generation: 1
    desiredReplicas: 1
    paused: false
    currentRevision: 1
    currentReplicaSetUid: contract-test-replicaset-uid
    currentTemplateHash: contract-test-template-hash
    capturedAt: "2026-01-01T00:00:00Z"
  authorization:
    decision: risk_policy
    policyDigest: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  fence:
    generation: 1
    expiresAt: "2099-01-01T00:00:00Z"
YAML

if kubectl patch sentinelremediation "${ACTION_ID}" \
  --namespace "${NAMESPACE}" \
  --type merge \
  --patch '{"spec":{"incidentId":"tampered"}}'; then
  echo "Expected the API server to reject an immutable spec update" >&2
  exit 1
fi

kubectl patch sentinelremediation "${ACTION_ID}" \
  --namespace "${NAMESPACE}" \
  --subresource status \
  --type merge \
  --patch '{"status":{"phase":"Succeeded","observedGeneration":1}}'

if kubectl patch sentinelremediation "${ACTION_ID}" \
  --namespace "${NAMESPACE}" \
  --subresource status \
  --type merge \
  --patch '{"status":{"phase":"Failed","observedGeneration":1}}'; then
  echo "Expected the API server to preserve a terminal remediation phase" >&2
  exit 1
fi

if kubectl patch sentinelremediation "${ACTION_ID}" \
  --namespace "${NAMESPACE}" \
  --subresource status \
  --type merge \
  --patch '{"status":{"phase":"Succeeded","observedGeneration":1,"reason":"mutated"}}'; then
  echo "Expected the API server to freeze the complete terminal status" >&2
  exit 1
fi

cleanup
trap - EXIT
