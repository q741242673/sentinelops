#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${SENTINELOPS_OBSERVABILITY_CLUSTER:-sentinelops-observability}"
CONTEXT="kind-${CLUSTER_NAME}"
IMAGE="sentinelops:topology-e2e"
POSTGRES_IMAGE="postgres:16-alpine"
CONTROL_PLANE_CHAOS="${SENTINELOPS_CONTROL_PLANE_CHAOS:-false}"
SECURITY_E2E="${SENTINELOPS_SECURITY_E2E:-false}"
DEFAULT_REPORT="${ROOT_DIR}/benchmarks/topology-readiness.json"
if [[ "${CONTROL_PLANE_CHAOS}" == "true" ]]; then
  DEFAULT_REPORT="${ROOT_DIR}/benchmarks/control-plane-chaos.json"
fi
if [[ "${SECURITY_E2E}" == "true" ]]; then
  DEFAULT_REPORT="${ROOT_DIR}/benchmarks/security-readiness.json"
fi
if [[ "${CONTROL_PLANE_CHAOS}" == "true" && "${SECURITY_E2E}" == "true" ]]; then
  echo "Control-plane chaos and security E2E must run separately" >&2
  exit 2
fi
OUTPUT="${SENTINELOPS_TOPOLOGY_READINESS_OUTPUT:-${DEFAULT_REPORT}}"
PYTHON="${PYTHON:-python}"
PORT_FORWARD_PIDS=""
TEMP_ROOT=""
CHAOS_ARGS=()
SECURITY_ARGS=()
if [[ "${CONTROL_PLANE_CHAOS}" == "true" ]]; then
  CHAOS_ARGS+=(--control-plane-chaos)
fi
if [[ "${SECURITY_E2E}" == "true" ]]; then
  SECURITY_ARGS+=(
    --security-e2e
    --anchor-gate-started-blocked
    --anchor-outage-failed-closed
  )
fi

diagnose() {
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    get pods --output wide || true
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    logs deployment/sentinelops-api --all-pods --all-containers --tail=200 || true
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    logs deployment/sentinelops-executor --all-pods --all-containers --tail=200 || true
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    logs deployment/postgres --all-containers --tail=100 || true
  if [[ "${SECURITY_E2E}" == "true" ]]; then
    kubectl --context "${CONTEXT}" --namespace sentinelops-system \
      logs deployment/sentinelops-anchor-publisher \
      --all-pods --all-containers --tail=200 || true
    kubectl --context "${CONTEXT}" --namespace sentinelops-security \
      get pods --output wide || true
    kubectl --context "${CONTEXT}" --namespace sentinelops-security \
      logs deployment/anchor-service --all-containers --tail=200 || true
  fi
  kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
    logs deployment/alertmanager --all-containers --tail=100 || true
}

cleanup() {
  local status="$1"
  for pid in ${PORT_FORWARD_PIDS}; do
    kill "${pid}" 2>/dev/null || true
  done
  if [[ -n "${TEMP_ROOT}" ]]; then
    rm -rf "${TEMP_ROOT}"
  fi
  if [[ "${status}" -ne 0 ]]; then
    diagnose
  fi
  if [[ "${SENTINELOPS_KEEP_OBSERVABILITY_CLUSTER:-false}" != "true" ]]; then
    "${ROOT_DIR}/scripts/observability-down.sh"
  fi
}

on_exit() {
  local status=$?
  trap - EXIT
  cleanup "${status}"
  exit "${status}"
}
trap on_exit EXIT

wait_for_url() {
  local url="$1"
  for _ in $(seq 1 90); do
    if curl --noproxy "*" --fail --silent --show-error "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for ${url}" >&2
  return 1
}

start_port_forward() {
  local namespace="$1"
  local resource="$2"
  local ports="$3"
  kubectl --context "${CONTEXT}" --namespace "${namespace}" \
    port-forward "${resource}" "${ports}" >/dev/null 2>&1 &
  PORT_FORWARD_PIDS="${PORT_FORWARD_PIDS} $!"
}

"${ROOT_DIR}/scripts/observability-up.sh"

docker build --tag "${IMAGE}" "${ROOT_DIR}"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"
NODE_CONTAINER="${CLUSTER_NAME}-control-plane"
case "$(docker exec "${NODE_CONTAINER}" uname -m)" in
  aarch64) NODE_PLATFORM="linux/arm64" ;;
  x86_64) NODE_PLATFORM="linux/amd64" ;;
  *) echo "Unsupported kind node architecture" >&2; exit 1 ;;
esac
docker pull --platform "${NODE_PLATFORM}" "${POSTGRES_IMAGE}"
docker save "${POSTGRES_IMAGE}" |
  docker exec --privileged -i "${NODE_CONTAINER}" \
    ctr --namespace=k8s.io images import \
    --platform "${NODE_PLATFORM}" --digests --snapshotter=overlayfs -

kubectl --context "${CONTEXT}" \
  delete namespace/sentinelops-system --ignore-not-found --wait=true
kubectl --context "${CONTEXT}" apply \
  --filename "${ROOT_DIR}/deploy/topology-e2e/base.yaml"

if [[ "${SECURITY_E2E}" == "true" ]]; then
  TEMP_ROOT="$(mktemp -d)"
  "${PYTHON}" "${ROOT_DIR}/scripts/generate_security_e2e_material.py" \
    --output-dir "${TEMP_ROOT}/material"
fi

POSTGRES_PASSWORD="$("${PYTHON}" -c 'import secrets; print(secrets.token_hex(24))')"
AUDIT_HMAC_KEY="$("${PYTHON}" -c 'import secrets; print(secrets.token_hex(32))')"
WEBHOOK_TOKEN="$("${PYTHON}" -c 'import secrets; print(secrets.token_hex(32))')"
DATABASE_URL="postgresql+asyncpg://sentinelops:${POSTGRES_PASSWORD}@postgres.sentinelops-system.svc.cluster.local:5432/sentinelops"

TOPOLOGY_SECRET_ARGS=(
  create secret generic sentinelops-topology-secrets
  --from-literal=postgres-user=sentinelops \
  --from-literal="postgres-password=${POSTGRES_PASSWORD}" \
  --from-literal=postgres-database=sentinelops \
  --from-literal="database-url=${DATABASE_URL}" \
  --from-literal="audit-hmac-key=${AUDIT_HMAC_KEY}" \
  --from-literal="webhook-bearer-token=${WEBHOOK_TOKEN}"
)
if [[ "${SECURITY_E2E}" == "true" ]]; then
  TOPOLOGY_SECRET_ARGS+=(
    --from-file="audit-anchor-token=${TEMP_ROOT}/material/anchor-delivery.token"
    --from-file="audit-anchor-reconcile-token=${TEMP_ROOT}/material/anchor-inventory.token"
  )
fi
kubectl --context "${CONTEXT}" --namespace sentinelops-system \
  "${TOPOLOGY_SECRET_ARGS[@]}" --dry-run=client --output=yaml |
  kubectl --context "${CONTEXT}" apply --filename -

kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  create secret generic sentinelops-topology-webhook \
  --from-literal="token=${WEBHOOK_TOKEN}" \
  --dry-run=client --output=yaml |
  kubectl --context "${CONTEXT}" apply --filename -

if [[ "${SECURITY_E2E}" == "true" ]]; then
  kubectl --context "${CONTEXT}" \
    delete namespace/sentinelops-security --ignore-not-found --wait=true
  kubectl --context "${CONTEXT}" \
    create namespace sentinelops-security \
    --dry-run=client --output=yaml |
    kubectl --context "${CONTEXT}" apply --filename -

  ANCHOR_POSTGRES_PASSWORD="$("${PYTHON}" -c 'import secrets; print(secrets.token_hex(24))')"
  ANCHOR_DATABASE_URL="postgresql+asyncpg://sentinelops_anchor:${ANCHOR_POSTGRES_PASSWORD}@anchor-postgres.sentinelops-security.svc.cluster.local:5432/sentinelops_anchor"
  kubectl --context "${CONTEXT}" --namespace sentinelops-security \
    create secret generic sentinelops-security-secrets \
    --from-literal=postgres-user=sentinelops_anchor \
    --from-literal="postgres-password=${ANCHOR_POSTGRES_PASSWORD}" \
    --from-literal=postgres-database=sentinelops_anchor \
    --from-literal="database-url=${ANCHOR_DATABASE_URL}" \
    --from-file="anchor-delivery-token=${TEMP_ROOT}/material/anchor-delivery.token" \
    --from-file="anchor-inventory-token=${TEMP_ROOT}/material/anchor-inventory.token" \
    --from-file="anchor-private.pem=${TEMP_ROOT}/material/anchor-private.pem" \
    --dry-run=client --output=yaml |
    kubectl --context "${CONTEXT}" apply --filename -
  kubectl --context "${CONTEXT}" --namespace sentinelops-security \
    create configmap sentinelops-security-jwks \
    --from-file="jwks.json=${TEMP_ROOT}/material/jwks.json" \
    --dry-run=client --output=yaml |
    kubectl --context "${CONTEXT}" apply --filename -
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    create configmap sentinelops-topology-anchor-public-keys \
    --from-file="receipt-public-keys.json=${TEMP_ROOT}/material/anchor-public-keys.json" \
    --dry-run=client --output=yaml |
    kubectl --context "${CONTEXT}" apply --filename -
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    patch configmap sentinelops-topology-runtime --type=merge \
    --patch-file "${ROOT_DIR}/deploy/security-e2e/runtime-patch.yaml"
  kubectl --context "${CONTEXT}" apply \
    --filename "${ROOT_DIR}/deploy/security-e2e/services.yaml"
  for deployment in anchor-postgres oidc-jwks anchor-service; do
    kubectl --context "${CONTEXT}" --namespace sentinelops-security \
      rollout status "deployment/${deployment}" --timeout=5m
  done
  unset ANCHOR_POSTGRES_PASSWORD ANCHOR_DATABASE_URL
fi

unset POSTGRES_PASSWORD AUDIT_HMAC_KEY WEBHOOK_TOKEN DATABASE_URL

kubectl --context "${CONTEXT}" --namespace sentinelops-system \
  rollout status deployment/postgres --timeout=3m

kubectl --context "${CONTEXT}" --namespace sentinelops-system \
  delete job/sentinelops-topology-migrate --ignore-not-found
kubectl --context "${CONTEXT}" apply \
  --filename "${ROOT_DIR}/deploy/topology-e2e/migration.yaml"
if ! kubectl --context "${CONTEXT}" --namespace sentinelops-system \
  wait --for=condition=complete job/sentinelops-topology-migrate --timeout=5m; then
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    logs job/sentinelops-topology-migrate --all-containers || true
  exit 1
fi

kubectl --context "${CONTEXT}" apply \
  --filename "${ROOT_DIR}/deploy/topology-e2e/control-plane.yaml"
if [[ "${SECURITY_E2E}" == "true" ]]; then
  for deployment in sentinelops-api sentinelops-executor; do
    kubectl --context "${CONTEXT}" --namespace sentinelops-system \
      rollout status "deployment/${deployment}" --timeout=5m
  done
  SECURITY_STATE="$(
    kubectl --context "${CONTEXT}" --namespace sentinelops-system \
      exec deployment/postgres -- \
      psql --username sentinelops --dbname sentinelops \
      --tuples-only --no-align \
      --command="SELECT status || ':' || write_blocked::text FROM sentinelops_audit_anchor_security_state WHERE scope_id='external-audit-anchor';"
  )"
  if [[ "${SECURITY_STATE//[[:space:]]/}" != "initializing:1" ]]; then
    echo "Expected audit anchor gate to start blocked, got ${SECURITY_STATE}" >&2
    exit 1
  fi
  kubectl --context "${CONTEXT}" apply \
    --filename "${ROOT_DIR}/deploy/security-e2e/anchor-publisher.yaml"
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    rollout status deployment/sentinelops-anchor-publisher --timeout=5m
  for _ in $(seq 1 90); do
    SECURITY_STATE="$(
      kubectl --context "${CONTEXT}" --namespace sentinelops-system \
        exec deployment/postgres -- \
        psql --username sentinelops --dbname sentinelops \
        --tuples-only --no-align \
        --command="SELECT status || ':' || write_blocked::text FROM sentinelops_audit_anchor_security_state WHERE scope_id='external-audit-anchor';"
    )"
    if [[ "${SECURITY_STATE//[[:space:]]/}" == "healthy:0" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "${SECURITY_STATE//[[:space:]]/}" != "healthy:0" ]]; then
    echo "Audit anchor gate did not become healthy: ${SECURITY_STATE}" >&2
    exit 1
  fi
  kubectl --context "${CONTEXT}" --namespace sentinelops-security \
    scale deployment/anchor-service --replicas=0
  kubectl --context "${CONTEXT}" --namespace sentinelops-security \
    rollout status deployment/anchor-service --timeout=2m
  for _ in $(seq 1 50); do
    SECURITY_STATE="$(
      kubectl --context "${CONTEXT}" --namespace sentinelops-system \
        exec deployment/postgres -- \
        psql --username sentinelops --dbname sentinelops \
        --tuples-only --no-align \
        --command="SELECT status || ':' || write_blocked::text FROM sentinelops_audit_anchor_security_state WHERE scope_id='external-audit-anchor';"
    )"
    if [[ "${SECURITY_STATE//[[:space:]]/}" == "degraded:1" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "${SECURITY_STATE//[[:space:]]/}" != "degraded:1" ]]; then
    echo "Audit anchor outage did not close the write gate: ${SECURITY_STATE}" >&2
    exit 1
  fi
  kubectl --context "${CONTEXT}" --namespace sentinelops-security \
    scale deployment/anchor-service --replicas=1
  kubectl --context "${CONTEXT}" --namespace sentinelops-security \
    rollout status deployment/anchor-service --timeout=5m
  for _ in $(seq 1 90); do
    SECURITY_STATE="$(
      kubectl --context "${CONTEXT}" --namespace sentinelops-system \
        exec deployment/postgres -- \
        psql --username sentinelops --dbname sentinelops \
        --tuples-only --no-align \
        --command="SELECT status || ':' || write_blocked::text FROM sentinelops_audit_anchor_security_state WHERE scope_id='external-audit-anchor';"
    )"
    if [[ "${SECURITY_STATE//[[:space:]]/}" == "healthy:0" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "${SECURITY_STATE//[[:space:]]/}" != "healthy:0" ]]; then
    echo "Audit anchor gate did not reopen after reconciliation: ${SECURITY_STATE}" >&2
    exit 1
  fi
fi
kubectl --context "${CONTEXT}" apply \
  --filename "${ROOT_DIR}/deploy/topology-e2e/alertmanager-config.yaml"
kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  patch deployment/alertmanager --type=strategic \
  --patch-file "${ROOT_DIR}/deploy/topology-e2e/alertmanager-patch.yaml"
kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  rollout restart deployment/alertmanager

for deployment in sentinelops-api sentinelops-executor; do
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    rollout status "deployment/${deployment}" --timeout=5m
done
kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
  rollout status deployment/alertmanager --timeout=3m

API_PODS_RAW="$(
  kubectl --context "${CONTEXT}" --namespace sentinelops-system \
    get pods \
    --selector app.kubernetes.io/name=sentinelops-api \
    --field-selector status.phase=Running \
    --output jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' |
    sort
)"
read -r -a API_PODS <<< "${API_PODS_RAW//$'\n'/ }"
if [[ "${#API_PODS[@]}" -ne 2 ]]; then
  echo "Expected two running API pods, got ${#API_PODS[@]}" >&2
  exit 1
fi

start_port_forward sentinelops-demo service/order-service 18080:8000
start_port_forward sentinelops-demo service/prometheus 19090:9090
start_port_forward sentinelops-system "pod/${API_PODS[0]}" 18100:8000
start_port_forward sentinelops-system "pod/${API_PODS[1]}" 18101:8000
if [[ "${SECURITY_E2E}" == "true" ]]; then
  start_port_forward sentinelops-security service/anchor-service 18200:8010
fi

wait_for_url http://127.0.0.1:18080/healthz
wait_for_url http://127.0.0.1:19090/-/ready
wait_for_url http://127.0.0.1:18100/ready
wait_for_url http://127.0.0.1:18101/ready
if [[ "${SECURITY_E2E}" == "true" ]]; then
  wait_for_url http://127.0.0.1:18200/health
  SECURITY_ARGS+=(
    --viewer-token-file "${TEMP_ROOT}/material/viewer.jwt"
    --approver-token-file "${TEMP_ROOT}/material/approver.jwt"
    --invalid-token-file "${TEMP_ROOT}/material/invalid.jwt"
    --anchor-url http://127.0.0.1:18200
    --anchor-inventory-token-file "${TEMP_ROOT}/material/anchor-inventory.token"
    --anchor-public-keys-file "${TEMP_ROOT}/material/anchor-public-keys.json"
  )
fi

READINESS_ARGS=(
  --context "${CONTEXT}" \
  --api-url http://127.0.0.1:18100 \
  --api-url http://127.0.0.1:18101 \
  --output "${OUTPUT}"
)
if [[ "${CONTROL_PLANE_CHAOS}" == "true" ]]; then
  READINESS_ARGS+=("${CHAOS_ARGS[@]}")
fi
if [[ "${SECURITY_E2E}" == "true" ]]; then
  READINESS_ARGS+=("${SECURITY_ARGS[@]}")
fi
"${PYTHON}" "${ROOT_DIR}/scripts/topology_readiness.py" \
  "${READINESS_ARGS[@]}"
