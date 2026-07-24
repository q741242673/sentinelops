#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${SENTINELOPS_OBSERVABILITY_CLUSTER:-sentinelops-observability}"
CONTEXT="kind-${CLUSTER_NAME}"
ROUNDS="${SENTINELOPS_KUBERNETES_READINESS_ROUNDS:-3}"
OUTPUT="${SENTINELOPS_KUBERNETES_READINESS_OUTPUT:-${ROOT_DIR}/benchmarks/kubernetes-readiness.json}"
PYTHON="${PYTHON:-python}"
PORT_FORWARD_PIDS=""

cleanup() {
  for pid in ${PORT_FORWARD_PIDS}; do
    kill "${pid}" 2>/dev/null || true
  done
  if [[ "${SENTINELOPS_KEEP_OBSERVABILITY_CLUSTER:-false}" != "true" ]]; then
    "${ROOT_DIR}/scripts/observability-down.sh"
  fi
}
trap cleanup EXIT

wait_for_url() {
  local url="$1"
  for _ in $(seq 1 60); do
    if curl --noproxy "*" --fail --silent --show-error "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for ${url}" >&2
  return 1
}

start_port_forward() {
  local resource="$1"
  local ports="$2"
  kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
    port-forward "${resource}" "${ports}" >/dev/null 2>&1 &
  PORT_FORWARD_PIDS="${PORT_FORWARD_PIDS} $!"
}

"${ROOT_DIR}/scripts/observability-up.sh"

start_port_forward service/order-service 18080:8000
start_port_forward service/prometheus 19090:9090
start_port_forward service/loki 13100:3100
start_port_forward service/tempo 13200:3200

wait_for_url http://127.0.0.1:18080/healthz
wait_for_url http://127.0.0.1:19090/-/ready
wait_for_url http://127.0.0.1:13100/ready
wait_for_url http://127.0.0.1:13200/ready

export SENTINELOPS_TOOL_BACKEND=kubernetes
export SENTINELOPS_MODEL_PROVIDER="${SENTINELOPS_MODEL_PROVIDER:-rule_based}"
export SENTINELOPS_KUBERNETES_NAMESPACE=sentinelops-demo
export SENTINELOPS_PROMETHEUS_URL=http://127.0.0.1:19090
export SENTINELOPS_LOKI_URL=http://127.0.0.1:13100
export SENTINELOPS_TEMPO_URL=http://127.0.0.1:13200
export SENTINELOPS_VERIFICATION_PROBE_URL=http://127.0.0.1:18080
export SENTINELOPS_CHANGE_REPOSITORY_PATH="${ROOT_DIR}"

"${PYTHON}" "${ROOT_DIR}/scripts/kubernetes_readiness.py" \
  --context "${CONTEXT}" \
  --rounds "${ROUNDS}" \
  --output "${OUTPUT}"
