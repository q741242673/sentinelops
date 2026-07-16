#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${SENTINELOPS_OBSERVABILITY_CLUSTER:-sentinelops-observability}"
CONTEXT="kind-${CLUSTER_NAME}"
ORDER_PORT="${SENTINELOPS_LIVE_ORDER_PORT:-28080}"
INVENTORY_PORT="${SENTINELOPS_LIVE_INVENTORY_PORT:-28081}"
PROMETHEUS_PORT="${SENTINELOPS_LIVE_PROMETHEUS_PORT:-29090}"
LOKI_PORT="${SENTINELOPS_LIVE_LOKI_PORT:-23100}"
TEMPO_PORT="${SENTINELOPS_LIVE_TEMPO_PORT:-23200}"
ALERTMANAGER_PORT="${SENTINELOPS_LIVE_ALERTMANAGER_PORT:-29093}"
PORT_FORWARD_PIDS=""
TRAFFIC_PID=""

cleanup() {
  if [[ -n "${TRAFFIC_PID}" ]]; then
    kill "${TRAFFIC_PID}" 2>/dev/null || true
  fi
  for pid in ${PORT_FORWARD_PIDS}; do
    kill "${pid}" 2>/dev/null || true
  done
  if [[ "${SENTINELOPS_KEEP_LIVE_CLUSTER:-true}" != "true" ]]; then
    "${ROOT_DIR}/scripts/observability-down.sh"
  fi
}
trap cleanup EXIT INT TERM

wait_for_url() {
  local url="$1"
  for _ in $(seq 1 90); do
    if curl --noproxy '*' --fail --silent --show-error "${url}" >/dev/null 2>&1; then
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
  (
    child_pid=""

    stop_port_forward() {
      trap - EXIT INT TERM
      if [[ -n "${child_pid}" ]]; then
        kill "${child_pid}" 2>/dev/null || true
        wait "${child_pid}" 2>/dev/null || true
      fi
      exit 0
    }

    trap stop_port_forward EXIT INT TERM
    while true; do
      kubectl --context "${CONTEXT}" --namespace sentinelops-demo \
        port-forward "${resource}" "${ports}" >/dev/null 2>&1 &
      child_pid=$!
      wait "${child_pid}" || true
      child_pid=""
      sleep 1
    done
  ) &
  PORT_FORWARD_PIDS="${PORT_FORWARD_PIDS} $!"
}

"${ROOT_DIR}/scripts/observability-up.sh"

start_port_forward service/order-service "${ORDER_PORT}:8000"
start_port_forward service/inventory-service "${INVENTORY_PORT}:8000"
start_port_forward service/prometheus "${PROMETHEUS_PORT}:9090"
start_port_forward service/loki "${LOKI_PORT}:3100"
start_port_forward service/tempo "${TEMPO_PORT}:3200"
start_port_forward service/alertmanager "${ALERTMANAGER_PORT}:9093"

wait_for_url "http://127.0.0.1:${ORDER_PORT}/healthz"
wait_for_url "http://127.0.0.1:${INVENTORY_PORT}/healthz"
wait_for_url "http://127.0.0.1:${PROMETHEUS_PORT}/-/ready"
wait_for_url "http://127.0.0.1:${LOKI_PORT}/ready"
wait_for_url "http://127.0.0.1:${TEMPO_PORT}/ready"
wait_for_url "http://127.0.0.1:${ALERTMANAGER_PORT}/-/ready"

python "${ROOT_DIR}/scripts/live_console_traffic.py" \
  --order-url "http://127.0.0.1:${ORDER_PORT}" &
TRAFFIC_PID=$!

export SENTINELOPS_TOOL_BACKEND=kubernetes
export SENTINELOPS_MODEL_PROVIDER="${SENTINELOPS_MODEL_PROVIDER:-openai_compatible}"
export SENTINELOPS_MODEL_NAME="${SENTINELOPS_MODEL_NAME:-deepseek-chat}"
export SENTINELOPS_MODEL_BASE_URL="${SENTINELOPS_MODEL_BASE_URL:-https://api.deepseek.com}"
export SENTINELOPS_KUBERNETES_NAMESPACE=sentinelops-demo
export SENTINELOPS_DEMO_ORDER_URL="http://127.0.0.1:${ORDER_PORT}"
export SENTINELOPS_DEMO_INVENTORY_URL="http://127.0.0.1:${INVENTORY_PORT}"
export SENTINELOPS_PROMETHEUS_URL="http://127.0.0.1:${PROMETHEUS_PORT}"
export SENTINELOPS_LOKI_URL="http://127.0.0.1:${LOKI_PORT}"
export SENTINELOPS_TEMPO_URL="http://127.0.0.1:${TEMPO_PORT}"
export SENTINELOPS_CHANGE_REPOSITORY_PATH="${ROOT_DIR}"
export SENTINELOPS_API_HOST=0.0.0.0

echo "Live stack ready: kind + Prometheus + Alertmanager + Loki + Tempo + ${SENTINELOPS_MODEL_NAME}"
"${ROOT_DIR}/scripts/dev-console.sh"
