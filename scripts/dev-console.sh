#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_PID=""

cleanup() {
  if [[ -n "${API_PID}" ]]; then
    kill "${API_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [[ ! -d "${ROOT_DIR}/web/node_modules" ]]; then
  npm --prefix "${ROOT_DIR}/web" install
fi

python -m sentinelops serve --host "${SENTINELOPS_API_HOST:-127.0.0.1}" --port 8000 &
API_PID=$!

echo "SentinelOps Console: http://127.0.0.1:5173"
npm --prefix "${ROOT_DIR}/web" run dev -- --host 127.0.0.1
