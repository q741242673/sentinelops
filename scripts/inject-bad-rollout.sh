#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

kubectl patch deployment order-service \
  --namespace sentinelops-demo \
  --type strategic \
  --patch-file "${ROOT_DIR}/deploy/kind/faults/bad-rollout-patch.yaml"

for _ in $(seq 1 60); do
  reasons="$(
    kubectl get pods \
      --namespace sentinelops-demo \
      --selector app=order-service \
      --output jsonpath='{range .items[*].status.containerStatuses[*].state.waiting}{.reason}{"\n"}{end}'
  )"
  case "${reasons}" in
    *CrashLoopBackOff* | *Error*)
      echo "Injected bad rollout; unhealthy pod is observable"
      exit 0
      ;;
  esac
  sleep 2
done

echo "Timed out waiting for the bad rollout to become observable" >&2
kubectl get pods --namespace sentinelops-demo --selector app=order-service -o wide >&2
exit 1

