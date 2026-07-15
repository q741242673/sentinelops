#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${SENTINELOPS_KIND_CLUSTER:-sentinelops}"
kind delete cluster --name "${CLUSTER_NAME}"

