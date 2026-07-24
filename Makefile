.PHONY: install test lint eval live-model-eval release-check production-readiness postgres-soak kubernetes-readiness kubernetes-soak soak-gate topology-readiness control-plane-chaos security-readiness demo serve db-init db-check executor console console-live console-live-down console-build kind-up kind-fault kind-e2e kind-down \
	observability-up observability-fault observability-e2e golden-path-e2e \
	observability-down

install:
	python -m pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check .

eval:
	python evals/run.py

live-model-eval:
	python evals/live_run.py $(LIVE_EVAL_ARGS)

release-check:
	python scripts/release_version.py

production-readiness:
	python scripts/production_readiness.py \
		--rounds 10 \
		--concurrency 16 \
		--output benchmarks/production-readiness.json

postgres-soak:
	python scripts/production_readiness.py \
		--rounds 100 \
		--concurrency 16 \
		--output artifacts/postgres-soak.json

kubernetes-readiness:
	scripts/run-kubernetes-readiness.sh

kubernetes-soak:
	SENTINELOPS_KUBERNETES_READINESS_ROUNDS=20 \
	SENTINELOPS_KUBERNETES_READINESS_OUTPUT=artifacts/kubernetes-soak.json \
	scripts/run-kubernetes-readiness.sh

soak-gate:
	python scripts/soak_gate.py \
		--kubernetes-report artifacts/kubernetes-soak.json \
		--postgres-report artifacts/postgres-soak.json \
		--expected-kubernetes-rounds 20 \
		--expected-postgres-rounds 100 \
		--output artifacts/soak-acceptance.json

topology-readiness:
	scripts/e2e-topology.sh

control-plane-chaos:
	SENTINELOPS_CONTROL_PLANE_CHAOS=true scripts/e2e-topology.sh

security-readiness:
	SENTINELOPS_SECURITY_E2E=true scripts/e2e-topology.sh

demo:
	sentinelops demo --scenario bad_rollout --approve

serve:
	sentinelops serve

db-init:
	sentinelops db-init

db-check:
	sentinelops db-check

executor:
	sentinelops executor

console:
	scripts/dev-console.sh

console-live:
	scripts/live-console.sh

console-live-down:
	scripts/observability-down.sh

console-build:
	npm --prefix web install
	npm --prefix web run build

kind-up:
	scripts/kind-up.sh

kind-fault:
	scripts/inject-bad-rollout.sh

kind-e2e:
	scripts/e2e-kind.sh

kind-down:
	scripts/kind-down.sh

observability-up:
	scripts/observability-up.sh

observability-fault:
	scripts/inject-observability-fault.sh

observability-e2e:
	scripts/e2e-observability.sh

golden-path-e2e:
	scripts/e2e-observability.sh

observability-down:
	scripts/observability-down.sh
