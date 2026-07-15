.PHONY: install test lint eval demo serve kind-up kind-fault kind-e2e kind-down \
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

demo:
	sentinelops demo --scenario bad_rollout --approve

serve:
	sentinelops serve

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
