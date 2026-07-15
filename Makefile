.PHONY: install test lint eval demo serve kind-up kind-fault kind-e2e kind-down

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

