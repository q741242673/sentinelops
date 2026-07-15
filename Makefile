.PHONY: install test lint eval demo serve

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

