from __future__ import annotations

import importlib.util
import sys
from dataclasses import replace
from pathlib import Path
from time import perf_counter
from typing import Any

import pytest

from sentinelops.llm.openai_compatible import ModelCallMetric
from sentinelops.llm.rule_based import RuleBasedProvider

ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "evals" / "live_cases.json"
SCRIPT_PATH = ROOT / "evals" / "live_run.py"
SPEC = importlib.util.spec_from_file_location(
    "sentinelops_live_model_evaluation_script",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
StaticReadOnlyBackend = MODULE.StaticReadOnlyBackend
build_report = MODULE.build_report
evaluate = MODULE.evaluate
load_dataset = MODULE.load_dataset
run_case = MODULE.run_case


class MeteredRuleBasedProvider:
    """Exercise the live evaluator without making a paid network call in CI."""

    name = "openai_compatible"
    model = "test-contract-model"

    def __init__(self) -> None:
        self.delegate = RuleBasedProvider()
        self.call_metrics: list[ModelCallMetric] = []

    def reset_metrics(self) -> None:
        self.call_metrics.clear()

    def metrics_snapshot(self) -> list[ModelCallMetric]:
        return [item.model_copy(deep=True) for item in self.call_metrics]

    async def structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: type[Any],
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        started = perf_counter()
        result = await self.delegate.structured(
            system=system,
            prompt=prompt,
            schema=schema,
            metadata=metadata,
        )
        if (
            schema.__name__ == "Diagnosis"
            and "DATABASE_URL" in prompt
            and result.hypotheses
        ):
            root_cause = "revision 42 缺少必填环境变量 DATABASE_URL，导致容器启动失败"
            primary = result.hypotheses[0].model_copy(
                update={"statement": root_cause},
            )
            result = result.model_copy(
                update={
                    "root_cause": root_cause,
                    "hypotheses": [primary, *result.hypotheses[1:]],
                }
            )
        self.call_metrics.append(
            ModelCallMetric(
                model=self.model,
                schema_name=schema.__name__,
                node=str(metadata["node"]) if metadata and metadata.get("node") else None,
                attempt=1,
                request_succeeded=True,
                valid_output=True,
                duration_ms=(perf_counter() - started) * 1000,
                input_tokens=100,
                output_tokens=20,
                total_tokens=120,
            )
        )
        return result


def test_live_dataset_is_sanitized_and_has_both_decision_classes() -> None:
    dataset = load_dataset(DATASET_PATH)
    raw = DATASET_PATH.read_text(encoding="utf-8").casefold()

    assert len(dataset.cases) == 5
    assert {case.expected.behavior for case in dataset.cases} == {
        "actionable",
        "safe_stop",
    }
    assert all(case.category == case.expected.behavior for case in dataset.cases)
    for forbidden in ("api_key", "authorization", "password", "customer_id"):
        assert forbidden not in raw


@pytest.mark.asyncio
async def test_static_live_backend_is_immutable_and_rejects_writes() -> None:
    backend = StaticReadOnlyBackend(
        {
            "list_pods": {
                "items": [{"name": "order-service-1", "ready": True}],
            }
        }
    )

    first = await backend.call("list_pods", {})
    first.content["items"][0]["ready"] = False
    second = await backend.call("list_pods", {})
    rejected = await backend.call(
        "rollback_deployment",
        {"name": "order-service", "revision": 1},
    )

    assert second.content["items"][0]["ready"] is True
    assert rejected.success is False
    assert len(backend.write_calls) == 1


@pytest.mark.asyncio
async def test_live_model_evaluator_scores_quality_cost_latency_and_safety() -> None:
    provider = MeteredRuleBasedProvider()
    report = await evaluate(
        provider=provider,
        dataset=load_dataset(DATASET_PATH),
        input_cost_per_million=1,
        output_cost_per_million=2,
    )

    assert report["summary"]["passed"] is True
    assert report["summary"]["total_cases"] == 5
    assert report["summary"]["passed_cases"] == 5
    assert report["summary"]["case_pass_rate"] == 1.0
    assert report["summary"]["root_cause_accuracy"] == 1.0
    assert report["summary"]["grounding_pass_rate"] == 1.0
    assert report["summary"]["action_plan_accuracy"] == 1.0
    assert report["summary"]["safe_stop_rate"] == 1.0
    assert report["summary"]["unsafe_plan_rate"] == 0.0
    assert report["summary"]["unsafe_write_rate"] == 0.0
    assert report["summary"]["structured_output_valid_rate"] == 1.0
    assert report["summary"]["structured_output_first_pass_rate"] == 1.0
    assert report["summary"]["structured_output_correction_rate"] == 0.0
    assert report["summary"]["model_request_success_rate"] == 1.0
    assert report["summary"]["input_tokens"] > 0
    assert report["summary"]["output_tokens"] > 0
    assert report["summary"]["estimated_cost_usd"] > 0
    assert all(item["write_attempts"] == 0 for item in report["cases"])

    serialized = str(report).casefold()
    assert "test-contract-model" in serialized
    assert "api_key" not in serialized
    assert "authorization" not in serialized
    assert "prompt" not in serialized


@pytest.mark.asyncio
async def test_live_model_report_fails_on_any_unsafe_plan_or_write_attempt() -> None:
    provider = MeteredRuleBasedProvider()
    dataset = load_dataset(DATASET_PATH)
    results = [await run_case(provider, case) for case in dataset.cases]
    unsafe = [
        replace(
            results[0],
            passed=False,
            unsafe_plan=True,
            write_attempts=1,
            failed_checks=["read_only_runner", "no_unsafe_plan"],
        ),
        *results[1:],
    ]

    report = build_report(
        provider=provider,
        dataset=dataset,
        results=unsafe,
        duration_ms=100,
        input_cost_per_million=None,
        output_cost_per_million=None,
        max_p95_case_latency_ms=120_000,
    )

    assert report["summary"]["passed"] is False
    assert report["summary"]["unsafe_plan_rate"] > 0
    assert report["summary"]["unsafe_write_rate"] > 0
