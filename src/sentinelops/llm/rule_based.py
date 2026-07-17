from __future__ import annotations

import json
from typing import Any, TypeVar

from pydantic import BaseModel

from sentinelops.domain import (
    Diagnosis,
    DiagnosisReview,
    Evidence,
    EvidenceCatalogEntry,
    FollowUpQuery,
    Hypothesis,
    RemediationAction,
    RemediationPlan,
    RiskLevel,
)

T = TypeVar("T", bound=BaseModel)


class RuleBasedProvider:
    """Deterministic offline provider used for demos and CI.

    It deliberately implements the same contract as remote LLM providers so the
    complete graph can be exercised without an API key.
    """

    name = "rule_based"

    async def structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: type[T],
        metadata: dict[str, Any] | None = None,
    ) -> T:
        payload = json.loads(prompt)
        observations = payload.get("observations", {})
        scenario = self._infer_scenario(observations)

        if schema is Diagnosis:
            return self._diagnose(scenario, observations)  # type: ignore[return-value]
        if schema is DiagnosisReview:
            return self._review(payload)  # type: ignore[return-value]
        if schema is RemediationPlan:
            return self._plan(scenario, payload)  # type: ignore[return-value]
        raise TypeError(f"RuleBasedProvider does not support schema {schema.__name__}")

    @staticmethod
    def _review(payload: dict[str, Any]) -> DiagnosisReview:
        preferred = ["git_changes", "kubernetes_logs", "prometheus_errors"]
        available = set(payload.get("available_sources", []))
        reasons = {
            "git_changes": "核对发布 revision 与 Git 提交的关联",
            "kubernetes_logs": "补充服务日志以验证错误模式",
            "prometheus_errors": "补充实时请求错误率",
        }
        queries = [
            FollowUpQuery(source=source, reason=reasons[source])  # type: ignore[arg-type]
            for source in preferred
            if source in available
        ]
        return DiagnosisReview(
            sufficient=False,
            confidence=float(payload.get("diagnosis", {}).get("confidence", 0)),
            missing_evidence=["当前诊断置信度不足，需要补充独立证据"],
            follow_up_queries=queries,
        )

    @staticmethod
    def _infer_scenario(observations: dict[str, Any]) -> str:
        declared = observations.get("metrics", {}).get("scenario")
        if declared in {
            "db_pool_exhaustion",
            "inventory_faulty_rollout",
            "transient_runtime_fault",
        }:
            return declared

        all_evidence = json.dumps(observations, ensure_ascii=False).lower()
        if (
            "transient_runtime_fault_enabled" in all_evidence
            or "reason=transient_runtime_fault" in all_evidence
        ):
            return "transient_runtime_fault"
        if "inventory_reservation_failed" in all_evidence or "synthetic_timeout" in all_evidence:
            return "inventory_faulty_rollout"
        if any(
            (
                RuleBasedProvider._has_bad_rollout_pod_signal(observations),
                RuleBasedProvider._has_bad_rollout_event_signal(observations),
                RuleBasedProvider._has_bad_rollout_log_signal(observations),
                RuleBasedProvider._has_bad_rollout_history_signal(observations),
            )
        ):
            return "bad_rollout"
        if RuleBasedProvider._has_db_pool_log_signal(
            observations
        ) or RuleBasedProvider._has_db_pool_metric_signal(observations):
            return "db_pool_exhaustion"
        return "unknown"

    @staticmethod
    def _has_db_pool_log_signal(observations: dict[str, Any]) -> bool:
        lines = observations.get("logs", {}).get("lines", [])
        logs = "\n".join(str(line) for line in lines).lower()
        return any(
            marker in logs
            for marker in (
                "timeout acquiring database connection from pool",
                "database connection pool exhausted",
                "db_pool_exhaustion",
            )
        )

    @staticmethod
    def _has_db_pool_metric_signal(observations: dict[str, Any]) -> bool:
        value = observations.get("metrics", {}).get("db_pool_utilization")
        if isinstance(value, bool):
            return False
        try:
            return float(value) >= 0.95
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _has_bad_rollout_pod_signal(observations: dict[str, Any]) -> bool:
        failure_states = {
            "crashloopbackoff",
            "error",
            "failed",
            "imagepullbackoff",
            "errimagepull",
            "oomkilled",
        }
        for pod in observations.get("pods", {}).get("items", []):
            states = {
                str(pod.get("phase", "")).casefold(),
                str(pod.get("reason", "")).casefold(),
                *(str(reason).casefold() for reason in pod.get("waiting_reasons", [])),
            }
            if not pod.get("ready") and states & failure_states:
                return True
        return False

    @staticmethod
    def _has_bad_rollout_event_signal(observations: dict[str, Any]) -> bool:
        markers = (
            "back-off restarting failed container",
            "crashloopbackoff",
            "failed to start",
            "startup probe failed",
            "readiness probe failed",
            "errimagepull",
            "imagepullbackoff",
        )
        for item in observations.get("events", {}).get("items", []):
            message = " ".join(
                str(item.get(key, "")) for key in ("reason", "message")
            ).casefold()
            if any(marker in message for marker in markers):
                return True
        return False

    @staticmethod
    def _has_bad_rollout_log_signal(observations: dict[str, Any]) -> bool:
        logs = "\n".join(
            str(line) for line in observations.get("logs", {}).get("lines", [])
        ).casefold()
        return any(
            marker in logs
            for marker in (
                "required environment variable",
                "application configuration is invalid",
                "invalid configuration",
                "crashloopbackoff",
                "failed to start",
            )
        )

    @classmethod
    def _has_bad_rollout_history_signal(cls, observations: dict[str, Any]) -> bool:
        current = cls._current_rollout_revision(observations)
        if current is None:
            return False
        return str(current.get("status", "")).casefold() in {
            "failed",
            "unhealthy",
            "degraded",
        } or str(current.get("health_status", "")).casefold() in {
            "failed",
            "unhealthy",
        }

    @staticmethod
    def _has_error_metric_signal(observations: dict[str, Any]) -> bool:
        value = observations.get("metrics", {}).get("error_rate")
        if isinstance(value, bool):
            return False
        try:
            return float(value) >= 0.05
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _current_rollout_revision(observations: dict[str, Any]) -> dict[str, Any] | None:
        rollout = observations.get("rollout", {})
        revisions = rollout.get("revisions", [])
        try:
            declared = int(rollout.get("current_revision", 0))
        except (TypeError, ValueError):
            declared = 0
        if declared:
            matching = next(
                (
                    revision
                    for revision in revisions
                    if int(revision.get("revision", 0)) == declared
                ),
                None,
            )
            if matching is not None:
                return matching
        candidates = [
            revision
            for revision in revisions
            if str(revision.get("revision", "")).isdigit()
            and (
                (revision.get("replicas") or 0) > 0
                or (revision.get("ready_replicas") or 0) > 0
                or str(revision.get("status", "")).casefold()
                in {"failed", "active", "current"}
            )
        ]
        return (
            max(candidates, key=lambda revision: int(revision["revision"]))
            if candidates
            else None
        )

    def _diagnose(self, scenario: str, observations: dict[str, Any]) -> Diagnosis:
        current_revision, _ = self._rollout_revisions(observations)
        if scenario == "transient_runtime_fault":
            candidates = []
            log_text = "\n".join(
                str(line) for line in observations.get("logs", {}).get("lines", [])
            ).casefold()
            if "transient_runtime_fault" in log_text:
                candidates.append(
                    (
                        "get_pod_logs",
                        "logs",
                        "Pod 日志显示瞬态运行时故障已启用且需要重启清除",
                    )
                )
            if observations.get("metrics", {}).get("scenario") == scenario:
                candidates.append(
                    (
                        "get_service_metrics",
                        "metrics",
                        "工作负载指标确认进程内瞬态故障处于活动状态",
                    )
                )
            prometheus_text = json.dumps(
                observations.get("prometheus", {}), ensure_ascii=False
            ).casefold()
            if "transient_runtime_fault" in prometheus_text:
                candidates.append(
                    (
                        "query_prometheus",
                        "prometheus",
                        "Prometheus 检测到库存服务的进程内瞬态故障指标为 1",
                    )
                )
            loki_text = json.dumps(
                observations.get("loki", {}), ensure_ascii=False
            ).casefold()
            if "transient_runtime_fault" in loki_text:
                candidates.append(
                    (
                        "search_loki",
                        "loki",
                        "Loki 日志显示 transient_runtime_fault 已启用且需要重启清除",
                    )
                )
            if observations.get("rollout", {}).get("revisions"):
                candidates.append(
                    (
                        "get_rollout_history",
                        "rollout",
                        "Kubernetes 发布历史没有出现与本次故障对应的新 revision",
                    )
                )
            root_cause = "库存服务进程内的瞬态故障状态导致所有预留请求返回 HTTP 503"
        elif scenario == "inventory_faulty_rollout":
            candidates = [
                ("get_pod_logs", "logs", "库存服务日志记录了合成的预留超时"),
                ("get_service_metrics", "metrics", "工作负载指标显示库存服务错误率升高"),
                ("query_prometheus", "prometheus", "库存服务请求指标中出现 HTTP 503 响应"),
                ("search_loki", "loki", "Loki 日志记录了合成的预留超时"),
                ("get_trace", "trace", "失败的结账链路经过库存服务并在此发生错误"),
                (
                    "get_rollout_history",
                    "rollout",
                    f"产生错误的配置来自 Deployment revision {current_revision}",
                ),
            ]
            root_cause = (
                f"库存服务 Deployment revision {current_revision} 启用了合成预留故障"
            )
        elif scenario == "bad_rollout":
            candidates = []
            if self._has_bad_rollout_pod_signal(observations):
                candidates.append(
                    ("list_pods", "pods", "当前 Pod 明确处于容器启动失败状态")
                )
            if self._has_bad_rollout_event_signal(observations):
                candidates.append(
                    ("list_events", "events", "Kubernetes 事件明确记录了容器启动失败")
                )
            if self._has_bad_rollout_history_signal(observations):
                candidates.append(
                    (
                        "get_rollout_history",
                        "rollout",
                        f"Deployment revision {current_revision} 被明确标记为失败",
                    )
                )
            if self._has_bad_rollout_log_signal(observations):
                candidates.append(
                    ("get_pod_logs", "logs", "Pod 日志明确记录了启动配置错误")
                )
            if self._has_error_metric_signal(observations):
                candidates.append(
                    ("get_service_metrics", "metrics", "工作负载错误率达到 5% 以上")
                )
            root_cause = (
                f"Deployment revision {current_revision} 的工作负载发生了明确的启动故障"
            )
        elif scenario == "db_pool_exhaustion":
            candidates = []
            if self._has_db_pool_log_signal(observations):
                candidates.append(
                    ("get_pod_logs", "logs", "日志明确记录了获取数据库连接超时")
                )
            if self._has_db_pool_metric_signal(observations):
                candidates.append(
                    ("get_service_metrics", "metrics", "数据库连接池利用率达到 95% 以上")
                )
            root_cause = "订单服务的数据库连接池已耗尽"
        else:
            root_cause = "现有证据不足，无法确认根本原因"
            return Diagnosis(
                root_cause=root_cause,
                confidence=0.1,
                hypotheses=[
                    Hypothesis(
                        statement=root_cause,
                        confidence=0.1,
                        evidence=[],
                    )
                ],
                evidence_summary=[],
            )

        evidence = [
            reference
            for tool, raw_key, finding in candidates
            if (
                reference := self._catalog_evidence(
                    observations,
                    tool=tool,
                    raw_key=raw_key,
                    finding=finding,
                )
            )
            is not None
        ]

        changes = observations.get("changes", {})
        if changes.get("correlation_status") in {
            "verified",
            "no_code_change",
            "current_commit_verified",
        }:
            change_reference = self._catalog_evidence(
                observations,
                tool="get_change_evidence",
                raw_key="changes",
                finding=str(changes.get("correlation_summary")),
            )
            if change_reference is not None:
                evidence.append(change_reference)

        return Diagnosis(
            root_cause=root_cause,
            confidence=0.94,
            hypotheses=[Hypothesis(statement=root_cause, confidence=0.94, evidence=evidence)],
            evidence_summary=[item.finding for item in evidence],
        )

    @staticmethod
    def _catalog_evidence(
        observations: dict[str, Any],
        *,
        tool: str,
        raw_key: str,
        finding: str,
    ) -> Evidence | None:
        matches: list[EvidenceCatalogEntry] = []
        for payload in observations.get("evidence_catalog", {}).values():
            try:
                entry = EvidenceCatalogEntry.model_validate(payload)
            except (TypeError, ValueError):
                continue
            if entry.tool == tool and entry.success:
                matches.append(entry)
        if not matches:
            return None
        entry = matches[-1]
        return Evidence(
            evidence_id=entry.evidence_id,
            source=entry.source,
            query=entry.tool,
            finding=finding,
            raw=observations.get(raw_key, {}),
        )

    def _plan(self, scenario: str, payload: dict[str, Any]) -> RemediationPlan:
        current_revision, previous_revision = self._rollout_revisions(
            payload.get("observations", {})
        )
        if scenario == "unknown":
            return RemediationPlan(
                summary="证据不足，不生成自动修复方案",
                actions=[],
                rollback="未执行任何集群写操作，无需回滚",
                verification=["补充至少两个独立且成功的证据来源后重新诊断"],
            )
        if scenario == "transient_runtime_fault":
            service = payload["alert"]["service"]
            action = RemediationAction(
                tool_name="restart_deployment",
                arguments={"name": service},
                rationale="故障仅存在于进程内存中，滚动重启可以清除异常状态且不改变期望配置",
                expected_outcome="新 Pod 启动后库存预留和结账请求恢复成功",
                risk=RiskLevel.MEDIUM,
            )
        elif scenario == "inventory_faulty_rollout":
            service = payload["alert"]["service"]
            action = RemediationAction(
                tool_name="rollback_deployment",
                arguments={"name": service, "revision": previous_revision},
                rationale=(
                    f"revision {current_revision} 引入库存服务 HTTP 503，"
                    f"而 revision {previous_revision} 已知健康"
                ),
                expected_outcome="库存服务不再返回 HTTP 503，结账流量恢复",
                risk=RiskLevel.HIGH,
            )
        elif scenario == "bad_rollout":
            action = RemediationAction(
                tool_name="rollback_deployment",
                arguments={
                    "name": payload["alert"]["service"],
                    "revision": previous_revision,
                },
                rationale=(
                    f"事故与 revision {current_revision} 强相关，并且该版本的 Pod 不健康"
                ),
                expected_outcome=(
                    f"revision {previous_revision} 恢复可用，错误率回到基线"
                ),
                risk=RiskLevel.HIGH,
            )
        else:
            action = RemediationAction(
                tool_name="restart_deployment",
                arguments={"name": payload["alert"]["service"]},
                rationale="在保留期望状态的同时回收泄漏的数据库连接",
                expected_outcome=(
                    "连接池利用率和请求错误率回到基线"
                ),
                risk=RiskLevel.MEDIUM,
            )
        return RemediationPlan(
            summary=f"修复：{payload['diagnosis']['root_cause']}",
            actions=[action],
            rollback="停止自动化并恢复到之前的 Deployment revision",
            verification=["可用副本数等于期望副本数", "请求错误率低于 1%"],
        )

    @staticmethod
    def _rollout_revisions(observations: dict[str, Any]) -> tuple[int, int]:
        revision_numbers = sorted(
            {
                int(item["revision"])
                for item in observations.get("rollout", {}).get("revisions", [])
                if str(item.get("revision", "")).isdigit()
            }
        )
        if not revision_numbers:
            return 2, 1
        current = revision_numbers[-1]
        previous = revision_numbers[-2] if len(revision_numbers) > 1 else max(current - 1, 1)
        return current, previous
