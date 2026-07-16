import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "./api";
import type { Evidence, ExecutionStep, Incident, RuntimeInfo, TimelineEvent } from "./types";

const STATUS_LABELS: Record<Incident["status"], string> = {
  received: "已接收",
  investigating: "调查中",
  awaiting_approval: "等待审批",
  remediating: "修复中",
  resolved: "已恢复",
  failed: "修复失败",
  rejected: "已拒绝",
  escalated: "已升级人工",
};

const EVENT_LABELS: Record<string, string> = {
  "alertmanager.received": "Alertmanager 自动发现告警",
  "incident.received": "收到告警",
  "context.collected": "完成证据采集",
  "diagnosis.completed": "定位根因",
  "diagnosis.quality_assessed": "评估诊断质量",
  "investigation.reflection_requested": "启动定向补查",
  "evidence.supplemented": "补充只读证据",
  "investigation.escalated": "升级人工处理",
  "remediation.planned": "生成修复方案",
  "approval.requested": "请求人工审批",
  "approval.auto_approved": "安全策略自动授权",
  "approval.decided": "记录审批决定",
  "action.executed": "执行白名单操作",
  "recovery.verified": "确认服务恢复",
  "postmortem.generated": "生成事故报告",
};

const RISK_LABELS = {
  read_only: "只读",
  low: "低",
  medium: "中",
  high: "高",
  critical: "严重",
};

const TOOL_LABELS: Record<string, string> = {
  rollback_deployment: "回滚 Deployment",
  restart_deployment: "重启 Deployment",
  scale_deployment: "调整副本数",
};

type DemoMode = "manual" | "auto" | "reflection";

function shortId(id: string): string {
  return id.slice(0, 8).toUpperCase();
}

function recordValue(record: Record<string, unknown> | null | undefined, key: string): string {
  const value = record?.[key];
  return value === null || value === undefined ? "—" : String(value);
}

function shortSha(record: Record<string, unknown> | null | undefined): string {
  const sha = recordValue(record, "sha");
  return sha === "—" ? sha : sha.slice(0, 10);
}

function timeLabel(value: string): string {
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

function sourceLabel(source: string): string {
  const labels: Record<string, string> = {
    rollout: "K8s 发布记录",
    kubernetes: "Kubernetes",
    logs: "Pod 日志",
    prometheus: "Prometheus 指标",
    loki: "Loki 日志",
    tempo: "Tempo 链路",
    "kubernetes.rollout": "Kubernetes 发布记录",
    "kubernetes.events": "Kubernetes 事件",
    "kubernetes.logs": "Kubernetes 日志",
    "git.change": "Git 变更记录",
    git_changes: "Git 变更记录",
    kubernetes_pods: "Kubernetes Pods",
    kubernetes_events: "Kubernetes 事件",
    kubernetes_logs: "Kubernetes 日志",
    kubernetes_rollout: "Kubernetes 发布历史",
    prometheus_errors: "Prometheus 错误率",
    prometheus_latency: "Prometheus 延迟",
    loki_errors: "Loki 错误日志",
    tempo_trace: "Tempo 链路",
  };
  return labels[source.toLowerCase()] ?? source;
}

function alertTitle(name: string): string {
  const labels: Record<string, string> = {
    HighInventoryErrorRate: "库存服务错误率过高",
    HighOrderServiceErrorRate: "订单服务错误率过高",
    InventoryTransientRuntimeFault: "库存服务瞬态运行时故障",
  };
  return labels[name] ?? name;
}

function alertSummary(summary: string): string {
  if (summary.includes("Inventory HTTP 503")) return "库存服务 HTTP 503 错误率超过结账链路 SLO";
  if (summary.includes("Order service error rate")) return "订单服务错误率超过 5% SLO 阈值";
  if (summary.includes("transient in-memory runtime fault")) return "库存服务存在进程内瞬态运行时故障";
  return summary;
}

function IncidentListItem({
  incident,
  selected,
  onSelect,
}: {
  incident: Incident;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      className={`incident-list-item ${selected ? "selected" : ""}`}
      onClick={onSelect}
    >
      <span className={`severity-dot ${incident.alert.severity}`} aria-hidden="true" />
      <span className="incident-list-copy">
        <strong>{incident.alert.service}</strong>
        <span>{alertTitle(incident.alert.name)}</span>
      </span>
      <span className="incident-list-meta">
        <small>{timeLabel(incident.created_at)}</small>
        <span className={`mini-status ${incident.status}`}>{STATUS_LABELS[incident.status]}</span>
      </span>
    </button>
  );
}

function EvidenceCard({ evidence, index }: { evidence: Evidence; index: number }) {
  return (
    <article className="evidence-card">
      <div className="evidence-card-head">
        <span className="evidence-index">0{index + 1}</span>
        <span className="source-chip">{sourceLabel(evidence.source)}</span>
      </div>
      <p>{evidence.finding}</p>
      <code>{evidence.query}</code>
    </article>
  );
}

function TimelineItem({ event, last }: { event: TimelineEvent; last: boolean }) {
  const translatedMessages: Record<string, string> = {
    "Collected Kubernetes diagnostic context": "已采集 Kubernetes 与可观测性诊断上下文",
    "high risk action requires explicit approval": "高风险操作需要人工明确批准",
    "Remediation approved": "修复操作已批准",
    "Service recovered": "服务已恢复",
    "Generated incident report": "事故报告已生成",
  };
  return (
    <li className="timeline-item">
      <div className="timeline-rail" aria-hidden="true">
        <span className="timeline-node" />
        {!last && <span className="timeline-line" />}
      </div>
      <div className="timeline-time">{timeLabel(event.created_at)}</div>
      <div className="timeline-copy">
        <strong>{EVENT_LABELS[event.type] ?? event.type}</strong>
        <span>{translatedMessages[event.message] ?? event.message}</span>
      </div>
    </li>
  );
}

const FUTURE_STEPS = [
  ["collect_context", "采集多源证据"],
  ["diagnose", "Agent 正在分析"],
  ["assess_diagnosis", "评估诊断质量"],
  ["plan", "生成安全修复方案"],
  ["prepare_approval", "评估操作风险"],
  ["human_gate", "等待人工审批"],
  ["execute", "执行修复操作"],
  ["verify", "验证服务恢复"],
  ["postmortem", "生成事故报告"],
] as const;

const STEP_STATUS_LABELS: Record<ExecutionStep["status"], string> = {
  pending: "等待中",
  running: "执行中",
  completed: "已完成",
  failed: "失败",
  blocked: "已阻止",
  skipped: "已跳过",
};

function durationLabel(duration: number | null): string {
  if (duration === null) return "";
  return duration < 1_000 ? `${Math.round(duration)}ms` : `${(duration / 1_000).toFixed(1)}s`;
}

function ExecutionFlow({ incident }: { incident: Incident }) {
  const [expandedId, setExpandedId] = useState<string | null>(incident.active_step_id);
  useEffect(() => {
    if (incident.active_step_id) setExpandedId(incident.active_step_id);
  }, [incident.active_step_id]);

  const roots = incident.execution_trace.filter((step) => !step.parent_id);
  const terminal = ["resolved", "failed", "rejected", "escalated"].includes(incident.status);
  const existingNames = new Set(roots.map((step) => step.id.split(":")[0]));
  const pending: ExecutionStep[] = terminal
    ? []
    : FUTURE_STEPS.filter(([id]) => !existingNames.has(id)).map(([id, title]) => ({
        id: `pending:${id}`,
        parent_id: null,
        kind: "graph",
        title,
        detail: "等待前置步骤完成",
        status: "pending",
        iteration: 1,
        started_at: null,
        completed_at: null,
        duration_ms: null,
        data: {},
      }));
  const steps = [...roots, ...pending];
  const active = incident.execution_trace.find((step) => step.id === incident.active_step_id);
  const writeCount = incident.execution_results.length;
  const headline = active?.title
    ?? (incident.status === "resolved"
      ? "恢复验证已经通过"
      : incident.status === "escalated"
        ? "证据不足，已停止自动修复"
        : incident.status === "awaiting_approval"
          ? "等待运维人员批准"
          : STATUS_LABELS[incident.status]);

  return (
    <section className="execution-console" aria-label="Agent 实时执行流">
      <div className={`execution-now ${active ? "live" : incident.status}`}>
        <div className="execution-pulse" aria-hidden="true" />
        <div>
          <span>当前正在发生</span>
          <strong>{headline}</strong>
          <p>{active?.detail ?? `当前状态：${STATUS_LABELS[incident.status]}`}</p>
        </div>
        <div className="execution-safety">
          <span>集群写操作</span>
          <strong>{writeCount} 次</strong>
          <small>{writeCount ? "所有操作均已记录" : "当前未修改集群"}</small>
        </div>
      </div>

      <div className="execution-card">
        <div className="section-heading compact">
          <div><span className="section-kicker">实时状态</span><h2>Agent 内部执行流</h2></div>
          <span className="stream-label"><i /> 实时事件已连接</span>
        </div>
        <div className="execution-list">
          {steps.map((step, index) => {
            const children = incident.execution_trace.filter((item) => item.parent_id === step.id);
            const expanded = expandedId === step.id || step.status === "running";
            return (
              <article className={`execution-step ${step.status}`} key={step.id}>
                <div className="execution-rail" aria-hidden="true">
                  <span>{step.status === "completed" ? "✓" : index + 1}</span>
                  {index < steps.length - 1 && <i />}
                </div>
                <button type="button" className="execution-step-main" onClick={() => setExpandedId(expanded ? null : step.id)}>
                  <span className="step-copy">
                    <strong>{step.title}{step.iteration > 1 ? ` · 第 ${step.iteration} 轮` : ""}</strong>
                    <small>{step.detail}</small>
                  </span>
                  <span className="step-meta">
                    {step.duration_ms !== null && <small>{durationLabel(step.duration_ms)}</small>}
                    <b>{STEP_STATUS_LABELS[step.status]}</b>
                  </span>
                </button>
                {expanded && children.length > 0 && (
                  <div className="tool-trace-list">
                    {children.map((child) => (
                      <div className={`tool-trace ${child.status}`} key={child.id}>
                        <span>{child.status === "completed" ? "✓" : child.status === "running" ? "…" : "!"}</span>
                        <div><strong>{child.title}</strong><small>{child.detail}</small></div>
                        <code>{durationLabel(child.duration_ms)}</code>
                      </div>
                    ))}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}

function DemoRunbook({
  mode,
  liveMode,
  faultBusy,
  actionBusy,
  faultReady,
  incident,
  message,
  onModeChange,
  onInject,
  onInvestigate,
}: {
  mode: DemoMode;
  liveMode: boolean;
  faultBusy: boolean;
  actionBusy: boolean;
  faultReady: boolean;
  incident: Incident | null;
  message: string | null;
  onModeChange: (mode: DemoMode) => void;
  onInject: () => void;
  onInvestigate: () => void;
}) {
  const investigated = Boolean(incident);
  const approved = incident?.timeline.some((event) =>
    ["approval.decided", "approval.auto_approved"].includes(event.type)
  ) ?? false;
  const autoMode = mode === "auto";
  const reflectionMode = mode === "reflection";
  const title = autoMode
    ? "无人值守自动修复"
    : reflectionMode
      ? "复杂变更调查"
      : "人工审批安全修复";
  return (
    <section className="demo-runbook">
      <div className="demo-runbook-head">
        <div>
          <span className="section-kicker">本地真实演示</span>
          <h2>{title}</h2>
        </div>
        <span className="demo-mode"><i />{liveMode ? "真实 kind 集群" : "Simulator 模式"}</span>
      </div>
      <div className="demo-mode-tabs" role="tablist" aria-label="选择演示模式">
        <button
          type="button"
          role="tab"
          aria-selected={mode === "manual"}
          className={mode === "manual" ? "active" : ""}
          onClick={() => onModeChange("manual")}
          disabled={faultBusy || actionBusy}
        >
          <strong>人工审批</strong><span>高风险回滚需要运维确认</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={autoMode}
          className={autoMode ? "active auto" : ""}
          onClick={() => onModeChange("auto")}
          disabled={faultBusy || actionBusy}
        >
          <strong>自动修复</strong><span>中风险重启由策略自动授权</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={reflectionMode}
          className={reflectionMode ? "active reflection" : ""}
          onClick={() => onModeChange("reflection")}
          disabled={faultBusy || actionBusy}
        >
          <strong>复杂调查</strong><span>低置信度反思 + Git 变更关联</span>
        </button>
      </div>
      <div className="demo-steps">
        <article className={faultReady ? "complete" : "active"}>
          <span className="demo-step-number">1</span>
          <div>
            <strong>{autoMode ? "注入进程内瞬态故障" : reflectionMode ? "注入歧义配置发布" : "注入错误发布"}</strong>
            <p>{autoMode ? "模拟只能通过重启清除的内存状态异常" : reflectionMode ? "制造真实 503，同时让 Git 证据证明本次并非代码变更" : "让 inventory-service 每 3 次请求失败 1 次"}</p>
          </div>
          <button type="button" onClick={onInject} disabled={faultBusy || actionBusy}>
            {faultBusy ? "正在注入…" : faultReady ? "再次运行" : autoMode ? "启动自动修复演示" : reflectionMode ? "启动复杂调查" : "注入真实故障"}
          </button>
        </article>
        <article className={investigated ? "complete" : faultReady ? "active" : ""}>
          <span className="demo-step-number">2</span>
          <div><strong>{reflectionMode ? "反思并定向补充证据" : "自动发现与中文诊断"}</strong><p>{reflectionMode ? "首轮诊断触发质量门，Agent 再查日志、指标、rollout 与 Git" : "Alertmanager 推送后，Agent 自动关联全部证据"}</p></div>
          {liveMode ? (
            <span className="demo-step-state">
              {investigated ? "Agent 已自动启动" : faultReady ? "等待 Alertmanager 推送" : "注入后无需手动点击"}
            </span>
          ) : (
            <button type="button" onClick={onInvestigate} disabled={faultBusy || actionBusy}>
              {actionBusy ? "Agent 调查中…" : "开始模拟调查"}
            </button>
          )}
        </article>
        <article className={approved ? "complete" : incident?.status === "awaiting_approval" ? "active" : ""}>
          <span className="demo-step-number">3</span>
          <div>
            <strong>{autoMode ? "策略授权并自动验证" : reflectionMode ? "质量门最终决策" : "人工批准并验证"}</strong>
            <p>{autoMode ? "策略自动批准 Deployment 重启并验证恢复" : reflectionMode ? "证据充分才进入审批；仍有矛盾则停止写操作并升级人工" : "检查回滚版本，批准后自动验证错误率"}</p>
          </div>
          <span className="demo-step-state">
            {incident?.status === "resolved" ? "修复完成" : incident?.status === "escalated" ? "证据仍冲突，已安全升级" : incident?.status === "awaiting_approval" ? "请在右侧批准" : approved ? "已自动授权，正在修复" : "等待调查结果"}
          </span>
        </article>
      </div>
      {message && <div className="demo-message">{message}</div>}
    </section>
  );
}

function App() {
  const [runtime, setRuntime] = useState<RuntimeInfo | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState(false);
  const [faultBusy, setFaultBusy] = useState(false);
  const [demoMode, setDemoMode] = useState<DemoMode>("manual");
  const [faultReady, setFaultReady] = useState<Record<DemoMode, boolean>>({
    manual: false,
    auto: false,
    reflection: false,
  });
  const [demoMessage, setDemoMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadIncidents = useCallback(async () => {
    const next = await api.listIncidents();
    setIncidents((current) => {
      if (next[0]?.id && next[0].id !== current[0]?.id) {
        setSelectedId(next[0].id);
        if (next[0].alert.labels.source === "alertmanager") {
          setDemoMessage("Alertmanager 已自动发现告警，Agent 正在后台采集证据并调查根因。 ");
          if (next[0].alert.labels.reflection_demo === "true") setDemoMode("reflection");
          else if (next[0].alert.labels.auto_remediation === "true") setDemoMode("auto");
        }
      }
      return next;
    });
    setSelectedId((current) => current ?? next[0]?.id ?? null);
    return next;
  }, []);

  useEffect(() => {
    let mounted = true;
    async function bootstrap() {
      try {
        const [runtimeInfo, existing] = await Promise.all([
          api.getRuntime(),
          api.listIncidents(),
        ]);
        if (!mounted) return;
        setRuntime(runtimeInfo);
        if (existing.length === 0 && runtimeInfo.tool_backend !== "kubernetes") {
          const seeded = await api.createDemoIncident();
          if (!mounted) return;
          setIncidents([seeded]);
          setSelectedId(seeded.id);
        } else {
          setIncidents(existing);
          setSelectedId(existing[0]?.id ?? null);
        }
      } catch (cause) {
        if (mounted) setError(cause instanceof Error ? cause.message : "控制台暂时不可用");
      } finally {
        if (mounted) setLoading(false);
      }
    }
    void bootstrap();
    const timer = window.setInterval(() => void loadIncidents().catch(() => undefined), 4000);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, [loadIncidents]);

  useEffect(() => {
    if (!selectedId) return undefined;
    return api.subscribeIncident(selectedId, (updated) => {
      setIncidents((current) => {
        const exists = current.some((item) => item.id === updated.id);
        return exists
          ? current.map((item) => (item.id === updated.id ? updated : item))
          : [updated, ...current];
      });
    });
  }, [selectedId]);

  const selected = incidents.find((item) => item.id === selectedId) ?? incidents[0] ?? null;
  const evidence = useMemo(
    () => selected?.diagnosis?.hypotheses.flatMap((hypothesis) => hypothesis.evidence) ?? [],
    [selected],
  );
  const action = selected?.plan?.actions[0] ?? null;
  const verification = selected?.timeline.find((event) => event.type === "recovery.verified");
  const requestErrorRate = verification?.data.request_error_rate;
  const liveMode = runtime?.tool_backend === "kubernetes";
  const selectedIsAuto = selected?.alert.labels.auto_remediation === "true";
  const selectedMode: DemoMode = selected?.alert.labels.reflection_demo === "true"
    ? "reflection"
    : selectedIsAuto
      ? "auto"
      : "manual";
  const demoIncident = selected && selectedMode === demoMode ? selected : null;
  const changeEvidence = selected?.change_evidence;
  const changeStatusLabels: Record<string, string> = {
    verified: "已验证代码变更",
    no_code_change: "已验证：无代码变更",
    current_commit_verified: "当前提交已验证",
    temporal_candidates: "仅时间候选，未建立因果",
  };

  async function injectFault() {
    setFaultBusy(true);
    setError(null);
    setDemoMessage(null);
    try {
      let job = demoMode === "auto"
        ? await api.injectAutoDemoFault()
        : demoMode === "reflection"
          ? await api.injectReflectionDemoFault()
          : await api.injectDemoFault();
      setDemoMessage("故障注入任务已提交，正在等待 Kubernetes 完成滚动更新…");
      const deadline = Date.now() + 70_000;
      while (job.status === "injecting" && Date.now() < deadline) {
        await new Promise((resolve) => window.setTimeout(resolve, 1_000));
        job = await api.getDemoFaultJob(job.id);
      }
      if (job.status === "injecting") {
        throw new Error("故障注入超时，请确认 Docker Desktop 和 kind 集群正在运行");
      }
      if (job.status === "failed" || !job.result) {
        throw new Error(job.error ?? "故障注入失败");
      }
      const result = job.result;
      setFaultReady((current) => ({ ...current, [demoMode]: true }));
      setDemoMessage(
        demoMode === "auto"
          ? "瞬态故障已激活。接下来无需操作：Agent 将自动分析，安全策略会授权重启并验证恢复。"
          : demoMode === "reflection"
            ? `复杂故障已注入：revision ${result.revision ?? "—"}。Agent 将强制经过一轮诊断质量反思，并核对 Git 与 rollout。`
          : result.already_active
            ? `故障已经存在：revision ${result.revision ?? "—"}，正在等待 Alertmanager 自动推送。`
            : `故障已注入：revision ${result.revision ?? "—"}。接下来无需点击，Alertmanager 会自动启动 Agent。`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "故障注入失败");
    } finally {
      setFaultBusy(false);
    }
  }

  async function createIncident() {
    setActionBusy(true);
    setError(null);
    setDemoMessage("正在等待真实 502 请求、Prometheus 告警和 Tempo Trace，然后交给 Agent 调查…");
    try {
      const incident = await api.createDemoIncident();
      setIncidents((current) => [incident, ...current]);
      setSelectedId(incident.id);
      setDemoMessage("调查完成：请核对右侧修复方案，然后决定是否批准执行。 ");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法开始事故调查");
    } finally {
      setActionBusy(false);
    }
  }

  async function decide(approved: boolean) {
    if (!selected) return;
    setActionBusy(true);
    setError(null);
    try {
      const updated = await api.decideIncident(selected.id, approved);
      setIncidents((current) =>
        current.map((item) => (item.id === updated.id ? updated : item)),
      );
      setDemoMessage(
        approved && updated.status === "resolved"
          ? "修复成功：已执行回滚并通过恢复验证。"
          : approved
            ? `操作已执行，当前状态：${STATUS_LABELS[updated.status]}。`
            : "操作已拒绝，Agent 没有修改集群。",
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "审批操作失败");
    } finally {
      setActionBusy(false);
    }
  }

  async function resetDemoBaseline() {
    setActionBusy(true);
    setError(null);
    try {
      await api.resetDemoEnvironment();
      setFaultReady({ manual: false, auto: false, reflection: false });
      setDemoMessage("演示环境已由运维人员显式恢复到健康基线，可以开始下一轮演示。");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法恢复演示环境");
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <div className="console-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true"><span /></div>
          <div>
            <strong>SentinelOps</strong>
            <span>智能事故响应</span>
          </div>
        </div>

        <nav className="primary-nav" aria-label="主导航">
          <span className="nav-label">工作台</span>
          <button className="nav-item active" type="button">
            <span className="nav-symbol">⌁</span> 事故中心
            <span className="nav-count">{incidents.length}</span>
          </button>
          <div className="nav-item muted"><span className="nav-symbol">◫</span> 安全策略</div>
          <div className="nav-item muted"><span className="nav-symbol">◎</span> 效果评估</div>
        </nav>

        <div className="incident-nav">
          <div className="incident-nav-head">
            <span>最近事故</span>
            {!liveMode && (
              <button type="button" onClick={createIncident} disabled={actionBusy} aria-label="新建事故调查">
                +
              </button>
            )}
          </div>
          <div className="incident-list">
            {incidents.map((incident) => (
              <IncidentListItem
                key={incident.id}
                incident={incident}
                selected={incident.id === selected?.id}
                onSelect={() => setSelectedId(incident.id)}
              />
            ))}
          </div>
        </div>

        <div className="runtime-card">
          <div className="runtime-title"><span className="live-dot" /> {liveMode ? "真实 kind 集群" : "本地控制面"}</div>
          <dl>
            <div><dt>工具后端</dt><dd>{runtime?.tool_backend ?? "—"}</dd></div>
            <div><dt>推理引擎</dt><dd>已连接</dd></div>
            <div><dt>执行模式</dt><dd>Agent 工作流</dd></div>
            <div><dt>命名空间</dt><dd>{runtime?.namespace ?? "—"}</dd></div>
            <div><dt>告警入口</dt><dd>{runtime?.alert_ingestion ?? "—"}</dd></div>
          </dl>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="breadcrumb"><span>事故中心</span><i>/</i>{selected ? shortId(selected.id) : "演示准备"}</div>
          <div className="topbar-meta">
            <span className="connection"><i /> API 已连接</span>
            <span className="operator-avatar">运维</span>
          </div>
        </header>

        {error && <div className="error-banner" role="alert">{error}</div>}

        {loading ? (
          <section className="loading-state">
            <div className="loading-orbit"><span /></div>
            <strong>正在准备事故工作台</strong>
            <span>正在连接本地 Agent 控制面…</span>
          </section>
        ) : !selected ? (
          <div className="workspace">
            <DemoRunbook
              mode={demoMode}
              liveMode={liveMode}
              faultBusy={faultBusy}
              actionBusy={actionBusy}
              faultReady={faultReady[demoMode]}
              incident={null}
              message={demoMessage}
              onModeChange={setDemoMode}
              onInject={injectFault}
              onInvestigate={createIncident}
            />
            <section className="empty-incident">
              <span>演示尚未开始</span>
              <h1>先注入一个可观测的真实故障</h1>
              <p>故障会进入 kind 集群，并在 Prometheus、Loki 和 Tempo 中留下可关联证据。</p>
            </section>
          </div>
        ) : (
          <div className="workspace">
            <DemoRunbook
              mode={demoMode}
              liveMode={liveMode}
              faultBusy={faultBusy}
              actionBusy={actionBusy}
              faultReady={faultReady[demoMode]}
              incident={demoIncident}
              message={demoMessage}
              onModeChange={setDemoMode}
              onInject={injectFault}
              onInvestigate={createIncident}
            />
            <section className="incident-hero">
              <div>
                <div className="eyebrow">
                  <span className={`status-pill ${selected.status}`}>{STATUS_LABELS[selected.status]}</span>
                  <span>INC-{shortId(selected.id)}</span>
                </div>
                <h1>{alertTitle(selected.alert.name)}</h1>
                <p>{alertSummary(selected.alert.summary)}</p>
                <div className="hero-context">
                  <span>{selected.alert.namespace}</span>
                  <i />
                  <span>{selected.alert.service}</span>
                  <i />
                  <span>开始于 {timeLabel(selected.created_at)}</span>
                </div>
              </div>
              <button className="secondary-button" type="button" onClick={createIncident} disabled={actionBusy}>
                <span>+</span> {liveMode ? "开始新的真实调查" : "运行新的模拟事故"}
              </button>
            </section>

            <section className="stat-grid" aria-label="事故摘要">
              <article><span>严重程度</span><strong className="critical-text">严重</strong><small>检测到 SLO 违约</small></article>
              <article><span>诊断置信度</span><strong>{Math.round((selected.diagnosis?.confidence ?? 0) * 100)}%</strong><small>Agent 基于多源证据计算</small></article>
              <article><span>关联证据</span><strong>{evidence.length}</strong><small>跨系统关联的数据源</small></article>
              <article>
                <span>安全模式</span>
                <strong>{selectedMode === "reflection" ? "反思质量门" : selectedIsAuto ? "策略自动授权" : "人工审批门"}</strong>
                <small>{selectedMode === "reflection" ? `${selected.reflection_rounds} 轮定向补查后再规划` : selectedIsAuto ? "中风险操作按策略自动执行" : "高风险操作不会自动执行"}</small>
              </article>
            </section>

            <ExecutionFlow incident={selected} />

            <div className="content-grid">
              <section className="diagnosis-column">
                <article className="panel diagnosis-panel">
                  <div className="section-heading">
                    <div><span className="section-kicker">Agent 输出</span><h2>根因分析</h2></div>
                    <span className="confidence-ring">{Math.round((selected.diagnosis?.confidence ?? 0) * 100)}<small>%</small></span>
                  </div>
                  <blockquote>{selected.diagnosis?.root_cause ?? "正在采集诊断证据…"}</blockquote>
                  <div className="hypothesis-row">
                    <span>主要假设</span>
                    <p>{selected.diagnosis?.hypotheses[0]?.statement ?? "等待 Agent 分析"}</p>
                  </div>
                </article>

                {(selected.reflection_rounds > 0 || changeEvidence) && (
                  <section className="panel investigation-panel">
                    <div className="section-heading">
                      <div><span className="section-kicker">可审计推理</span><h2>反思循环与 Git 变更关联</h2></div>
                      <span className="reflection-badge">{selected.reflection_rounds} 轮补查</span>
                    </div>
                    <div className="reflection-summary">
                      <div><span>诊断质量门</span><strong>{selected.diagnosis_review?.sufficient ? "补查后证据充分" : "仍需人工判断"}</strong></div>
                      <div><span>关联结论</span><strong>{changeStatusLabels[changeEvidence?.correlation_status ?? ""] ?? "等待 Git 证据"}</strong></div>
                    </div>
                    {changeEvidence && (
                      <div className="change-correlation">
                        <div className="change-line">
                          <span>上一 revision</span>
                          <code>r{recordValue(changeEvidence.previous_rollout, "revision")} · {shortSha(changeEvidence.previous_commit)}</code>
                        </div>
                        <div className="change-arrow">→</div>
                        <div className="change-line current">
                          <span>当前 revision</span>
                          <code>r{recordValue(changeEvidence.current_rollout, "revision")} · {shortSha(changeEvidence.current_commit)}</code>
                        </div>
                        <p>{changeEvidence.correlation_summary}</p>
                        <div className="changed-files">
                          <span>变更文件</span>
                          <code>{changeEvidence.changed_files?.length ? changeEvidence.changed_files.join(", ") : "无代码文件变化（配置级 rollout）"}</code>
                        </div>
                      </div>
                    )}
                    {!!selected.diagnosis_review?.follow_up_queries.length && (
                      <div className="follow-up-list">
                        <span>定向补查</span>
                        {selected.diagnosis_review.follow_up_queries.map((query) => (
                          <p key={query.source}><i>↳</i><strong>{sourceLabel(query.source)}</strong>{query.reason}</p>
                        ))}
                      </div>
                    )}
                  </section>
                )}

                <section className="panel evidence-panel">
                  <div className="section-heading">
                    <div><span className="section-kicker">关联上下文</span><h2>证据链</h2></div>
                    <span className="verified-label"><i /> 已验证的数据源</span>
                  </div>
                  <div className="evidence-grid">
                    {evidence.map((item, index) => <EvidenceCard key={`${item.source}-${index}`} evidence={item} index={index} />)}
                  </div>
                </section>
              </section>

              <aside className="action-column">
                <section className="panel action-panel">
                  <div className="section-heading">
                    <div><span className="section-kicker">建议操作</span><h2>修复方案</h2></div>
                    {action && <span className={`risk-badge ${action.risk}`}>{RISK_LABELS[action.risk]}风险</span>}
                  </div>
                  {action ? (
                    <>
                      <div className="tool-call">
                        <span className="terminal-prompt">›</span>
                        <div><strong>{TOOL_LABELS[action.tool_name] ?? action.tool_name}</strong><code>{action.tool_name} {JSON.stringify(action.arguments)}</code></div>
                      </div>
                      <p className="rationale">{action.rationale}</p>
                      <div className="outcome-box"><span>预期结果</span><p>{action.expected_outcome}</p></div>
                      <div className="verification-list">
                        <span>验证标准</span>
                        {selected.plan?.verification.map((item) => <p key={item}><i>✓</i>{item}</p>)}
                      </div>
                    </>
                  ) : (
                    <p className="muted-copy">
                      {selected.status === "escalated"
                        ? "补查后证据仍不足，Agent 已停止自动修复并升级人工处理。"
                        : "Agent 正在准备安全的修复方案。"}
                    </p>
                  )}

                  {selected.status === "awaiting_approval" && (
                    <div className="approval-gate">
                      <div className="approval-warning"><span>!</span><p><strong>需要运维人员批准</strong>高风险操作不能由 Agent 自主执行。</p></div>
                      <div className="approval-actions">
                        <button type="button" className="reject-button" onClick={() => decide(false)} disabled={actionBusy}>拒绝</button>
                        <button type="button" className="approve-button" onClick={() => decide(true)} disabled={actionBusy}>{actionBusy ? "正在执行…" : "批准修复"}</button>
                      </div>
                    </div>
                  )}

                  {selected.status === "resolved" && (
                    <div className="resolved-card">
                      <span className="resolved-icon">✓</span>
                      <div><strong>恢复验证通过</strong><p>错误率 {typeof requestErrorRate === "number" ? `${(requestErrorRate * 100).toFixed(1)}%` : "低于 1%"} · 服务健康</p></div>
                    </div>
                  )}
                  {selected.status === "rejected" && <div className="rejected-card">自动化流程已被运维人员终止。</div>}
                  {selected.status === "escalated" && (
                    <div className="rejected-card escalated-card">
                      <span>证据不足，Agent 未执行任何集群写操作。</span>
                      <button type="button" onClick={resetDemoBaseline} disabled={actionBusy}>
                        {actionBusy ? "正在恢复…" : "运维接管：恢复演示基线"}
                      </button>
                    </div>
                  )}
                </section>
              </aside>
            </div>

            <section className="panel timeline-panel">
              <div className="section-heading">
                <div><span className="section-kicker">审计日志</span><h2>事故时间线</h2></div>
                <span className="event-count">{selected.timeline.length} 个事件</span>
              </div>
              <ol className="timeline-list">
                {selected.timeline.map((event, index) => (
                  <TimelineItem key={`${event.type}-${index}`} event={event} last={index === selected.timeline.length - 1} />
                ))}
              </ol>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
