import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api } from "./api";
import type { Evidence, ExecutionStep, Incident, RuntimeInfo } from "./types";

const STATUS_LABELS: Record<Incident["status"], string> = {
  received: "已接收",
  investigating: "调查中",
  awaiting_approval: "等待审批",
  remediating: "修复中",
  resolved: "已恢复",
  failed: "执行失败",
  rejected: "已拒绝",
  escalated: "已升级人工",
};

const STEP_STATUS_LABELS: Record<ExecutionStep["status"], string> = {
  pending: "等待",
  running: "进行中",
  completed: "完成",
  failed: "失败",
  blocked: "已停止",
  skipped: "跳过",
};

const TOOL_LABELS: Record<string, string> = {
  rollback_deployment: "回滚 Deployment",
  restart_deployment: "重启 Deployment",
  scale_deployment: "调整副本数",
};

const SOURCE_LABELS: Record<string, string> = {
  rollout: "K8s 发布记录",
  kubernetes: "Kubernetes",
  logs: "Pod 日志",
  prometheus: "Prometheus",
  loki: "Loki",
  tempo: "Tempo",
  "kubernetes.rollout": "K8s 发布记录",
  "kubernetes.events": "K8s 事件",
  "kubernetes.logs": "Pod 日志",
  "git.change": "Git 变更",
  git_changes: "Git 变更",
  kubernetes_pods: "K8s Pods",
  kubernetes_events: "K8s 事件",
  kubernetes_logs: "Pod 日志",
  kubernetes_rollout: "K8s 发布历史",
  prometheus_errors: "Prometheus 错误率",
  prometheus_latency: "Prometheus 延迟",
  loki_errors: "Loki 错误日志",
  tempo_trace: "Tempo 链路",
};

type DemoMode = "manual" | "auto" | "reflection";

const DEMO_MODES: Array<{
  id: DemoMode;
  title: string;
  subtitle: string;
}> = [
  { id: "auto", title: "自动修复", subtitle: "自动授权安全操作" },
  { id: "manual", title: "人工审批", subtitle: "高风险操作需确认" },
  { id: "reflection", title: "复杂调查", subtitle: "证据冲突时定向补查" },
];

function timeLabel(value: string): string {
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

function durationLabel(duration: number | null): string {
  if (duration === null) return "";
  return duration < 1_000 ? `${Math.round(duration)}ms` : `${(duration / 1_000).toFixed(1)}s`;
}

function sourceLabel(source: string): string {
  return SOURCE_LABELS[source.toLowerCase()] ?? source;
}

function alertTitle(name: string): string {
  const labels: Record<string, string> = {
    HighInventoryErrorRate: "库存服务错误率过高",
    HighOrderServiceErrorRate: "订单服务错误率过高",
    InventoryTransientRuntimeFault: "库存服务瞬态运行时故障",
  };
  return labels[name] ?? name;
}

function mergeIncident(items: Incident[], updated: Incident): Incident[] {
  const next = items.some((item) => item.id === updated.id)
    ? items.map((item) => (item.id === updated.id ? updated : item))
    : [updated, ...items];
  return next.sort(
    (left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime(),
  );
}

function currentHeadline(incident: Incident, active?: ExecutionStep): string {
  if (active) return active.title;
  if (incident.status === "resolved") return "服务已恢复，验证通过";
  if (incident.status === "escalated") return "证据不足，已安全停止";
  if (incident.status === "awaiting_approval") return "等待运维人员审批";
  if (incident.status === "received") return "告警已接收，正在启动 Agent";
  return STATUS_LABELS[incident.status];
}

function IncidentQueue({
  incidents,
  selectedId,
  onSelect,
}: {
  incidents: Incident[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <aside className="incident-queue">
      <div className="queue-heading">
        <span>事故队列</span>
        <b>{incidents.length}</b>
      </div>
      <div className="queue-list">
        {incidents.length === 0 && <p className="queue-empty">等待真实告警进入…</p>}
        {incidents.map((incident) => (
          <button
            type="button"
            key={incident.id}
            className={incident.id === selectedId ? "queue-item selected" : "queue-item"}
            onClick={() => onSelect(incident.id)}
          >
            <span className={`severity ${incident.alert.severity}`} />
            <span className="queue-copy">
              <strong>{incident.alert.service}</strong>
              <small>{alertTitle(incident.alert.name)}</small>
            </span>
            <span className="queue-meta">
              <small>{timeLabel(incident.created_at)}</small>
              <b className={incident.status}>{STATUS_LABELS[incident.status]}</b>
            </span>
          </button>
        ))}
      </div>
    </aside>
  );
}

function DemoLauncher({
  mode,
  busy,
  message,
  onModeChange,
  onRun,
}: {
  mode: DemoMode;
  busy: boolean;
  message: string;
  onModeChange: (mode: DemoMode) => void;
  onRun: () => void;
}) {
  return (
    <section className="demo-launcher">
      <div className="mode-switch" aria-label="演示场景">
        {DEMO_MODES.map((item) => (
          <button
            type="button"
            key={item.id}
            className={mode === item.id ? "active" : ""}
            onClick={() => onModeChange(item.id)}
            disabled={busy}
          >
            <strong>{item.title}</strong>
            <small>{item.subtitle}</small>
          </button>
        ))}
      </div>
      <div className="launcher-action">
        <span className={busy ? "launcher-message busy" : "launcher-message"}>
          {busy && <i />}{message}
        </span>
        <button type="button" className="run-button" onClick={onRun} disabled={busy}>
          {busy ? "正在执行" : "启动演示"}
        </button>
      </div>
    </section>
  );
}

function ExecutionFlow({ incident }: { incident: Incident }) {
  const active = incident.execution_trace.find((step) => step.id === incident.active_step_id);
  const roots = incident.execution_trace.filter((step) => !step.parent_id);
  const writeCount = incident.execution_results.length;

  return (
    <section className="flow-panel">
      <div className={`now-card ${active ? "live" : incident.status}`}>
        <span className="now-indicator" />
        <div className="now-copy">
          <small>{active ? "当前执行" : "当前状态"}</small>
          <h2>{currentHeadline(incident, active)}</h2>
          <p>{active?.detail ?? `事故状态：${STATUS_LABELS[incident.status]}`}</p>
        </div>
        <div className="write-count">
          <small>集群写操作</small>
          <strong>{writeCount}</strong>
          <span>{writeCount === 0 ? "尚未修改集群" : "操作已审计"}</span>
        </div>
      </div>

      <div className="flow-heading">
        <div><h2>Agent 执行流</h2><span>节点和工具调用开始时立即更新</span></div>
        <span className="live-badge"><i /> LIVE</span>
      </div>

      <div className="flow-list" aria-live="polite">
        {roots.length === 0 && (
          <div className="flow-placeholder"><i /><span>正在建立事故上下文…</span></div>
        )}
        {roots.map((step, index) => {
          const children = incident.execution_trace.filter((item) => item.parent_id === step.id);
          return (
            <article className={`flow-step ${step.status}`} key={step.id}>
              <div className="step-rail">
                <span>{step.status === "completed" ? "✓" : step.status === "running" ? "" : index + 1}</span>
                {index < roots.length - 1 && <i />}
              </div>
              <div className="step-body">
                <div className="step-summary">
                  <div>
                    <strong>{step.title}{step.iteration > 1 ? ` · 第 ${step.iteration} 轮` : ""}</strong>
                    <small>{step.detail}</small>
                  </div>
                  <span><b>{STEP_STATUS_LABELS[step.status]}</b>{durationLabel(step.duration_ms)}</span>
                </div>
                {children.length > 0 && (
                  <div className="tool-list">
                    {children.map((child) => (
                      <div className={`tool-row ${child.status}`} key={child.id}>
                        <span className="tool-state">{child.status === "completed" ? "✓" : child.status === "running" ? "" : "!"}</span>
                        <div><strong>{child.title}</strong><small>{child.detail}</small></div>
                        <code>{durationLabel(child.duration_ms)}</code>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function ResultPanel({
  incident,
  busy,
  onDecide,
  onReset,
}: {
  incident: Incident;
  busy: boolean;
  onDecide: (approved: boolean) => void;
  onReset: () => void;
}) {
  const evidence = incident.diagnosis?.hypotheses.flatMap((item) => item.evidence) ?? [];
  const action = incident.plan?.actions[0];
  const verification = incident.timeline.find((event) => event.type === "recovery.verified");
  const errorRate = verification?.data.request_error_rate;

  return (
    <aside className="result-panel">
      <section className="result-section diagnosis-result">
        <div className="result-heading">
          <h2>诊断结论</h2>
          {incident.diagnosis && <span>{Math.round(incident.diagnosis.confidence * 100)}% 置信度</span>}
        </div>
        <p className={incident.diagnosis ? "root-cause" : "root-cause pending"}>
          {incident.diagnosis?.root_cause ?? "Agent 正在分析多源证据，结论生成后会立即显示。"}
        </p>
        {incident.diagnosis?.hypotheses[0] && (
          <div className="primary-hypothesis">
            <small>主要假设</small>
            <p>{incident.diagnosis.hypotheses[0].statement}</p>
          </div>
        )}
      </section>

      <section className="result-section remediation-result">
        <div className="result-heading"><h2>处置决策</h2></div>
        {action ? (
          <>
            <div className="action-command">
              <span>›</span>
              <div>
                <strong>{TOOL_LABELS[action.tool_name] ?? action.tool_name}</strong>
                <code>{action.tool_name} {JSON.stringify(action.arguments)}</code>
              </div>
            </div>
            <p className="action-reason">{action.rationale}</p>
          </>
        ) : (
          <p className="pending-copy">
            {incident.status === "escalated"
              ? "证据不足，Agent 未生成或执行集群写操作。"
              : "等待诊断质量门通过后生成修复方案。"}
          </p>
        )}

        {incident.status === "awaiting_approval" && (
          <div className="approval-box">
            <strong>需要人工批准</strong>
            <p>这是高风险操作，批准前不会修改集群。</p>
            <div>
              <button type="button" onClick={() => onDecide(false)} disabled={busy}>拒绝</button>
              <button type="button" className="approve" onClick={() => onDecide(true)} disabled={busy}>
                {busy ? "正在执行…" : "批准修复"}
              </button>
            </div>
          </div>
        )}
        {incident.status === "resolved" && (
          <div className="terminal-result success">
            <span>✓</span><div><strong>恢复验证通过</strong><small>错误率 {typeof errorRate === "number" ? `${(errorRate * 100).toFixed(1)}%` : "已恢复至阈值内"}</small></div>
          </div>
        )}
        {incident.status === "escalated" && (
          <div className="terminal-result stopped">
            <span>!</span><div><strong>已安全停止</strong><small>没有执行集群写操作</small></div>
            <button type="button" onClick={onReset} disabled={busy}>恢复演示基线</button>
          </div>
        )}
      </section>

      <section className="result-section evidence-result">
        <div className="result-heading"><h2>关键证据</h2><span>{evidence.length} 条</span></div>
        <div className="evidence-list">
          {evidence.length === 0 && <p className="pending-copy">证据采集中…</p>}
          {evidence.slice(0, 6).map((item: Evidence, index) => (
            <article key={`${item.source}-${index}`}>
              <span>{sourceLabel(item.source)}</span>
              <p>{item.finding}</p>
            </article>
          ))}
        </div>
      </section>

      <details className="audit-details">
        <summary>查看完整审计信息</summary>
        <div>
          <p>执行事件：{incident.timeline.length}</p>
          <p>反思轮次：{incident.reflection_rounds}</p>
          <p>事故 ID：{incident.id}</p>
          {incident.timeline.map((event, index) => (
            <p key={`${event.type}-${index}`}><time>{timeLabel(event.created_at)}</time>{event.message}</p>
          ))}
        </div>
      </details>
    </aside>
  );
}

function App() {
  const [runtime, setRuntime] = useState<RuntimeInfo | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [streamConnected, setStreamConnected] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [faultBusy, setFaultBusy] = useState(false);
  const [demoMode, setDemoMode] = useState<DemoMode>("auto");
  const [demoMessage, setDemoMessage] = useState("选择场景后启动，页面会自动跟随最新事故。");
  const [error, setError] = useState<string | null>(null);
  const knownIncidentIds = useRef(new Set<string>());

  const acceptIncident = useCallback((updated: Incident, forceFollow = false) => {
    const isNew = !knownIncidentIds.current.has(updated.id);
    knownIncidentIds.current.add(updated.id);
    setIncidents((current) => mergeIncident(current, updated));
    if (forceFollow || isNew) {
      setSelectedId(updated.id);
      setDemoMode(
        updated.execution_profile_id.startsWith("lab.bounded-reflection")
          ? "reflection"
          : updated.execution_profile_id.startsWith("lab.auto-remediation")
            ? "auto"
            : "manual",
      );
    }
    if (["received", "investigating", "remediating"].includes(updated.status)) {
      setDemoMessage("告警已进入系统，Agent 正在实时处理。无需刷新页面。");
    } else if (updated.status === "resolved") {
      setDemoMessage("自动处置完成，恢复验证已经通过。");
    } else if (updated.status === "escalated") {
      setDemoMessage("证据不足，Agent 已停止写操作并升级人工处理。");
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    async function bootstrap() {
      try {
        const [runtimeInfo, existing] = await Promise.all([api.getRuntime(), api.listIncidents()]);
        if (!mounted) return;
        setRuntime(runtimeInfo);
        existing.forEach((incident) => knownIncidentIds.current.add(incident.id));
        setIncidents((current) => existing.reduce(mergeIncident, current));
        setSelectedId((current) => current ?? existing[0]?.id ?? null);
      } catch (cause) {
        if (mounted) setError(cause instanceof Error ? cause.message : "控制台暂时不可用");
      } finally {
        if (mounted) setLoading(false);
      }
    }
    void bootstrap();
    const unsubscribe = api.subscribeIncidents(
      (incident) => mounted && acceptIncident(incident),
      (connected) => mounted && setStreamConnected(connected),
    );
    return () => {
      mounted = false;
      unsubscribe();
    };
  }, [acceptIncident]);

  const selected = incidents.find((item) => item.id === selectedId) ?? incidents[0] ?? null;
  const liveMode = runtime?.tool_backend === "kubernetes";
  const selectedMode: DemoMode = selected?.execution_profile_id.startsWith("lab.bounded-reflection")
    ? "reflection"
    : selected?.execution_profile_id.startsWith("lab.auto-remediation")
      ? "auto"
      : "manual";
  const selectedEvidence = useMemo(
    () => selected?.diagnosis?.hypotheses.flatMap((item) => item.evidence) ?? [],
    [selected],
  );

  async function injectFault() {
    setFaultBusy(true);
    setError(null);
    setDemoMessage("正在向 kind 集群注入故障…");
    try {
      let job = demoMode === "auto"
        ? await api.injectAutoDemoFault()
        : demoMode === "reflection"
          ? await api.injectReflectionDemoFault()
          : await api.injectDemoFault();
      const deadline = Date.now() + 70_000;
      while (job.status === "injecting" && Date.now() < deadline) {
        await new Promise((resolve) => window.setTimeout(resolve, 350));
        job = await api.getDemoFaultJob(job.id);
      }
      if (job.status === "injecting") throw new Error("故障注入超时，请检查本地集群状态");
      if (job.status === "failed" || !job.result) throw new Error(job.error ?? "故障注入失败");
      setDemoMessage("故障已生效，正在等待 Alertmanager 告警；告警到达后页面会立即切换。");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "故障注入失败");
      setDemoMessage("演示未启动，请根据错误信息检查环境。");
    } finally {
      setFaultBusy(false);
    }
  }

  async function createSimulatedIncident() {
    setActionBusy(true);
    setError(null);
    setDemoMessage("正在创建模拟事故并启动 Agent…");
    try {
      const incident = await api.createDemoIncident();
      acceptIncident(incident, true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法创建模拟事故");
    } finally {
      setActionBusy(false);
    }
  }

  async function decide(approved: boolean) {
    if (!selected) return;
    setActionBusy(true);
    setError(null);
    setDemoMessage(approved ? "审批已提交，Agent 正在执行并验证恢复…" : "正在拒绝本次操作…");
    try {
      acceptIncident(await api.decideIncident(selected.id, approved), true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "审批操作失败");
    } finally {
      setActionBusy(false);
    }
  }

  async function resetBaseline() {
    setActionBusy(true);
    setError(null);
    setDemoMessage("正在恢复演示基线…");
    try {
      await api.resetDemoEnvironment();
      setDemoMessage("演示环境已恢复健康，可以开始下一轮。");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法恢复演示环境");
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="product-name"><span>S</span><div><strong>SentinelOps</strong><small>Agent 事故响应控制台</small></div></div>
        <div className="header-status">
          <span><i className={streamConnected ? "connected" : ""} />{streamConnected ? "实时事件已连接" : "正在重连事件流"}</span>
          <span>{liveMode ? "真实 kind 集群" : "本地模拟环境"}</span>
        </div>
      </header>

      <DemoLauncher
        mode={demoMode}
        busy={faultBusy || actionBusy}
        message={demoMessage}
        onModeChange={setDemoMode}
        onRun={liveMode ? injectFault : createSimulatedIncident}
      />

      {error && <div className="error-banner" role="alert">{error}</div>}

      <div className="console-layout">
        <IncidentQueue incidents={incidents} selectedId={selected?.id ?? null} onSelect={setSelectedId} />
        <main className="incident-workspace">
          {loading ? (
            <div className="empty-state"><i /><strong>正在连接事故控制面…</strong></div>
          ) : !selected ? (
            <div className="empty-state"><i /><strong>等待演示开始</strong><span>启动一个场景后，这里会立即显示 Agent 的每一步动作。</span></div>
          ) : (
            <>
              <section className="incident-header">
                <div>
                  <span className={`status-pill ${selected.status}`}>{STATUS_LABELS[selected.status]}</span>
                  <h1>{alertTitle(selected.alert.name)}</h1>
                  <p>{selected.alert.service} · {selected.alert.namespace} · {timeLabel(selected.created_at)}</p>
                </div>
                <div className="incident-facts">
                  <span><small>场景</small><strong>{DEMO_MODES.find((item) => item.id === selectedMode)?.title}</strong></span>
                  <span><small>证据</small><strong>{selectedEvidence.length}</strong></span>
                  <span><small>状态</small><strong>{STATUS_LABELS[selected.status]}</strong></span>
                </div>
              </section>
              <div className="workspace-grid">
                <ExecutionFlow incident={selected} />
                <ResultPanel incident={selected} busy={actionBusy} onDecide={decide} onReset={resetBaseline} />
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
