import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "./api";
import type { Evidence, Incident, RuntimeInfo, TimelineEvent } from "./types";

const STATUS_LABELS: Record<Incident["status"], string> = {
  received: "已接收",
  investigating: "调查中",
  awaiting_approval: "等待审批",
  remediating: "修复中",
  resolved: "已恢复",
  failed: "修复失败",
  rejected: "已拒绝",
};

const EVENT_LABELS: Record<string, string> = {
  "incident.received": "收到告警",
  "context.collected": "完成证据采集",
  "diagnosis.completed": "定位根因",
  "remediation.planned": "生成修复方案",
  "approval.requested": "请求人工审批",
  "approval.decided": "记录审批决定",
  "action.executed": "执行白名单操作",
  "recovery.verified": "确认服务恢复",
  "postmortem.generated": "生成事故报告",
};

const FLOW_STAGES = [
  { label: "检测", event: "incident.received" },
  { label: "取证", event: "context.collected" },
  { label: "诊断", event: "diagnosis.completed" },
  { label: "审批", event: "approval.decided", activeEvent: "approval.requested" },
  { label: "修复", event: "action.executed" },
  { label: "验证", event: "recovery.verified" },
];

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

function shortId(id: string): string {
  return id.slice(0, 8).toUpperCase();
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
  };
  return labels[source.toLowerCase()] ?? source;
}

function alertTitle(name: string): string {
  const labels: Record<string, string> = {
    HighInventoryErrorRate: "库存服务错误率过高",
    HighOrderServiceErrorRate: "订单服务错误率过高",
  };
  return labels[name] ?? name;
}

function alertSummary(summary: string): string {
  if (summary.includes("Inventory HTTP 503")) return "库存服务 HTTP 503 错误率超过结账链路 SLO";
  if (summary.includes("Order service error rate")) return "订单服务错误率超过 5% SLO 阈值";
  return summary;
}

function stageState(incident: Incident, event: string, activeEvent?: string): string {
  const events = new Set(incident.timeline.map((item) => item.type));
  if (events.has(event)) return "complete";
  if (activeEvent && events.has(activeEvent)) return "active";
  if (incident.status === "failed" || incident.status === "rejected") return "stopped";
  return "pending";
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

function DemoRunbook({
  liveMode,
  faultBusy,
  actionBusy,
  faultReady,
  incident,
  message,
  onInject,
  onInvestigate,
}: {
  liveMode: boolean;
  faultBusy: boolean;
  actionBusy: boolean;
  faultReady: boolean;
  incident: Incident | null;
  message: string | null;
  onInject: () => void;
  onInvestigate: () => void;
}) {
  const investigated = Boolean(incident);
  const approved = incident?.timeline.some((event) => event.type === "approval.decided") ?? false;
  return (
    <section className="demo-runbook">
      <div className="demo-runbook-head">
        <div>
          <span className="section-kicker">本地真实演示</span>
          <h2>故障注入与自动修复</h2>
        </div>
        <span className="demo-mode"><i />{liveMode ? "真实 kind 集群" : "Simulator 模式"}</span>
      </div>
      <div className="demo-steps">
        <article className={faultReady ? "complete" : "active"}>
          <span className="demo-step-number">1</span>
          <div><strong>注入故障</strong><p>让 inventory-service 每 3 次请求失败 1 次</p></div>
          <button type="button" onClick={onInject} disabled={faultBusy || actionBusy}>
            {faultBusy ? "正在注入…" : faultReady ? "再次检查" : "注入真实故障"}
          </button>
        </article>
        <article className={investigated ? "complete" : faultReady ? "active" : ""}>
          <span className="demo-step-number">2</span>
          <div><strong>AI 调查</strong><p>关联 K8s、Prometheus、Loki 与 Tempo 证据</p></div>
          <button type="button" onClick={onInvestigate} disabled={faultBusy || actionBusy}>
            {actionBusy ? "DeepSeek 调查中…" : "开始 AI 调查"}
          </button>
        </article>
        <article className={approved ? "complete" : incident?.status === "awaiting_approval" ? "active" : ""}>
          <span className="demo-step-number">3</span>
          <div><strong>批准并验证</strong><p>检查回滚版本，批准后自动验证错误率</p></div>
          <span className="demo-step-state">
            {incident?.status === "resolved" ? "修复完成" : incident?.status === "awaiting_approval" ? "请在右侧批准" : "等待调查结果"}
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
  const [faultReady, setFaultReady] = useState(false);
  const [demoMessage, setDemoMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadIncidents = useCallback(async () => {
    const next = await api.listIncidents();
    setIncidents(next);
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

  const selected = incidents.find((item) => item.id === selectedId) ?? incidents[0] ?? null;
  const evidence = useMemo(
    () => selected?.diagnosis?.hypotheses.flatMap((hypothesis) => hypothesis.evidence) ?? [],
    [selected],
  );
  const action = selected?.plan?.actions[0] ?? null;
  const verification = selected?.timeline.find((event) => event.type === "recovery.verified");
  const requestErrorRate = verification?.data.request_error_rate;
  const liveMode = runtime?.tool_backend === "kubernetes";

  async function injectFault() {
    setFaultBusy(true);
    setError(null);
    setDemoMessage(null);
    try {
      const result = await api.injectDemoFault();
      setFaultReady(true);
      setDemoMessage(
        result.already_active
          ? `故障已经存在：revision ${result.revision ?? "—"}，可以直接开始 AI 调查。`
          : `故障已注入：revision ${result.revision ?? "—"}，inventory-service 每 3 次请求失败 1 次。`,
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
    setDemoMessage("正在等待真实 502 请求、Prometheus 告警和 Tempo Trace，然后交给 DeepSeek 调查…");
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
            <button type="button" onClick={createIncident} disabled={actionBusy} aria-label="新建事故调查">
              +
            </button>
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
            <div><dt>模型</dt><dd>{runtime?.model_name ?? "—"}</dd></div>
            <div><dt>模型协议</dt><dd>{runtime?.model_provider ?? "—"}</dd></div>
            <div><dt>命名空间</dt><dd>{runtime?.namespace ?? "—"}</dd></div>
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
              liveMode={liveMode}
              faultBusy={faultBusy}
              actionBusy={actionBusy}
              faultReady={faultReady}
              incident={null}
              message={demoMessage}
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
              liveMode={liveMode}
              faultBusy={faultBusy}
              actionBusy={actionBusy}
              faultReady={faultReady}
              incident={selected}
              message={demoMessage}
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
              <article><span>AI 置信度</span><strong>{Math.round((selected.diagnosis?.confidence ?? 0) * 100)}%</strong><small>基于多源证据的诊断</small></article>
              <article><span>关联证据</span><strong>{evidence.length}</strong><small>跨系统关联的数据源</small></article>
              <article><span>安全模式</span><strong>人工审批门</strong><small>高风险操作不会自动执行</small></article>
            </section>

            <section className="flow-card">
              <div className="section-heading compact">
                <div><span className="section-kicker">AGENT 执行过程</span><h2>事故响应状态图</h2></div>
                <span className="graph-engine">LangGraph · 支持检查点恢复</span>
              </div>
              <div className="flow-stages">
                {FLOW_STAGES.map((stage, index) => {
                  const state = stageState(selected, stage.event, stage.activeEvent);
                  return (
                    <div className={`flow-stage ${state}`} key={stage.label}>
                      <div className="stage-track">
                        <span className="stage-node">{state === "complete" ? "✓" : index + 1}</span>
                        {index < FLOW_STAGES.length - 1 && <span className="stage-line" />}
                      </div>
                      <strong>{stage.label}</strong>
                      <span>{state === "complete" ? "完成" : state === "active" ? "等待中" : "排队中"}</span>
                    </div>
                  );
                })}
              </div>
            </section>

            <div className="content-grid">
              <section className="diagnosis-column">
                <article className="panel diagnosis-panel">
                  <div className="section-heading">
                    <div><span className="section-kicker">模型输出</span><h2>根因分析</h2></div>
                    <span className="confidence-ring">{Math.round((selected.diagnosis?.confidence ?? 0) * 100)}<small>%</small></span>
                  </div>
                  <blockquote>{selected.diagnosis?.root_cause ?? "正在采集诊断证据…"}</blockquote>
                  <div className="hypothesis-row">
                    <span>主要假设</span>
                    <p>{selected.diagnosis?.hypotheses[0]?.statement ?? "等待模型分析"}</p>
                  </div>
                </article>

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
                  ) : <p className="muted-copy">Agent 正在准备安全的修复方案。</p>}

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
