import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "./api";
import type { Evidence, Incident, RuntimeInfo, TimelineEvent } from "./types";

const STATUS_LABELS: Record<Incident["status"], string> = {
  received: "Received",
  investigating: "Investigating",
  awaiting_approval: "Awaiting approval",
  remediating: "Remediating",
  resolved: "Resolved",
  failed: "Failed",
  rejected: "Rejected",
};

const EVENT_LABELS: Record<string, string> = {
  "incident.received": "Alert received",
  "context.collected": "Evidence collected",
  "diagnosis.completed": "Root cause identified",
  "remediation.planned": "Remediation planned",
  "approval.requested": "Operator approval requested",
  "approval.decided": "Operator decision recorded",
  "action.executed": "Allowlisted action executed",
  "recovery.verified": "Recovery verified",
  "postmortem.generated": "Postmortem generated",
};

const FLOW_STAGES = [
  { label: "Detect", event: "incident.received" },
  { label: "Collect", event: "context.collected" },
  { label: "Diagnose", event: "diagnosis.completed" },
  { label: "Approve", event: "approval.decided", activeEvent: "approval.requested" },
  { label: "Remediate", event: "action.executed" },
  { label: "Verify", event: "recovery.verified" },
];

function shortId(id: string): string {
  return id.slice(0, 8).toUpperCase();
}

function timeLabel(value: string): string {
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

function sourceLabel(source: string): string {
  return source
    .split(/[._]/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" · ");
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
        <span>{incident.alert.name}</span>
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
  return (
    <li className="timeline-item">
      <div className="timeline-rail" aria-hidden="true">
        <span className="timeline-node" />
        {!last && <span className="timeline-line" />}
      </div>
      <div className="timeline-time">{timeLabel(event.created_at)}</div>
      <div className="timeline-copy">
        <strong>{EVENT_LABELS[event.type] ?? event.type}</strong>
        <span>{event.message}</span>
      </div>
    </li>
  );
}

function App() {
  const [runtime, setRuntime] = useState<RuntimeInfo | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState(false);
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
        if (existing.length === 0) {
          const seeded = await api.createDemoIncident();
          if (!mounted) return;
          setIncidents([seeded]);
          setSelectedId(seeded.id);
        } else {
          setIncidents(existing);
          setSelectedId(existing[0].id);
        }
      } catch (cause) {
        if (mounted) setError(cause instanceof Error ? cause.message : "Console unavailable");
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

  async function createIncident() {
    setActionBusy(true);
    setError(null);
    try {
      const incident = await api.createDemoIncident();
      setIncidents((current) => [incident, ...current]);
      setSelectedId(incident.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not start incident");
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
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Decision failed");
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
            <span>Incident Intelligence</span>
          </div>
        </div>

        <nav className="primary-nav" aria-label="Primary navigation">
          <span className="nav-label">Workspace</span>
          <button className="nav-item active" type="button">
            <span className="nav-symbol">⌁</span> Incidents
            <span className="nav-count">{incidents.length}</span>
          </button>
          <div className="nav-item muted"><span className="nav-symbol">◫</span> Policies</div>
          <div className="nav-item muted"><span className="nav-symbol">◎</span> Evaluations</div>
        </nav>

        <div className="incident-nav">
          <div className="incident-nav-head">
            <span>Recent incidents</span>
            <button type="button" onClick={createIncident} disabled={actionBusy} aria-label="New incident">
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
          <div className="runtime-title"><span className="live-dot" /> Local control plane</div>
          <dl>
            <div><dt>Tools</dt><dd>{runtime?.tool_backend ?? "—"}</dd></div>
            <div><dt>Model</dt><dd>{runtime?.model_provider ?? "—"}</dd></div>
            <div><dt>Namespace</dt><dd>{runtime?.namespace ?? "—"}</dd></div>
          </dl>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="breadcrumb"><span>Incidents</span><i>/</i>{selected ? shortId(selected.id) : "Loading"}</div>
          <div className="topbar-meta">
            <span className="connection"><i /> API connected</span>
            <span className="operator-avatar">OP</span>
          </div>
        </header>

        {error && <div className="error-banner" role="alert">{error}</div>}

        {loading || !selected ? (
          <section className="loading-state">
            <div className="loading-orbit"><span /></div>
            <strong>Preparing incident workspace</strong>
            <span>Connecting the local Agent control plane…</span>
          </section>
        ) : (
          <div className="workspace">
            <section className="incident-hero">
              <div>
                <div className="eyebrow">
                  <span className={`status-pill ${selected.status}`}>{STATUS_LABELS[selected.status]}</span>
                  <span>INC-{shortId(selected.id)}</span>
                </div>
                <h1>{selected.alert.name}</h1>
                <p>{selected.alert.summary}</p>
                <div className="hero-context">
                  <span>{selected.alert.namespace}</span>
                  <i />
                  <span>{selected.alert.service}</span>
                  <i />
                  <span>Started {timeLabel(selected.created_at)}</span>
                </div>
              </div>
              <button className="secondary-button" type="button" onClick={createIncident} disabled={actionBusy}>
                <span>+</span> Run new simulation
              </button>
            </section>

            <section className="stat-grid" aria-label="Incident summary">
              <article><span>Severity</span><strong className="critical-text">Critical</strong><small>SLO breach detected</small></article>
              <article><span>AI confidence</span><strong>{Math.round((selected.diagnosis?.confidence ?? 0) * 100)}%</strong><small>Evidence-backed diagnosis</small></article>
              <article><span>Evidence</span><strong>{evidence.length}</strong><small>Correlated sources</small></article>
              <article><span>Safety mode</span><strong>Human gate</strong><small>No autonomous high-risk action</small></article>
            </section>

            <section className="flow-card">
              <div className="section-heading compact">
                <div><span className="section-kicker">AGENT EXECUTION</span><h2>Incident response graph</h2></div>
                <span className="graph-engine">LangGraph · checkpointed</span>
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
                      <span>{state === "complete" ? "Complete" : state === "active" ? "Waiting" : "Queued"}</span>
                    </div>
                  );
                })}
              </div>
            </section>

            <div className="content-grid">
              <section className="diagnosis-column">
                <article className="panel diagnosis-panel">
                  <div className="section-heading">
                    <div><span className="section-kicker">MODEL OUTPUT</span><h2>Root cause analysis</h2></div>
                    <span className="confidence-ring">{Math.round((selected.diagnosis?.confidence ?? 0) * 100)}<small>%</small></span>
                  </div>
                  <blockquote>{selected.diagnosis?.root_cause ?? "Collecting diagnostic evidence…"}</blockquote>
                  <div className="hypothesis-row">
                    <span>Primary hypothesis</span>
                    <p>{selected.diagnosis?.hypotheses[0]?.statement ?? "Pending"}</p>
                  </div>
                </article>

                <section className="panel evidence-panel">
                  <div className="section-heading">
                    <div><span className="section-kicker">CORRELATED CONTEXT</span><h2>Evidence trail</h2></div>
                    <span className="verified-label"><i /> verified sources</span>
                  </div>
                  <div className="evidence-grid">
                    {evidence.map((item, index) => <EvidenceCard key={`${item.source}-${index}`} evidence={item} index={index} />)}
                  </div>
                </section>
              </section>

              <aside className="action-column">
                <section className="panel action-panel">
                  <div className="section-heading">
                    <div><span className="section-kicker">PROPOSED ACTION</span><h2>Remediation plan</h2></div>
                    {action && <span className={`risk-badge ${action.risk}`}>{action.risk} risk</span>}
                  </div>
                  {action ? (
                    <>
                      <div className="tool-call">
                        <span className="terminal-prompt">›</span>
                        <div><strong>{action.tool_name}</strong><code>{JSON.stringify(action.arguments)}</code></div>
                      </div>
                      <p className="rationale">{action.rationale}</p>
                      <div className="outcome-box"><span>Expected outcome</span><p>{action.expected_outcome}</p></div>
                      <div className="verification-list">
                        <span>Verification criteria</span>
                        {selected.plan?.verification.map((item) => <p key={item}><i>✓</i>{item}</p>)}
                      </div>
                    </>
                  ) : <p className="muted-copy">The Agent is still preparing a safe remediation.</p>}

                  {selected.status === "awaiting_approval" && (
                    <div className="approval-gate">
                      <div className="approval-warning"><span>!</span><p><strong>Operator approval required</strong>High-risk actions cannot execute autonomously.</p></div>
                      <div className="approval-actions">
                        <button type="button" className="reject-button" onClick={() => decide(false)} disabled={actionBusy}>Reject</button>
                        <button type="button" className="approve-button" onClick={() => decide(true)} disabled={actionBusy}>{actionBusy ? "Executing…" : "Approve rollback"}</button>
                      </div>
                    </div>
                  )}

                  {selected.status === "resolved" && (
                    <div className="resolved-card">
                      <span className="resolved-icon">✓</span>
                      <div><strong>Recovery verified</strong><p>Error rate {typeof requestErrorRate === "number" ? `${(requestErrorRate * 100).toFixed(1)}%` : "below 1%"} · service healthy</p></div>
                    </div>
                  )}
                  {selected.status === "rejected" && <div className="rejected-card">Automation stopped by operator.</div>}
                </section>
              </aside>
            </div>

            <section className="panel timeline-panel">
              <div className="section-heading">
                <div><span className="section-kicker">AUDIT LOG</span><h2>Incident timeline</h2></div>
                <span className="event-count">{selected.timeline.length} events</span>
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
