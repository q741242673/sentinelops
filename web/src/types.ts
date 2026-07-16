export type IncidentStatus =
  | "received"
  | "investigating"
  | "awaiting_approval"
  | "remediating"
  | "resolved"
  | "failed"
  | "rejected"
  | "escalated";

export interface Alert {
  name: string;
  namespace: string;
  service: string;
  severity: "info" | "warning" | "critical";
  summary: string;
  labels: Record<string, string>;
  starts_at: string;
}

export interface Evidence {
  source: string;
  query: string;
  finding: string;
  supports_hypothesis: boolean;
  raw: Record<string, unknown>;
}

export interface Diagnosis {
  root_cause: string;
  confidence: number;
  hypotheses: Array<{
    statement: string;
    confidence: number;
    evidence: Evidence[];
    contradictions: string[];
  }>;
  evidence_summary: string[];
}

export interface DiagnosisReview {
  sufficient: boolean;
  confidence: number;
  contradictions: string[];
  missing_evidence: string[];
  follow_up_queries: Array<{ source: string; reason: string }>;
}

export interface RemediationAction {
  tool_name: string;
  arguments: Record<string, unknown>;
  rationale: string;
  expected_outcome: string;
  risk: "read_only" | "low" | "medium" | "high" | "critical";
}

export interface RemediationPlan {
  summary: string;
  actions: RemediationAction[];
  rollback: string;
  verification: string[];
}

export interface TimelineEvent {
  type: string;
  message: string;
  data: Record<string, unknown>;
  created_at: string;
}

export interface Incident {
  id: string;
  alert: Alert;
  status: IncidentStatus;
  diagnosis: Diagnosis | null;
  diagnosis_review: DiagnosisReview | null;
  reflection_rounds: number;
  plan: RemediationPlan | null;
  approval: unknown | null;
  execution_results: Array<{
    tool_name: string;
    success: boolean;
    content: Record<string, unknown>;
    error: string | null;
    duration_ms: number;
  }>;
  timeline: TimelineEvent[];
  postmortem: string | null;
  created_at: string;
  updated_at: string;
}

export interface RuntimeInfo {
  environment: string;
  tool_backend: string;
  model_provider: string;
  model_name: string;
  namespace: string;
  approval_mode: string;
  alert_ingestion: string;
}

export interface DemoFaultResult {
  deployment?: string;
  service?: string;
  fault_active: boolean;
  already_active?: boolean;
  revision?: number | null;
  failure_every?: string;
  fault_type?: string;
}

export interface DemoFaultJob {
  id: string;
  scenario: "bad_rollout" | "transient_runtime_fault";
  status: "injecting" | "active" | "failed";
  result: DemoFaultResult | null;
  error: string | null;
}
