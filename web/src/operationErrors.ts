import type { IncidentStatus } from "./types";

export interface ConsoleError {
  message: string;
  operation?: {
    kind: "approval-timeout";
    incidentId: string;
  };
}

const TERMINAL_INCIDENT_STATUSES = new Set<IncidentStatus>([
  "resolved",
  "failed",
  "rejected",
  "escalated",
]);

export function consoleError(message: string): ConsoleError {
  return { message };
}

export function approvalTimeoutError(message: string, incidentId: string): ConsoleError {
  return {
    message,
    operation: { kind: "approval-timeout", incidentId },
  };
}

export function clearStaleApprovalTimeout(
  current: ConsoleError | null,
  incidentId: string,
  status: IncidentStatus,
): ConsoleError | null {
  if (
    current?.operation?.kind === "approval-timeout"
    && current.operation.incidentId === incidentId
    && TERMINAL_INCIDENT_STATUSES.has(status)
  ) {
    return null;
  }
  return current;
}

export function isTerminalIncidentStatus(status: IncidentStatus): boolean {
  return TERMINAL_INCIDENT_STATUSES.has(status);
}
