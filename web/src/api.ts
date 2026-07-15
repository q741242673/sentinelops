import type { Incident, RuntimeInfo } from "./types";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail ?? `Request failed with HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  listIncidents: () => request<Incident[]>("/api/v1/incidents"),
  getRuntime: () => request<RuntimeInfo>("/api/v1/runtime"),
  createDemoIncident: () =>
    request<Incident>("/api/v1/incidents", {
      method: "POST",
      body: JSON.stringify({
        name: "HighOrderServiceErrorRate",
        namespace: "sentinelops-demo",
        service: "order-service",
        severity: "critical",
        summary: "Order service error rate exceeded the 5% SLO threshold",
        labels: { source: "local-console", scenario: "bad_rollout" },
      }),
    }),
  decideIncident: (incidentId: string, approved: boolean) =>
    request<Incident>(`/api/v1/incidents/${incidentId}/approval`, {
      method: "POST",
      body: JSON.stringify({
        approved,
        note: approved
          ? "Approved from the SentinelOps local console"
          : "Rejected from the SentinelOps local console",
      }),
    }),
};
