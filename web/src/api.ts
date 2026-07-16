import type { DemoFaultJob, Incident, RuntimeInfo } from "./types";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(path, {
      headers: { "Content-Type": "application/json", ...options?.headers },
      ...options,
      signal: controller.signal,
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail ?? `请求失败，HTTP 状态码 ${response.status}`);
    }
    return response.json() as Promise<T>;
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") {
      throw new Error("请求超时，请确认本地 API、Docker Desktop 和 kind 集群正在运行");
    }
    throw cause;
  } finally {
    window.clearTimeout(timeout);
  }
}

export const api = {
  listIncidents: () => request<Incident[]>("/api/v1/incidents"),
  getRuntime: () => request<RuntimeInfo>("/api/v1/runtime"),
  createDemoIncident: () =>
    request<Incident>("/api/v1/demo/incidents", {
      method: "POST",
    }),
  injectDemoFault: () =>
    request<DemoFaultJob>("/api/v1/demo/faults", {
      method: "POST",
    }),
  injectAutoDemoFault: () =>
    request<DemoFaultJob>("/api/v1/demo/auto-faults", {
      method: "POST",
    }),
  injectReflectionDemoFault: () =>
    request<DemoFaultJob>("/api/v1/demo/reflection-faults", {
      method: "POST",
    }),
  getDemoFaultJob: (jobId: string) =>
    request<DemoFaultJob>(`/api/v1/demo/faults/${jobId}`),
  resetDemoEnvironment: () =>
    request<{ baseline_restored: boolean }>("/api/v1/demo/reset", {
      method: "POST",
    }),
  decideIncident: (incidentId: string, approved: boolean) =>
    request<Incident>(`/api/v1/incidents/${incidentId}/approval`, {
      method: "POST",
      body: JSON.stringify({
        approved,
        note: approved
          ? "已从 SentinelOps 本地控制台批准"
          : "已从 SentinelOps 本地控制台拒绝",
      }),
    }),
  subscribeIncidents: (
    onUpdate: (incident: Incident) => void,
    onConnectionChange?: (connected: boolean) => void,
  ) => {
    const source = new EventSource("/api/v1/incidents/events");
    source.onopen = () => onConnectionChange?.(true);
    source.onerror = () => onConnectionChange?.(false);
    source.onmessage = (event) => onUpdate(JSON.parse(event.data) as Incident);
    return () => source.close();
  },
};
