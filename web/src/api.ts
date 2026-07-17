import type { DemoFaultJob, Incident, RuntimeInfo } from "./types";

export const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
export const APPROVAL_REQUEST_TIMEOUT_MS = 90_000;
export const DEMO_RESET_REQUEST_TIMEOUT_MS = 60_000;

const DEFAULT_TIMEOUT_MESSAGE = "请求超时，请确认本地 API、Docker Desktop 和 kind 集群正在运行";
const APPROVAL_TIMEOUT_MESSAGE =
  "审批请求等待超时，操作可能仍在后台执行，请以实时事故状态为准";
const DEMO_RESET_TIMEOUT_MESSAGE =
  "恢复请求等待超时，操作可能仍在后台执行，请以实时状态为准";

interface RequestOptions extends RequestInit {
  timeoutMs?: number;
  timeoutMessage?: string;
}

export class RequestTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestTimeoutError";
  }
}

function isAbortError(cause: unknown): boolean {
  return cause instanceof Error && cause.name === "AbortError";
}

async function request<T>(path: string, requestOptions: RequestOptions = {}): Promise<T> {
  const {
    timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
    timeoutMessage = DEFAULT_TIMEOUT_MESSAGE,
    ...options
  } = requestOptions;
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {
      ...options,
      headers: { "Content-Type": "application/json", ...options.headers },
      signal: controller.signal,
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail ?? `请求失败，HTTP 状态码 ${response.status}`);
    }
    return response.json() as Promise<T>;
  } catch (cause) {
    if (isAbortError(cause)) {
      throw new RequestTimeoutError(timeoutMessage);
    }
    throw cause;
  } finally {
    globalThis.clearTimeout(timeout);
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
      timeoutMs: DEMO_RESET_REQUEST_TIMEOUT_MS,
      timeoutMessage: DEMO_RESET_TIMEOUT_MESSAGE,
    }),
  decideIncident: (
    incidentId: string,
    approvalId: string,
    approvalVersion: number,
    approved: boolean,
  ) =>
    request<Incident>(`/api/v1/incidents/${incidentId}/approval`, {
      method: "POST",
      timeoutMs: approved ? APPROVAL_REQUEST_TIMEOUT_MS : DEFAULT_REQUEST_TIMEOUT_MS,
      timeoutMessage: approved ? APPROVAL_TIMEOUT_MESSAGE : DEFAULT_TIMEOUT_MESSAGE,
      body: JSON.stringify({
        approval_id: approvalId,
        approval_version: approvalVersion,
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
