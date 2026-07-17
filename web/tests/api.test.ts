import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  api,
  APPROVAL_REQUEST_TIMEOUT_MS,
  DEFAULT_REQUEST_TIMEOUT_MS,
  RequestTimeoutError,
} from "../src/api";

function pendingFetch() {
  return vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
    new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => {
        reject(new DOMException("The operation was aborted", "AbortError"));
      });
    }));
}

describe("endpoint request timeouts", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("keeps ordinary requests and rejected approvals on the 15 second fast path", async () => {
    vi.stubGlobal("fetch", pendingFetch());

    const ordinaryRequest = api.getRuntime();
    const rejectedApproval = api.decideIncident("inc-1", "approval-1", 1, false);
    const ordinaryResult = expect(ordinaryRequest).rejects.toBeInstanceOf(RequestTimeoutError);
    const rejectedResult = expect(rejectedApproval).rejects.toBeInstanceOf(RequestTimeoutError);

    await vi.advanceTimersByTimeAsync(DEFAULT_REQUEST_TIMEOUT_MS - 1);
    expect(fetch).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);

    await Promise.all([ordinaryResult, rejectedResult]);
  });

  it("allows an approved remediation to succeed after the ordinary timeout", async () => {
    const responseBody = { id: "inc-1", status: "resolved" };
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>((resolve) => {
      globalThis.setTimeout(() => {
        resolve(new Response(JSON.stringify(responseBody), {
          headers: { "Content-Type": "application/json" },
        }));
      }, DEFAULT_REQUEST_TIMEOUT_MS + 1_000);
    })));

    const request = api.decideIncident("inc-1", "approval-1", 1, true);
    await vi.advanceTimersByTimeAsync(DEFAULT_REQUEST_TIMEOUT_MS + 1_000);

    await expect(request).resolves.toEqual(responseBody);
  });

  it("uses an approval timeout that covers the 30-round recovery verification window", async () => {
    vi.stubGlobal("fetch", pendingFetch());

    const request = api.decideIncident("inc-1", "approval-1", 1, true);
    const result = expect(request).rejects.toMatchObject({
      name: "RequestTimeoutError",
      message: expect.stringContaining("操作可能仍在后台执行，请以实时事故状态为准"),
    });
    await vi.advanceTimersByTimeAsync(APPROVAL_REQUEST_TIMEOUT_MS - 1);
    await vi.advanceTimersByTimeAsync(1);

    await result;
  });

  it("starts reset as a fast background job and exposes a polling endpoint", async () => {
    const job = { id: "reset-1", status: "resetting", result: null, error: null };
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => Promise.resolve(
      new Response(JSON.stringify(job), { headers: { "Content-Type": "application/json" } }),
    )));

    await expect(api.resetDemoEnvironment()).resolves.toEqual(job);
    await expect(api.getDemoResetJob("reset-1")).resolves.toEqual(job);

    expect(fetch).toHaveBeenNthCalledWith(1, "/api/v1/demo/reset", expect.objectContaining({ method: "POST" }));
    expect(fetch).toHaveBeenNthCalledWith(2, "/api/v1/demo/resets/reset-1", expect.any(Object));
  });

  it("explains that a reset submission may already be running when its response times out", async () => {
    vi.stubGlobal("fetch", pendingFetch());

    const request = api.resetDemoEnvironment();
    const result = expect(request).rejects.toMatchObject({
      name: "RequestTimeoutError",
      message: expect.stringContaining("任务可能已经在后台运行"),
    });
    await vi.advanceTimersByTimeAsync(DEFAULT_REQUEST_TIMEOUT_MS);

    await result;
  });
});
