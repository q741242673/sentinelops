import { describe, expect, it } from "vitest";

import {
  approvalTimeoutError,
  clearStaleApprovalTimeout,
  consoleError,
  errorForSelectedIncident,
} from "../src/operationErrors";

describe("approval timeout convergence", () => {
  it.each(["resolved", "failed", "rejected", "escalated"] as const)(
    "clears the matching approval timeout when SSE or GET reports %s",
    (status) => {
      const timeout = approvalTimeoutError("审批超时", "inc-1");

      expect(clearStaleApprovalTimeout(timeout, "inc-1", status)).toBeNull();
    },
  );

  it("does not clear the timeout while the same incident is still running", () => {
    const timeout = approvalTimeoutError("审批超时", "inc-1");

    expect(clearStaleApprovalTimeout(timeout, "inc-1", "remediating")).toBe(timeout);
  });

  it("does not clear another incident's timeout or an unrelated error", () => {
    const timeout = approvalTimeoutError("审批超时", "inc-1");
    const unrelated = consoleError("事件流连接失败");

    expect(clearStaleApprovalTimeout(timeout, "inc-2", "resolved")).toBe(timeout);
    expect(clearStaleApprovalTimeout(unrelated, "inc-1", "resolved")).toBe(unrelated);
  });

  it("only displays an approval timeout while its incident is selected", () => {
    const timeout = approvalTimeoutError("审批超时", "inc-1");

    expect(errorForSelectedIncident(timeout, "inc-1")).toBe(timeout);
    expect(errorForSelectedIncident(timeout, "inc-2")).toBeNull();
    expect(errorForSelectedIncident(consoleError("连接失败"), "inc-2")).toEqual({
      message: "连接失败",
    });
  });
});
