import { describe, expect, it } from "vitest";

import {
  clusterConnectionCounts,
  filterIncidentsByCluster,
  relativeLastSeenLabel,
} from "../src/App";

describe("cluster directory presentation", () => {
  it("filters already loaded incidents without changing their order", () => {
    const incidents = [
      { id: "inc-b-new", alert: { cluster_id: "cluster-b" } },
      { id: "inc-a", alert: { cluster_id: "cluster-a" } },
      { id: "inc-b-old", alert: { cluster_id: "cluster-b" } },
    ];

    expect(filterIncidentsByCluster(incidents, "cluster-b").map((item) => item.id)).toEqual([
      "inc-b-new",
      "inc-b-old",
    ]);
    expect(filterIncidentsByCluster(incidents, null)).toBe(incidents);
  });

  it("counts connected and heartbeat-timeout clusters separately", () => {
    expect(clusterConnectionCounts([
      { connection_status: "online" },
      { connection_status: "offline" },
      { connection_status: "online" },
    ])).toEqual({ online: 2, offline: 1 });
  });

  it("formats last heartbeat as a compact relative time", () => {
    const now = Date.parse("2026-07-27T08:00:00Z");

    expect(relativeLastSeenLabel("2026-07-27T07:59:55Z", now)).toBe("刚刚");
    expect(relativeLastSeenLabel("2026-07-27T07:59:30Z", now)).toBe("30 秒前");
    expect(relativeLastSeenLabel("2026-07-27T07:55:00Z", now)).toBe("5 分钟前");
    expect(relativeLastSeenLabel("2026-07-27T06:00:00Z", now)).toBe("2 小时前");
    expect(relativeLastSeenLabel(null, now)).toBe("尚无心跳");
    expect(relativeLastSeenLabel("not-a-date", now)).toBe("心跳时间未知");
  });
});
