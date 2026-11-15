import { describe, expect, it } from "vitest";
import { stillInEffect } from "./response-undo";
import type { ExecutedAction } from "./api";

const a = (id: string, action_id: string, target: string, minutesAgo: number, input: Record<string, unknown> = {}): ExecutedAction =>
  ({ id, action_id, target, input, status: "executed", result: null, created_at: new Date(Date.now() - minutesAgo * 60_000).toISOString() });

describe("what is still isolated or suspended", () => {
  it("is the newest action per host or account, when that action is isolate or disable", () => {
    const list = stillInEffect([
      a("1", "host.isolate", "LAPTOP-7", 60), a("2", "host.release", "laptop-7", 30),          // released again
      a("3", "host.isolate", "WEB-1", 20),                                                       // still isolated
      a("4", "account.disable", "okta:jane@acme.io", 50), a("5", "account.enable", "okta:jane@acme.io", 55), // re-suspended after a restore
      a("6", "ip.block", "45.155.205.12", 5), a("7", "notify.admins", "administrators", 1),      // not response actions
    ]);
    expect(list.map((x) => x.id).sort()).toEqual(["3", "4"]);
  });
  it("a host and an account with the same name are separate; nothing executed means nothing listed", () => {
    expect(stillInEffect([a("1", "host.isolate", "x", 10), a("2", "account.enable", "x", 5)]).map((x) => x.id)).toEqual(["1"]);
    expect(stillInEffect([])).toEqual([]);
  });
});
