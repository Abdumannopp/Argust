import { describe, expect, it } from "vitest";
import { smoothPath, trendOf } from "./dashboard-math";

describe("trendOf: the change from the 24 hours before", () => {
  it("says up, down or the same, in whole percent", () => {
    expect(trendOf(118, 100)).toEqual({ kind: "up", pct: 18 });
    expect(trendOf(50, 100)).toEqual({ kind: "down", pct: 50 });
    expect(trendOf(10, 10)).toEqual({ kind: "same", pct: 0 });
  });
  it("never divides by zero: nothing before is 'new', nothing at all is 'quiet'", () => {
    expect(trendOf(5, 0)).toEqual({ kind: "new", pct: 0 });
    expect(trendOf(0, 0)).toEqual({ kind: "quiet", pct: 0 });
    expect(trendOf(0, 4)).toEqual({ kind: "down", pct: 100 });
  });
});

describe("smoothPath: the activity line", () => {
  const pts = [{ x: 0, y: 100 }, { x: 10, y: 20 }, { x: 20, y: 100 }, { x: 30, y: 60 }];
  it("starts at the first point and ends at the last", () => {
    const d = smoothPath(pts, 100);
    expect(d.startsWith("M0.0,100.0")).toBe(true);
    expect(d.endsWith("30.0,60.0")).toBe(true);
    expect((d.match(/C/g) ?? []).length).toBe(3);
  });
  it("never leaves the chart: control points stay between the top and the baseline", () => {
    const nums = [...smoothPath([{ x: 0, y: 100 }, { x: 10, y: 0 }, { x: 20, y: 100 }], 100).matchAll(/[\d.]+,([\d.]+)/g)].map((m) => Number(m[1]));
    for (const y of nums) { expect(y).toBeGreaterThanOrEqual(0); expect(y).toBeLessThanOrEqual(100); }
  });
  it("copes with no points and one point", () => {
    expect(smoothPath([], 100)).toBe("");
    expect(smoothPath([{ x: 3, y: 4 }], 100)).toBe("M3,4");
  });
});
