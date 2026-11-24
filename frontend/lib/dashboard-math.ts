/** Small pure helpers behind the dashboard widgets (tested in dashboard-math.test.ts). */

/** "↑ +18% vs the 24 h before": the change from the previous 24 hours, or why there is none to compare. */
export function trendOf(total: number, previous: number): { kind: "up" | "down" | "same" | "new" | "quiet"; pct: number } {
  if (total === 0 && previous === 0) return { kind: "quiet", pct: 0 };
  if (previous === 0) return { kind: "new", pct: 0 };
  const pct = Math.round(((total - previous) / previous) * 100);
  return pct === 0 ? { kind: "same", pct } : pct > 0 ? { kind: "up", pct } : { kind: "down", pct: -pct };
}

/** A smooth line through the points (Catmull-Rom turned into cubic Béziers); never dips below the baseline. */
export function smoothPath(points: { x: number; y: number }[], floor: number): string {
  if (points.length === 0) return "";
  if (points.length === 1) return `M${points[0]!.x},${points[0]!.y}`;
  const clamp = (y: number) => Math.min(Math.max(y, 0), floor);
  let d = `M${points[0]!.x.toFixed(1)},${points[0]!.y.toFixed(1)}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[i - 1] ?? points[i]!, p1 = points[i]!, p2 = points[i + 1]!, p3 = points[i + 2] ?? p2;
    const c1 = { x: p1.x + (p2.x - p0.x) / 6, y: clamp(p1.y + (p2.y - p0.y) / 6) };
    const c2 = { x: p2.x - (p3.x - p1.x) / 6, y: clamp(p2.y - (p3.y - p1.y) / 6) };
    d += ` C${c1.x.toFixed(1)},${c1.y.toFixed(1)} ${c2.x.toFixed(1)},${c2.y.toFixed(1)} ${p2.x.toFixed(1)},${p2.y.toFixed(1)}`;
  }
  return d;
}

