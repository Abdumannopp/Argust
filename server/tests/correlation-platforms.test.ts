/** Correlation across platforms (campaigns.ts, rule multi_platform): one attack seen by several security tools becomes one campaign. */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { ingestFindings } from "../src/integrations/ingest.js";
import { CORRELATION_SOURCE, listCampaigns } from "../src/campaigns.js";
import { AUTO_RULES } from "../src/blocklist.js";
import type { Finding } from "../src/integrations/types.js";

let tA: string, tB: string;
const IP = "45.155.205.12";
let n = 0;
const f = (extra: Partial<Finding> = {}): Finding => ({ externalId: `e${++n}`, title: `Alert ${n}`, severity: "medium", summary: "detail", occurredAt: null, sourceIp: IP, target: "web-1", mitre: [], confidence: 70, asset: null, ...extra });
const multi = async (t: string) => (await listCampaigns(t)).filter((c) => c.rule === "multi_platform");

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
});

describe("the same attacking address in two platforms", () => {
  it("becomes one campaign with one alert that names the platforms; more alerts do not announce it again", async () => {
    await ingestFindings(tA, "crowdstrike", [f({ target: "LAPTOP-7" })]);
    expect(await multi(tA)).toHaveLength(0);
    const report = await ingestFindings(tA, "okta", [f({ target: "jane@acme.io" })]);
    const found = await multi(tA);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ subject: IP, sources: [IP] });
    expect(found[0]!.targets.sort()).toEqual(["LAPTOP-7", "jane@acme.io"]);
    expect(report.campaigns).toContain(found[0]!.id);
    const alert = (await query("SELECT title, summary, severity, agent, source_ip FROM alerts WHERE tenant_id = $1 AND source = $2", [tA, CORRELATION_SOURCE])).rows;
    expect(alert).toHaveLength(1);
    expect(alert[0]).toMatchObject({ severity: "high", agent: "Hunter", source_ip: IP });
    expect(alert[0].title).toContain("2 platforms");
    expect(alert[0].summary).toMatch(/crowdstrike/);
    expect(alert[0].summary).toMatch(/okta/);
    await ingestFindings(tA, "guardduty", [f({ target: "i-0abc" })]);
    await ingestFindings(tA, "okta", [f()]);
    expect((await query("SELECT count(*)::int AS n FROM alerts WHERE tenant_id = $1 AND source = $2 AND title LIKE 'One attack seen%'", [tA, CORRELATION_SOURCE])).rows[0].n).toBe(1);
  });
  it("one platform alone, however many alerts, is not it; nor is Argust's own alert a platform", async () => {
    await ingestFindings(tA, "okta", [f(), f(), f()]);
    await ingestFindings(tA, "legion-payments", [f()]);
    expect(await multi(tA)).toHaveLength(0);
  });
  it("events older than the window do not count", async () => {
    await ingestFindings(tA, "crowdstrike", [f({ occurredAt: new Date(Date.now() - 3 * 3600_000).toISOString() })]);
    await ingestFindings(tA, "okta", [f()]);
    expect(await multi(tA)).toHaveLength(0);
  });
  it("another workspace's alerts are never joined", async () => {
    await ingestFindings(tA, "crowdstrike", [f()]);
    await ingestFindings(tB, "okta", [f()]);
    expect(await multi(tA)).toHaveLength(0);
    expect(await multi(tB)).toHaveLength(0);
  });
});

describe("the same host or account in two platforms", () => {
  it("needs a high or critical alert from each: ordinary noise on a busy server is not an attack", async () => {
    await ingestFindings(tA, "wazuh", [f({ sourceIp: null, severity: "medium" })]);
    await ingestFindings(tA, "sentinelone", [f({ sourceIp: null, severity: "high" })]);
    expect(await multi(tA)).toHaveLength(0);
    await ingestFindings(tA, "wazuh", [f({ sourceIp: null, severity: "critical" })]);
    const found = await multi(tA);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ subject: "web-1", sources: [] });
    const alert = (await query("SELECT target, source_ip, summary FROM alerts WHERE tenant_id = $1 AND source = $2", [tA, CORRELATION_SOURCE])).rows[0];
    expect(alert).toMatchObject({ target: "web-1", source_ip: null });
    expect(alert.summary).toMatch(/sentinelone/);
  });
});

describe("what it never does", () => {
  it("is not a reason to block automatically: it joins evidence, a person decides", () => {
    expect(AUTO_RULES.has("multi_platform")).toBe(false);
  });
});
