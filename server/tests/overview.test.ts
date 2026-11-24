/**
 * The first screen's answers (src/overview.ts): what is protected, what
 * threats are open, what Argust blocked and why, what is left to set up —
 * computed from this workspace's records only.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { issueCredential, sendSigned } from "./helpers/webhook.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, adminA: User, viewerA: User, adminB: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const get = async (u: User) => (await request(app).get("/overview").set(...bearer(u))).body;
const event = (id: string, level = 12) => ({ provider: "wazuh", event: { id, rule: { level, description: `rule ${id}` }, agent: { name: "web-01" } } });

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tA, role: "admin", status: "active" });
  viewerA = await store.insertUser({ email: "viewer@alpha.io", password_hash: hash, tenant_id: tA, role: "viewer", status: "active" });
  adminB = await store.insertUser({ email: "admin@bravo.io", password_hash: hash, tenant_id: tB, role: "admin", status: "active" });
});

describe("protection status", () => {
  it("walks from not connected, to waiting, to attention, to protected", async () => {
    let o = await get(viewerA);
    expect(o).toMatchObject({ status: "not_connected", reasons: ["no_sources"] });
    expect(o.onboarding.steps.map((s: { id: string; done: boolean }) => [s.id, s.done])).toEqual([
      ["connect", false], ["first_event", false], ["notifications", false], ["team", true], ["agent", false]]);

    const cred = await issueCredential(tA, "HQ manager");
    o = await get(viewerA);
    expect(o).toMatchObject({ status: "waiting_for_data", reasons: ["no_events_yet"] });
    expect(o.protected.sources).toEqual([{ kind: "wazuh", name: "HQ manager", health: "waiting", last_event_at: null }]);

    // A test alert is not a sensor event.
    expect((await request(app).post("/security-events/test").set(...bearer(adminA))).status).toBe(201);
    expect((await get(viewerA)).status).toBe("waiting_for_data");

    expect((await sendSigned(app, cred, event("e1", 12))).status).toBe(202);
    o = await get(viewerA);
    expect(o.status).toBe("attention");
    expect(o.reasons).toContain("open_critical");
    expect(o.protected.sources[0]).toMatchObject({ health: "receiving" });
    expect(o.protected.assets).toBe(1);
    expect(o.threats).toMatchObject({ open: { critical: 1, low: 1 }, open_total: 2 });
    expect(o.threats.top[0]).toMatchObject({ severity: "critical", title: "rule e1" });

    // Resolving what is open (a resolved alert is not a threat any more).
    for (const a of await store.listAlerts(tA)) await store.updateAlertStatus(tA, a.id, "resolved");
    await query("UPDATE tenants SET notification_email = 'soc@alpha.io' WHERE id = $1", [tA]);
    o = await get(viewerA);
    expect(o).toMatchObject({ status: "protected", reasons: [], threats: { open_total: 0 } });
    expect(o.onboarding.complete).toBe(true);
  });

  it("a sensor that went quiet needs attention", async () => {
    const cred = await issueCredential(tA);
    await sendSigned(app, cred, event("e1", 3));
    await query("UPDATE alerts SET status = 'resolved' WHERE tenant_id = $1", [tA]);
    await query("UPDATE webhook_credentials SET last_used_at = now() - interval '1 day' WHERE tenant_id = $1", [tA]);
    const o = await get(viewerA);
    expect(o.protected.sources[0].health).toBe("silent");
    expect(o.reasons).toContain("source_silent");
  });

  it("shows what Argust blocked, with the rule, for this workspace only", async () => {
    const created = await request(app).post("/agents").set(...bearer(adminA)).send({ name: "exfil-bot", permissions: ["tool.database:read"] });
    const token = (await request(app).post("/agent/v1/token").set("Authorization", `Bearer ${created.body.credential.secret}`)).body.access_token;
    await request(app).post("/agent/v1/tools/authorize").set("Authorization", `Bearer ${token}`)
      .send({ call: { kind: "database", operation: "query", sql: "SELECT id FROM alerts WHERE tenant_id = $1 LIMIT 5", params: [tB] } });
    const o = await get(viewerA);
    expect(o.blocked).toMatchObject({ window_days: 7, refused: 1, contained: 1 });
    expect(o.blocked.recent[0]).toMatchObject({ agent_name: "exfil-bot", decision: "QUARANTINE", rules: expect.arrayContaining(["sql.foreign_tenant"]) });
    expect(o.reasons).toContain("agent_contained");
    expect((await get(adminB)).blocked).toMatchObject({ refused: 0, recent: [] });
  });
});

describe("dashboard activity, campaigns and blocks", () => {
  const alertAt = (tenant: string, id: string, hoursAgo: number) => query(
    `INSERT INTO alerts (id, tenant_id, title, severity, agent, status, summary, confidence, source, created_at)
     VALUES ($1, $2, $1, 'high', 'Sentinel', 'open', 's', 70, 'wazuh', now() - make_interval(mins => $3))`, [id, tenant, Math.round(hoursAgo * 60)]);
  it("counts alerts per hour for the last 24 hours, and the 24 before them, for this workspace only", async () => {
    await alertAt(tA, "a1", 0.2); await alertAt(tA, "a2", 0.3); await alertAt(tA, "a3", 5.5); await alertAt(tA, "a4", 30); await alertAt(tA, "a5", 40); await alertAt(tA, "old", 60);
    await alertAt(tB, "b1", 0.2);
    const o = await get(viewerA);
    expect(o.activity.hours).toHaveLength(24);
    expect(o.activity.hours.reduce((n: number, h: { count: number }) => n + h.count, 0)).toBe(3);
    expect(o.activity.total_24h).toBe(3);
    expect(o.activity.previous_24h).toBe(2);
    // Oldest first, one entry per hour, the last one is the current hour.
    const times = o.activity.hours.map((h: { at: string }) => Date.parse(h.at));
    expect(times).toEqual([...times].sort((a: number, b: number) => a - b));
    expect(times[23] - times[0]).toBe(23 * 3600_000);
    expect((await get(adminB)).activity).toMatchObject({ total_24h: 1, previous_24h: 0 });
  });
  it("counts campaigns that are still going and addresses blocked right now", async () => {
    const campaign = (id: string, tenant: string, lastSeenMinutes: number, status = "active") => query(
      `INSERT INTO attack_campaigns (tenant_id, id, rule, subject, status, alert_count, sources, targets, techniques, last_seen)
       VALUES ($1, $2, 'velocity', $2, $4, 5, '{}', '{}', '{}', now() - make_interval(mins => $3))`, [tenant, id, lastSeenMinutes, status]);
    await campaign("CMP-1", tA, 5); await campaign("CMP-2", tA, 600); await campaign("CMP-3", tA, 5, "closed"); await campaign("CMP-4", tB, 5);
    const block = (ip: string, tenant: string, expiresMinutes: number, revoked = false) => query(
      `INSERT INTO ip_blocks (tenant_id, id, ip, reason, expires_at, revoked_at) VALUES ($1, $2, $3, 'test', now() + make_interval(mins => $4), ${revoked ? "now()" : "NULL"})`, [tenant, randomUUID(), ip, expiresMinutes]);
    await block("45.155.205.12", tA, 60); await block("45.155.205.13", tA, -5); await block("45.155.205.14", tA, 60, true); await block("45.155.205.15", tB, 60);
    const o = await get(viewerA);
    expect(o).toMatchObject({ campaigns_active: 1, blocks_active: 1 });
    expect(await get(adminB)).toMatchObject({ campaigns_active: 1, blocks_active: 1 });
  });
});

describe("the test alert and the permission catalogue", () => {
  it("test alerts are admin-only, labelled, and capped", async () => {
    expect((await request(app).post("/security-events/test").set(...bearer(viewerA))).status).toBe(403);
    const r = await request(app).post("/security-events/test").set(...bearer(adminA));
    const alert = await store.getAlert(tA, r.body.alert_id);
    expect(alert).toMatchObject({ source: "legion-test", severity: "low", title: "Test alert: Argust is working" });
    for (let i = 0; i < 9; i++) await request(app).post("/security-events/test").set(...bearer(adminA));
    expect((await request(app).post("/security-events/test").set(...bearer(adminA))).status).toBe(429);
  });

  it("lists every agent permission with its risk tier and whether it asks a person first", async () => {
    const r = (await request(app).get("/agent-permissions").set(...bearer(viewerA))).body;
    const byId = Object.fromEntries(r.permissions.map((p: { id: string }) => [p.id, p]));
    expect(byId["alerts:read"]).toEqual({ id: "alerts:read", tier: 0, asks_first: false });
    expect(byId["tool.slack:write"]).toEqual({ id: "tool.slack:write", tier: 2, asks_first: true });
    expect(r.never).toContain("manage_people");
  });
});
