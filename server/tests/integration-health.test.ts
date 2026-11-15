/** The integration engine's one view: health, freshness and volume of every connection, and "check now". */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { ingestFindings } from "../src/integrations/ingest.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, adminA: User, adminB: User, viewerA: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const create = async (u: User, body: Record<string, unknown>) => (await request(app).post("/integrations").set(...bearer(u)).send(body)).body.id as string;
const health = async (u: User) => (await request(app).get("/integrations/health").set(...bearer(u))).body;
const GUID = "11111111-1111-4111-8111-111111111111";
const okta = { kind: "okta", name: "Okta", config: { domain: "acme.okta.com" }, secrets: { api_token: "00abc" } };
const slack = { kind: "slack", name: "Slack", config: { min_severity: "high" }, secrets: { webhook_url: "https://hooks.slack.com/services/T0/B0/xyz" } };
const vt = { kind: "virustotal", name: "VT", config: {}, secrets: { api_key: "a".repeat(64) } };

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

describe("GET /integrations/health", () => {
  it("administrators only; another workspace's connections are not in it", async () => {
    await create(adminA, okta);
    expect((await request(app).get("/integrations/health").set(...bearer(viewerA))).status).toBe(403);
    expect((await request(app).get("/integrations/health")).status).toBe(401);
    expect((await health(adminB)).connections).toEqual([]);
    expect((await health(adminA)).connections).toHaveLength(1);
  });
  it("tells the direction of each connection and what state it is in", async () => {
    const o = await create(adminA, okta); const s = await create(adminA, slack); const v = await create(adminA, vt);
    let h = await health(adminA);
    const by = (id: string) => h.connections.find((c: { id: string }) => c.id === id);
    expect(by(o)).toMatchObject({ direction: "in", health: "waiting", alerts_24h: 0, queued: null });
    expect(by(s)).toMatchObject({ direction: "out", health: "waiting", alerts_24h: null, queued: 0, undelivered: 0 });
    expect(by(v)).toMatchObject({ direction: "intel", alerts_24h: null, queued: null });
    expect(h.summary).toEqual({ total: 3, ok: 3, attention: 0, paused: 0 });

    await query("UPDATE integration_connections SET last_success_at = now() WHERE id = $1", [o]);
    await query("UPDATE integration_connections SET failures = 3, last_error = 'Slack answered 500' WHERE id = $1", [s]);
    await query("UPDATE integration_connections SET status = 'error', failures = 10 WHERE id = $1", [v]);
    h = await health(adminA);
    expect(by(o).health).toBe("ok");
    expect(by(s)).toMatchObject({ health: "failing", failures: 3, last_error: "Slack answered 500" });
    expect(by(v).health).toBe("stopped");
    expect(h.summary).toEqual({ total: 3, ok: 1, attention: 2, paused: 0 });

    await request(app).post(`/integrations/${o}/pause`).set(...bearer(adminA));
    expect((await health(adminA)).summary.paused).toBe(1);
  });
  it("a pull connection that has not been polled for long is overdue", async () => {
    const o = await create(adminA, okta);
    await query("UPDATE integration_connections SET last_success_at = now() - interval '5 hours', next_poll_at = now() - interval '4 hours' WHERE id = $1", [o]);
    expect((await health(adminA)).connections[0].health).toBe("overdue");
  });
  it("counts what each vendor brought in and what is still to be sent; secrets never appear", async () => {
    const o = await create(adminA, okta); await create(adminA, slack);
    const f = (id: string, severity: "high" | "low") => ({ externalId: id, title: id, severity, summary: "s", occurredAt: null, sourceIp: "198.51.100.9", target: "u@acme.io", mitre: [], confidence: 70, asset: null });
    await ingestFindings(tA, "okta", [f("a", "high"), f("b", "low")]);
    await ingestFindings(tA, "wazuh", [f("c", "high")]);
    await ingestFindings(tB, "okta", [f("z", "high")]);
    const h = await health(adminA);
    expect(h.connections.find((c: { id: string }) => c.id === o).alerts_24h).toBe(2);
    expect(h.connections.find((c: { kind: string }) => c.kind === "slack").queued).toBeGreaterThan(0);
    expect(h.sources.find((x: { source: string }) => x.source === "wazuh")).toMatchObject({ alerts_24h: 1 });
    expect(h.sources.find((x: { source: string }) => x.source === "okta")).toMatchObject({ alerts_24h: 2 });
    expect(JSON.stringify(h)).not.toMatch(/00abc|hooks\.slack\.com|secrets/);
  });
});

describe("POST /integrations/:id/check", () => {
  it("brings a working pull connection's next poll forward; not for outbound, paused or another workspace's", async () => {
    const o = await create(adminA, okta); const s = await create(adminA, slack);
    await query("UPDATE integration_connections SET next_poll_at = now() + interval '1 hour' WHERE id = $1", [o]);
    expect((await request(app).post(`/integrations/${o}/check`).set(...bearer(adminB))).status).toBe(404);
    expect((await request(app).post(`/integrations/${o}/check`).set(...bearer(viewerA))).status).toBe(403);
    expect((await query("SELECT next_poll_at > now() AS later FROM integration_connections WHERE id = $1", [o])).rows[0].later).toBe(true);
    expect((await request(app).post(`/integrations/${o}/check`).set(...bearer(adminA))).status).toBe(200);
    expect((await query("SELECT next_poll_at <= now() AS due FROM integration_connections WHERE id = $1", [o])).rows[0].due).toBe(true);
    expect((await request(app).post(`/integrations/${s}/check`).set(...bearer(adminA))).status).toBe(404);
    expect((await request(app).post(`/integrations/${GUID}/check`).set(...bearer(adminA))).status).toBe(404);
    await request(app).post(`/integrations/${o}/pause`).set(...bearer(adminA));
    expect((await request(app).post(`/integrations/${o}/check`).set(...bearer(adminA))).status).toBe(404);
  });
});
