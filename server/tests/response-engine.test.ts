/**
 * Response engine: acting in a customer's own systems (isolate a host in the EDR, suspend an account in the
 * identity provider) — only through a separate response connection, only after people approved that exact action.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { proposeAction, runQueued, syncWithApproval, type Proposal } from "../src/actions/engine.js";
import { decide } from "../src/approvals/engine.js";
import * as registry from "../src/integrations/registry.js";
import { RESPONSE_ADAPTERS } from "../src/integrations/response.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, admin: User, admin2: User, admin3: User, analyst: User, adminB: User;
const now = () => Math.floor(Date.now() / 1000);
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version, auth_time: now() }, { expiresIn: "1h" })}`] as const;
const key = () => `k-${randomUUID()}`;
const byAgent = (action_id: string, input: unknown, over: Partial<Proposal> = {}): Proposal =>
  ({ action_id, input, actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "live", idempotency_key: key(), ...over });
const create = (u: User, body: Record<string, unknown>) => request(app).post("/integrations").set(...as(u)).send(body);
const CID = "0123456789abcdef0123456789abcdef";
const AID = "a".repeat(32);
const falcon = (never: string[] = []) => ({ kind: "crowdstrike_response", name: "Falcon response", config: { cloud: "eu-1", client_id: CID, never }, secrets: { client_secret: "falcon-SECRET-1" } });
const okta = (never: string[] = []) => ({ kind: "okta_response", name: "Okta response", config: { domain: "acme.okta.com", never }, secrets: { api_token: "okta-SECRET-1" } });

type Call = { url: string; method: string; headers: Record<string, string>; body: string };
let calls: Call[]; let respond: (c: Call) => { status: number; body?: unknown };
const realFetch = globalThis.fetch;
const acting = () => calls.filter((c) => /devices-actions|lifecycle/.test(c.url));

/** Two different people approve (each with a verified second factor), then the engine picks it up. */
async function approveAndRun(tenantId: string, actionId: string, approvers: User[]) {
  const a = (await query("SELECT approval_id, action_digest FROM action_requests WHERE id = $1", [actionId])).rows[0];
  for (const u of approvers) await decide(tenantId, a.approval_id, { userId: u.id, decision: "approve", actionDigest: a.action_digest, mfaVerified: true });
  await syncWithApproval(tenantId, actionId, { kind: "system", component: "test" });
  return runQueued(tenantId, actionId);
}

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
afterEach(() => { globalThis.fetch = realFetch; });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tA, tB]);
  const h = await bcrypt.hash("password123", 4);
  const mk = (email: string, tenant: string, role: "admin" | "analyst") => store.insertUser({ email, password_hash: h, tenant_id: tenant, role, status: "active" });
  admin = await mk("a1@a.io", tA, "admin"); admin2 = await mk("a2@a.io", tA, "admin"); admin3 = await mk("a3@a.io", tA, "admin");
  analyst = await mk("an@a.io", tA, "analyst"); adminB = await mk("b@b.io", tB, "admin");
  await query("UPDATE users SET email_verified_at = now()");
  // The administrator turned protection on (hybrid, nothing pre-authorised): live actions exist, none runs on its own.
  await request(app).put("/soc/protection").set(...as(admin)).send({ mode: "hybrid", auto_actions: [], acknowledge: true }).expect(200);
  calls = []; respond = () => ({ status: 404 });
  globalThis.fetch = (async (input: URL | string, init: RequestInit = {}) => {
    const c: Call = { url: String(input), method: String(init.method ?? "GET"), headers: Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>)), body: String(init.body ?? "") };
    calls.push(c);
    const r = respond(c);
    return new Response(typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {}), { status: r.status });
  }) as typeof fetch;
});
const falconOk = (c: Call) => c.url.includes("/oauth2/token") ? { status: 201, body: { access_token: "tok" } }
  : c.url.includes("/devices/queries/") ? { status: 200, body: { resources: [AID] } }
  : { status: 202, body: { resources: [{ id: AID }] } };

describe("response connections", () => {
  it("are separate from the read-only ones, administrators only, and are never polled or sent alerts", async () => {
    expect((await create(analyst, falcon())).status).toBe(403);
    expect((await create(admin, falcon())).status).toBe(201);
    expect((await create(admin, okta())).status).toBe(201);
    for (const a of RESPONSE_ADAPTERS) {
      expect(a.manifest.kind.endsWith("_response")).toBe(true);
      expect(registry.pullKinds()).not.toContain(a.manifest.kind);
      expect(registry.outboundKinds()).not.toContain(a.manifest.kind);
      expect(registry.intelKinds()).not.toContain(a.manifest.kind);
    }
    // The connection that brings alerts in cannot act.
    for (const k of ["crowdstrike", "okta", "sentinelone", "m365"]) expect(registry.responseAdapter(k), k).toBeNull();
    const list = (await request(app).get("/integrations").set(...as(admin))).body;
    expect(JSON.stringify(list)).not.toContain("SECRET");
  });
  it("the Okta domain and the Falcon client id are checked when saving", async () => {
    expect((await create(admin, { ...okta(), config: { domain: "evil.com" } })).status).toBe(400);
    expect((await create(admin, { ...falcon(), config: { cloud: "eu-1", client_id: "nope" } })).status).toBe(400);
  });
});

describe("isolating a host", () => {
  it("waits for two people; nothing is sent before; then Falcon is asked to contain exactly that device, and it is audited", async () => {
    await create(admin, falcon());
    respond = falconOk;
    const { action } = await proposeAction(tA, byAgent("host.isolate", { host: "LAPTOP-7", reason: "ransomware signs" }));
    expect(action).toMatchObject({ status: "awaiting_approval", risk_class: "R4" });
    await runQueued(tA, action.id);
    expect(calls).toHaveLength(0);
    // One approval is not enough for a critical action.
    const a = (await query("SELECT approval_id, action_digest FROM action_requests WHERE id = $1", [action.id])).rows[0];
    await decide(tA, a.approval_id, { userId: admin.id, decision: "approve", actionDigest: a.action_digest, mfaVerified: true });
    await syncWithApproval(tA, action.id, { kind: "system", component: "test" });
    expect((await runQueued(tA, action.id))?.status).toBe("awaiting_approval");
    expect(calls).toHaveLength(0);
    // …and never without a second-factor code.
    await expect(decide(tA, a.approval_id, { userId: admin2.id, decision: "approve", actionDigest: a.action_digest, mfaVerified: false })).rejects.toThrow(/two-factor/);
    await decide(tA, a.approval_id, { userId: admin2.id, decision: "approve", actionDigest: a.action_digest, mfaVerified: true });
    await syncWithApproval(tA, action.id, { kind: "system", component: "test" });
    const done = await runQueued(tA, action.id);
    expect(done).toMatchObject({ status: "executed", result: { did: "isolate_host", target: "LAPTOP-7" } });
    expect(acting()).toHaveLength(1);
    expect(acting()[0]!.url).toBe("https://api.eu-1.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain");
    expect(JSON.parse(acting()[0]!.body)).toEqual({ ids: [AID] });
    expect(new URL(calls.find((c) => c.url.includes("/devices/queries/"))!.url).searchParams.get("filter")).toBe("hostname:'LAPTOP-7'");
    expect((await query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1 AND action = 'security.response.host.isolate'", [tA])).rows[0].n).toBe(1);
    // Done once: running it again does nothing.
    await runQueued(tA, action.id);
    expect(acting()).toHaveLength(1);
    expect(JSON.stringify(done)).not.toContain("SECRET");
  });
  it("the person who asked cannot approve their own request", async () => {
    await create(admin, falcon());
    const r = await request(app).post("/actions").set(...as(admin)).send({ action_id: "host.isolate", input: { host: "LAPTOP-7" }, mode: "live", idempotency_key: key() });
    expect(r.body.action.status).toBe("awaiting_approval");
    const a = (await query("SELECT approval_id, action_digest FROM action_requests WHERE id = $1", [r.body.action.id])).rows[0];
    await expect(decide(tA, a.approval_id, { userId: admin.id, decision: "approve", actionDigest: a.action_digest, mfaVerified: true })).rejects.toThrow(/yourself/);
    // An analyst cannot start a real action at all.
    expect((await request(app).post("/actions").set(...as(analyst)).send({ action_id: "host.isolate", input: { host: "LAPTOP-7" }, mode: "live", idempotency_key: key() })).status).toBe(403);
  });
  it("declines, with nothing done: no such device, two devices with the name, a protected host, a name that is not a host name", async () => {
    await create(admin, falcon(["DC-01"]));
    const run = async (host: string) => { const { action } = await proposeAction(tA, byAgent("host.isolate", { host })); return approveAndRun(tA, action.id, [admin, admin2]); };
    respond = (c) => c.url.includes("/devices/queries/") ? { status: 200, body: { resources: [] } } : falconOk(c);
    expect(await run("GHOST-1")).toMatchObject({ status: "failed", error: expect.stringMatching(/refused: CrowdStrike knows no device/) });
    respond = (c) => c.url.includes("/devices/queries/") ? { status: 200, body: { resources: [AID, "b".repeat(32)] } } : falconOk(c);
    expect(await run("TWIN-1")).toMatchObject({ status: "failed", error: expect.stringMatching(/does not guess/) });
    respond = falconOk;
    expect(await run("dc-01")).toMatchObject({ status: "failed", error: expect.stringMatching(/never-touch/) });
    expect(await run("x' OR hostname:'*")).toMatchObject({ status: "failed", error: expect.stringMatching(/Not a host name/) });
    expect(acting()).toHaveLength(0);
  });
  it("with no response connection, or with protection turned off after approval, nothing is done", async () => {
    const first = (await proposeAction(tA, byAgent("host.isolate", { host: "LAPTOP-7" }))).action;
    expect(await approveAndRun(tA, first.id, [admin, admin2])).toMatchObject({ status: "failed", error: expect.stringMatching(/No response connection/) });
    await create(admin, falcon()); respond = falconOk;
    const second = (await proposeAction(tA, byAgent("host.isolate", { host: "LAPTOP-8" }))).action;
    const a = (await query("SELECT approval_id, action_digest FROM action_requests WHERE id = $1", [second.id])).rows[0];
    for (const u of [admin, admin2]) await decide(tA, a.approval_id, { userId: u.id, decision: "approve", actionDigest: a.action_digest, mfaVerified: true });
    await syncWithApproval(tA, second.id, { kind: "system", component: "test" });
    await request(app).put("/soc/protection").set(...as(admin)).send({ mode: "manual" }).expect(200);
    expect((await runQueued(tA, second.id))?.status).toBe("cancelled");
    expect(calls).toHaveLength(0);
  });
  it("another workspace's response connection is never used", async () => {
    await create(adminB, falcon()); respond = falconOk;
    const { action } = await proposeAction(tA, byAgent("host.isolate", { host: "LAPTOP-7" }));
    expect(await approveAndRun(tA, action.id, [admin, admin2])).toMatchObject({ status: "failed", error: expect.stringMatching(/No response connection/) });
    expect(calls).toHaveLength(0);
  });
  it("a failure keeps the credential out of the stored error, and the action is not retried", async () => {
    await create(admin, falcon());
    respond = (c) => c.url.includes("/oauth2/token") ? { status: 201, body: { access_token: "tok" } } : c.url.includes("/devices/queries/") ? { status: 200, body: { resources: [AID] } } : { status: 500, body: "boom falcon-SECRET-1" };
    const { action } = await proposeAction(tA, byAgent("host.isolate", { host: "LAPTOP-7" }));
    const done = await approveAndRun(tA, action.id, [admin, admin2]);
    expect(done!.status).toBe("failed");
    expect(JSON.stringify(done)).not.toContain("SECRET");
    expect(String((await query("SELECT last_error FROM integration_connections WHERE tenant_id = $1", [tA])).rows[0].last_error)).not.toContain("SECRET");
    const before = calls.length;
    await runQueued(tA, action.id);
    expect(calls).toHaveLength(before);
  });
});

describe("the way back, and accounts", () => {
  it("releasing a host and restoring an account go through the same door; an administrator's own request runs, a machine's waits", async () => {
    await create(admin, falcon()); await create(admin, okta());
    respond = (c) => c.url.includes("okta.com") ? { status: 200, body: {} } : falconOk(c);
    const machine = (await proposeAction(tA, byAgent("host.release", { host: "LAPTOP-7" }))).action;
    expect(machine).toMatchObject({ status: "awaiting_approval", risk_class: "R3" });
    const r = await request(app).post("/actions").set(...as(admin)).send({ action_id: "host.release", input: { host: "LAPTOP-7" }, mode: "live", idempotency_key: key() });
    expect(r.body.action).toMatchObject({ status: "executed", result: { did: "release_host" } });
    expect(acting().at(-1)!.url).toContain("action_name=lift_containment");
    const e = await request(app).post("/actions").set(...as(admin)).send({ action_id: "account.enable", input: { account: "jane@acme.io", system: "okta" }, mode: "live", idempotency_key: key() });
    expect(e.body.action).toMatchObject({ status: "executed", result: { did: "restore_account" } });
    expect(acting().at(-1)!.url).toBe("https://acme.okta.com/api/v1/users/jane%40acme.io/lifecycle/unsuspend");
  });
  it("suspending an account: approved by two people, sent to Okta with the response token only; other systems have no connector", async () => {
    await create(admin, okta(["ceo@acme.io"]));
    respond = () => ({ status: 200, body: {} });
    const { action } = await proposeAction(tA, byAgent("account.disable", { account: "jane@acme.io", system: "okta" }));
    expect(action.status).toBe("awaiting_approval");
    expect(await approveAndRun(tA, action.id, [admin2, admin3])).toMatchObject({ status: "executed", result: { did: "suspend_account", target: "jane@acme.io" } });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ method: "POST", url: "https://acme.okta.com/api/v1/users/jane%40acme.io/lifecycle/suspend" });
    expect(calls[0]!.headers.authorization).toBe("SSWS okta-SECRET-1");
    const run = async (input: Record<string, unknown>) => { const p = await proposeAction(tA, byAgent("account.disable", input)); return approveAndRun(tA, p.action.id, [admin, admin2]); };
    expect(await run({ account: "ceo@acme.io", system: "okta" })).toMatchObject({ status: "failed", error: expect.stringMatching(/never-touch/) });
    expect(await run({ account: "jane@acme.io", system: "entra" })).toMatchObject({ status: "failed", error: expect.stringMatching(/No response connection/) });
    expect(await run({ account: "../../admin", system: "okta" })).toMatchObject({ status: "failed", error: expect.stringMatching(/Not an account name/) });
    respond = () => ({ status: 404, body: {} });
    expect(await run({ account: "ghost@acme.io", system: "okta" })).toMatchObject({ status: "failed", error: expect.stringMatching(/knows no account/) });
    expect(calls.filter((c) => c.url.includes("suspend"))).toHaveLength(2);
  });
});
