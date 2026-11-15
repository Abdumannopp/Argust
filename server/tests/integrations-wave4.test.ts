/**
 * FortiGate's own webhook (the firewall sends; Legion never calls it), and host isolation through SentinelOne,
 * Microsoft Defender for Endpoint and Palo Alto Cortex XDR — behind the same approvals as every response action.
 * Vendors are simulated from their documented API shapes.
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
import { findingFromFortiEvent, fortigateAdapter, parseFortiLine } from "../src/integrations/fortigate.js";
import { HOST_RESPONSE_KINDS, RESPONSE_ADAPTERS } from "../src/integrations/response.js";
import { catalogEntry } from "../src/policy/catalog.js";
import { proposeAction, runQueued, syncWithApproval } from "../src/actions/engine.js";
import { decide } from "../src/approvals/engine.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, admin: User, admin2: User, admin3: User, adminB: User;
const now = () => Math.floor(Date.now() / 1000);
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version, auth_time: now() }, { expiresIn: "1h" })}`] as const;
const create = (u: User, body: Record<string, unknown>) => request(app).post("/integrations").set(...as(u)).send(body);
const GUID = "11111111-1111-4111-8111-111111111111";
const TOKEN = "fgt-" + "t0ken".repeat(8);

type Call = { url: string; method: string; headers: Record<string, string>; body: string };
let calls: Call[]; let respond: (c: Call) => { status: number; body?: unknown };
const realFetch = globalThis.fetch;

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
afterEach(() => { globalThis.fetch = realFetch; });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tA, tB]);
  const h = await bcrypt.hash("password123", 4);
  const mk = (email: string, t: string) => store.insertUser({ email, password_hash: h, tenant_id: t, role: "admin", status: "active" });
  admin = await mk("a1@a.io", tA); admin2 = await mk("a2@a.io", tA); admin3 = await mk("a3@a.io", tA); adminB = await mk("b@b.io", tB);
  await query("UPDATE users SET email_verified_at = now()");
  calls = []; respond = () => ({ status: 404 });
  globalThis.fetch = (async (input: URL | string, init: RequestInit = {}) => {
    const c: Call = { url: String(input), method: String(init.method ?? "GET"), headers: Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>)), body: String(init.body ?? "") };
    calls.push(c);
    const r = respond(c);
    return new Response(typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {}), { status: r.status });
  }) as typeof fetch;
});

describe("FortiGate events", () => {
  const ips = { logid: "0419016384", type: "utm", subtype: "ips", level: "alert", severity: "critical", srcip: "45.155.205.12", dstip: "10.0.0.5", attack: "Apache.Log4j.Error.Log.Remote.Code.Execution", action: "dropped", devname: "fw-01", eventtime: "1731578400000000000", msg: "%%log.msg%%", user: "N/A" };
  it("a detection becomes an alert; routine traffic and notices do not; an unfilled template variable is empty", () => {
    const f = findingFromFortiEvent(ips)!;
    expect(f).toMatchObject({ title: "FortiGate ips: Apache.Log4j.Error.Log.Remote.Code.Execution", severity: "critical", sourceIp: "45.155.205.12", target: "10.0.0.5", occurredAt: "2024-11-14T10:00:00.000Z" });
    expect(f.summary).not.toContain("%%");
    expect(f.summary).not.toContain("User:");
    expect(findingFromFortiEvent({ type: "traffic", subtype: "forward", level: "warning", msg: "x" })).toBeNull();
    expect(findingFromFortiEvent({ type: "event", subtype: "system", level: "notice", msg: "Admin logged in" })).toBeNull();
    expect(findingFromFortiEvent({ type: "event", subtype: "user", level: "alert", msg: "Administrator admin login failed", srcip: "45.155.205.12" })).toMatchObject({ severity: "critical" });
    expect(findingFromFortiEvent({ type: "utm", subtype: "virus", level: "warning" })).toBeNull();
  });
  it("raw FortiOS log lines are read too (quoted values with spaces)", () => {
    const line = `date=2026-11-14 time=10:00:00 logid="0211008192" type="utm" subtype="virus" level="warning" srcip=45.155.205.12 dstip=10.0.0.9 virus="EICAR_TEST_FILE" msg="File is infected." action="blocked" hostname="files.acme.io"`;
    expect(parseFortiLine(line)).toMatchObject({ virus: "EICAR_TEST_FILE", msg: "File is infected.", hostname: "files.acme.io" });
    const r = fortigateAdapter.normalize(`${line}\n\nnot a log line\n`);
    expect(r.skipped).toBe(false);
    if (!r.skipped) expect(r.findings[0]).toMatchObject({ title: "FortiGate virus: EICAR_TEST_FILE", severity: "medium", target: "files.acme.io" });
    for (const hostile of [null, 42, "", "=".repeat(100_000), [null, 1, "x"], { events: "nope" }]) expect(() => fortigateAdapter.normalize(hostile)).not.toThrow();
  });
});

describe("POST /security-events/webhook/fortigate", () => {
  const body = { logid: "0419016384", type: "utm", subtype: "ips", level: "alert", severity: "high", srcip: "45.155.205.12", dstip: "10.0.0.5", attack: "SQL.Injection", action: "dropped", eventtime: "1731578400000000000" };
  const send = (id: string, token: string | null, payload: unknown = body) => {
    const r = request(app).post(`/security-events/webhook/fortigate?connection=${id}`).set("content-type", "application/json");
    return (token === null ? r : r.set("authorization", `Bearer ${token}`)).send(JSON.stringify(payload));
  };
  it("the token of that connection is the proof: wrong, missing, another connection's or an unknown id all get the same 401", async () => {
    const a = (await create(admin, { kind: "fortigate", name: "fw-01", config: {}, secrets: { token: TOKEN } })).body.id as string;
    const b = (await create(adminB, { kind: "fortigate", name: "fw-b", config: {}, secrets: { token: TOKEN.replace("fgt", "bbb") } })).body.id as string;
    const bad = [await send(a, "wrong-" + TOKEN), await send(a, null), await send(a, TOKEN.replace("fgt", "bbb")), await send(randomUUID(), TOKEN), await send("not-a-uuid", TOKEN)];
    for (const r of bad) { expect(r.status).toBe(401); expect(r.body).toEqual({ detail: "Invalid request" }); }
    expect((await query("SELECT count(*)::int AS n FROM alerts")).rows[0].n).toBe(0);
    const ok = await send(a, TOKEN);
    expect(ok.status).toBe(202);
    expect(ok.body).toMatchObject({ status: "ingested" });
    const rows = (await query("SELECT tenant_id, source, title, source_ip FROM alerts WHERE source = 'fortigate'")).rows;
    expect(rows).toEqual([{ tenant_id: tA, source: "fortigate", title: "FortiGate ips: SQL.Injection", source_ip: "45.155.205.12" }]);
    // A replayed delivery adds nothing; the other workspace's connection puts its events in its own workspace.
    expect((await send(a, TOKEN)).body).toMatchObject({ status: "skipped", reason: "duplicate" });
    await send(b, TOKEN.replace("fgt", "bbb"));
    expect((await query("SELECT tenant_id FROM alerts WHERE source = 'fortigate' ORDER BY created_at")).rows.map((r) => r.tenant_id)).toEqual([tA, tB]);
    expect((await query("SELECT last_success_at IS NOT NULL AS ok FROM integration_connections WHERE id = $1", [a])).rows[0].ok).toBe(true);
  });
  it("a paused or removed connection stops accepting; a short token is refused when saving; the token is never returned", async () => {
    expect((await create(admin, { kind: "fortigate", name: "fw", config: {}, secrets: { token: "short" } })).status).toBe(400);
    const made = await create(admin, { kind: "fortigate", name: "fw", config: {}, secrets: { token: TOKEN } });
    expect(JSON.stringify(made.body)).not.toContain(TOKEN);
    await request(app).post(`/integrations/${made.body.id}/pause`).set(...as(admin));
    expect((await send(made.body.id, TOKEN)).status).toBe(401);
    expect((await send(made.body.id, TOKEN, "{not json")).status).toBe(401);
  });
});

describe("isolating a host through SentinelOne, Defender for Endpoint and Cortex XDR", () => {
  const conns = {
    sentinelone_response: { kind: "sentinelone_response", name: "S1 response", config: { console: "acme", never: [] }, secrets: { api_token: "s1-SECRET" } },
    defender_response: { kind: "defender_response", name: "MDE response", config: { directory_id: GUID, client_id: GUID, never: [] }, secrets: { client_secret: "mde-SECRET" } },
    cortex_response: { kind: "cortex_response", name: "XDR response", config: { api_host: "api-acme.xdr.eu.paloaltonetworks.com", api_key_id: "7", key_type: "standard", never: [] }, secrets: { api_key: "xdr-SECRET" } },
  } as const;
  const MID = "a".repeat(40);
  const vendor = (c: Call): { status: number; body?: unknown } => {
    if (c.url.includes("login.microsoftonline.com")) return { status: 200, body: { access_token: "tok" } };
    if (c.url.includes("sentinelone.net/web/api/v2.1/agents?")) return { status: 200, body: { data: [{ id: "1234567890123", computerName: "LAPTOP-7" }, { id: "9999999999999", computerName: "LAPTOP-70" }] } };
    if (c.url.includes("/agents/actions/")) return { status: 200, body: { data: { affected: 1 } } };
    if (c.url.includes("/api/machines?")) return { status: 200, body: { value: [{ id: MID, computerDnsName: "laptop-7" }] } };
    if (c.url.includes("/api/machines/")) return { status: 201, body: { id: "act-1", status: "Pending" } };
    if (c.url.includes("/get_endpoint/")) return { status: 200, body: { reply: { endpoints: [{ endpoint_id: "ep-12345678", endpoint_name: "LAPTOP-7" }] } } };
    if (c.url.includes("/isolate/") || c.url.includes("/unisolate/")) return { status: 200, body: { reply: { action_id: 1 } } };
    return { status: 404 };
  };
  const acting = () => calls.filter((c) => /actions\/(dis)?connect|\/(un)?isolate/.test(c.url));
  async function isolate(input: Record<string, unknown>, action = "host.isolate") {
    const { action: a } = await proposeAction(tA, { action_id: action, input, actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "live", idempotency_key: `k-${randomUUID()}` });
    expect(a.status).toBe("awaiting_approval");
    const row = (await query("SELECT approval_id, action_digest, risk_class FROM action_requests WHERE id = $1", [a.id])).rows[0];
    for (const u of row.risk_class === "R4" ? [admin2, admin3] : [admin2]) await decide(tA, row.approval_id, { userId: u.id, decision: "approve", actionDigest: row.action_digest, mfaVerified: true });
    await syncWithApproval(tA, a.id, { kind: "system", component: "test" });
    return runQueued(tA, a.id);
  }
  beforeEach(async () => { await request(app).put("/soc/protection").set(...as(admin)).send({ mode: "hybrid", auto_actions: [], acknowledge: true }).expect(200); respond = vendor; });

  it("every EDR response connector is a separate kind, and the catalog's \"via\" lists exactly them", () => {
    expect(RESPONSE_ADAPTERS.filter((a) => a.actions.includes("host.isolate")).map((a) => a.manifest.kind).sort()).toEqual([...HOST_RESPONSE_KINDS].sort());
    for (const k of HOST_RESPONSE_KINDS) expect(catalogEntry("host.isolate")!.input.safeParse({ host: "x", via: k }).success, k).toBe(true);
    expect(catalogEntry("host.isolate")!.input.safeParse({ host: "x", via: "okta_response" }).success).toBe(false);
    expect(catalogEntry("host.release")!.input.safeParse({ host: "x", via: "shell" }).success).toBe(false);
  });
  it("SentinelOne: only the endpoint whose name is exactly that one is disconnected, and reconnected on release", async () => {
    await create(admin, conns.sentinelone_response);
    expect(await isolate({ host: "LAPTOP-7" })).toMatchObject({ status: "executed", result: { did: "isolate_host", through: "SentinelOne — response" } });
    expect(acting()[0]).toMatchObject({ url: "https://acme.sentinelone.net/web/api/v2.1/agents/actions/disconnect" });
    expect(JSON.parse(acting()[0]!.body)).toEqual({ filter: { ids: ["1234567890123"] } });
    expect(acting()[0]!.headers.authorization).toBe("ApiToken s1-SECRET");
    expect(await isolate({ host: "LAPTOP-7" }, "host.release")).toMatchObject({ status: "executed", result: { did: "release_host" } });
    expect(acting()[1]!.url).toContain("/agents/actions/connect");
    respond = (c) => c.url.includes("/agents/actions/") ? { status: 200, body: { data: { affected: 0 } } } : vendor(c);
    expect(await isolate({ host: "LAPTOP-7" })).toMatchObject({ status: "failed", error: expect.stringMatching(/did not confirm/) });
  });
  it("Defender for Endpoint: token for its own API, exact DNS name, full isolation with a comment", async () => {
    await create(admin, conns.defender_response);
    expect(await isolate({ host: "LAPTOP-7" })).toMatchObject({ status: "executed", result: { did: "isolate_host" } });
    expect(new URLSearchParams(calls[0]!.body).get("scope")).toBe("https://api.securitycenter.microsoft.com/.default");
    expect(new URL(calls[1]!.url).searchParams.get("$filter")).toBe("computerDnsName eq 'laptop-7'");
    expect(acting()[0]!.url).toBe(`https://api.securitycenter.microsoft.com/api/machines/${MID}/isolate`);
    expect(JSON.parse(acting()[0]!.body)).toMatchObject({ IsolationType: "Full" });
    expect(await isolate({ host: "x' or 1 eq 1 or computerDnsName eq 'y" })).toMatchObject({ status: "failed", error: expect.stringMatching(/Not a host name/) });
    expect(acting()).toHaveLength(1);
  });
  it("Cortex XDR: looks the endpoint up by name, then isolates that endpoint id", async () => {
    await create(admin, conns.cortex_response);
    expect(await isolate({ host: "LAPTOP-7" })).toMatchObject({ status: "executed", result: { did: "isolate_host" } });
    expect(JSON.parse(calls[0]!.body).request_data.filters[0]).toEqual({ field: "hostname", operator: "in", value: ["LAPTOP-7"] });
    expect(acting()[0]!.url).toBe("https://api-acme.xdr.eu.paloaltonetworks.com/public_api/v1/endpoints/isolate/");
    expect(JSON.parse(acting()[0]!.body)).toEqual({ request_data: { endpoint_id: "ep-12345678" } });
    expect(await isolate({ host: "GHOST" })).toMatchObject({ status: "failed", error: expect.stringMatching(/knows no endpoint/) });
  });
  it("with two EDRs connected Legion does not choose: the request must say which one, and only that one is called", async () => {
    await create(admin, conns.sentinelone_response); await create(admin, conns.cortex_response);
    expect(await isolate({ host: "LAPTOP-7" })).toMatchObject({ status: "failed", error: expect.stringMatching(/say which one/) });
    expect(calls).toHaveLength(0);
    expect(await isolate({ host: "LAPTOP-7", via: "cortex_response" })).toMatchObject({ status: "executed", result: { through: "Palo Alto Cortex XDR — response" } });
    expect([...new Set(calls.map((c) => new URL(c.url).host))]).toEqual(["api-acme.xdr.eu.paloaltonetworks.com"]);
    // Naming an EDR the workspace has not connected does nothing.
    expect(await isolate({ host: "LAPTOP-7", via: "defender_response" })).toMatchObject({ status: "failed", error: expect.stringMatching(/No response connection/) });
    expect(JSON.stringify((await query("SELECT result, error FROM action_requests WHERE tenant_id = $1", [tA])).rows)).not.toContain("SECRET");
  });
});
