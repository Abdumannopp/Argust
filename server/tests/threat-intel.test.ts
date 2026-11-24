/**
 * Threat intelligence (VirusTotal, MISP, OpenCTI): what is sent where, what the answers become, and what can
 * never happen — a private address leaving, a customer host pointing inside, a key in an error, another
 * workspace's source being asked.
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
import { ingestFindings, findingAlertId } from "../src/integrations/ingest.js";
import * as registry from "../src/integrations/registry.js";
import { guardedFetch, transport, validCustomerHost } from "../src/integrations/guarded-fetch.js";
import { answerFromVirusTotal } from "../src/integrations/virustotal.js";
import { answerFromMisp } from "../src/integrations/misp.js";
import { answerFromOpenCti } from "../src/integrations/opencti.js";
import { clearIntelCache, lookupIndicators, vetIndicator } from "../src/threat-intel.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, adminA: User, adminB: User, viewerA: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const create = (u: User, body: Record<string, unknown>) => request(app).post("/integrations").set(...bearer(u)).send(body);
const VT_KEY = "a".repeat(64);
const IP = "45.155.205.12";

type Call = { url: string; method: string; headers: Record<string, string>; body: string };
let calls: Call[]; let respond: (c: Call) => { status: number; body?: unknown };
const realFetch = globalThis.fetch; const realResolve = transport.resolve; const realSend = transport.send;
let resolveTo: { address: string; family: number }[];
const vt = (malicious: number, harmless = 60) => ({ data: { attributes: { last_analysis_stats: { malicious, suspicious: 0, harmless, undetected: 10 }, last_analysis_date: Math.floor(Date.now() / 1000) - 3600, as_owner: "Bad Hosting", country: "NL" } } });

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll(); clearIntelCache();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tA, role: "admin", status: "active" });
  viewerA = await store.insertUser({ email: "viewer@alpha.io", password_hash: hash, tenant_id: tA, role: "viewer", status: "active" });
  adminB = await store.insertUser({ email: "admin@bravo.io", password_hash: hash, tenant_id: tB, role: "admin", status: "active" });
  calls = []; respond = () => ({ status: 404 }); resolveTo = [{ address: "93.184.216.34", family: 4 }];
  const record = (url: string, init: { method?: string; headers?: unknown; body?: unknown }) => {
    const c: Call = { url, method: String(init.method ?? "GET"), headers: Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>)), body: String(init.body ?? "") };
    calls.push(c); return respond(c);
  };
  globalThis.fetch = (async (input: URL | string, init: RequestInit = {}) => {
    const r = record(String(input), init);
    return new Response(typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {}), { status: r.status });
  }) as typeof fetch;
  transport.resolve = async () => resolveTo;
  transport.send = async (host, _addr, path, init) => { const r = record(`https://${host}${path}`, init); return { status: r.status, body: typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {}) }; };
});
afterEach(() => { globalThis.fetch = realFetch; transport.resolve = realResolve; transport.send = realSend; });

describe("catalogue and connections", () => {
  it("the three sources are available, read only, and never polled or sent alerts", async () => {
    const cat = (await request(app).get("/integrations/catalogue").set(...bearer(adminA))).body.integrations as { kind: string }[];
    for (const k of ["virustotal", "misp", "opencti"]) {
      expect(cat.find((c) => c.kind === k), k).toMatchObject({ status: "available", plane: "data", inbound: null, outbound: [], intel: true });
      expect(registry.pullKinds()).not.toContain(k);
      expect(registry.outboundKinds()).not.toContain(k);
    }
    expect(registry.intelKinds().sort()).toEqual(["abuseipdb", "misp", "opencti", "virustotal"]);
  });
  it("a customer host must be a public DNS name: no address, no internal name, no URL", async () => {
    for (const bad of ["10.0.0.5", "127.0.0.1", "localhost", "misp.local", "misp.internal", "https://misp.example.com", "misp.example.com/x", "misp", "169.254.169.254", "[::1]"]) {
      expect(validCustomerHost(bad), bad).toBe(false);
      expect((await create(adminA, { kind: "misp", name: "M", config: { host: bad }, secrets: { api_key: "k" } })).status, bad).toBe(400);
    }
    expect((await create(adminA, { kind: "misp", name: "M", config: { host: "misp.example.com" }, secrets: { api_key: "k" } })).status).toBe(201);
    expect((await create(viewerA, { kind: "virustotal", name: "VT", config: {}, secrets: { api_key: VT_KEY } })).status).toBe(403);
  });
});

describe("the guarded fetch for customer hosts", () => {
  it("refuses a name that resolves inside — every address must be public", async () => {
    for (const inside of ["10.1.2.3", "127.0.0.1", "169.254.169.254", "192.168.1.1", "::1", "fd00::1", "::ffff:10.0.0.1"]) {
      resolveTo = [{ address: "93.184.216.34", family: 4 }, { address: inside, family: inside.includes(":") ? 6 : 4 }];
      await expect(guardedFetch("misp.example.com", "/x"), inside).rejects.toThrow(/public internet address/);
    }
    expect(calls).toHaveLength(0);
  });
  it("connects to exactly the address that was checked", async () => {
    let pinned = ""; transport.send = async (_h, addr) => { pinned = addr.address; return { status: 200, body: "{}" }; };
    await guardedFetch("misp.example.com", "/x");
    expect(pinned).toBe("93.184.216.34");
  });
});

describe("what may leave Argust", () => {
  it("private and reserved addresses are never sent; malformed values are refused", () => {
    for (const ip of ["10.0.0.1", "192.168.1.10", "127.0.0.1", "169.254.169.254", "::1", "fe80::1"]) expect(vetIndicator({ type: "ip", value: ip }), ip).toEqual({ skip: "private_address" });
    expect(vetIndicator({ type: "url", value: "http://192.168.0.1/admin" })).toEqual({ skip: "private_address" });
    for (const [type, value] of [["ip", "not-an-ip"], ["hash", "xyz"], ["domain", "a b.com"], ["url", "ftp://x.com"], ["url", "https://u:p@x.com"], ["ip", "8.8.8.8\n1"]] as const) expect(vetIndicator({ type, value }), value).toHaveProperty("skip");
    expect(vetIndicator({ type: "ip", value: IP })).toEqual({ ok: { type: "ip", value: IP } });
  });
  it("with a source connected, a private address still goes nowhere", async () => {
    await create(adminA, { kind: "virustotal", name: "VT", config: {}, secrets: { api_key: VT_KEY } });
    const r = await lookupIndicators(tA, [{ type: "ip", value: "10.0.0.7" }]);
    expect(r.skipped).toEqual([{ value: "10.0.0.7", reason: "private_address" }]);
    expect(calls).toHaveLength(0);
  });
});

describe("answers", () => {
  it("VirusTotal: several vendors → malicious; one → suspicious; many clean → benign; no analysis → no opinion", () => {
    const i = { type: "ip" as const, value: IP };
    expect(answerFromVirusTotal(i, vt(7))).toMatchObject({ verdict: "malicious", indicator: IP });
    expect(answerFromVirusTotal(i, vt(1))).toMatchObject({ verdict: "suspicious" });
    expect(answerFromVirusTotal(i, vt(0))).toMatchObject({ verdict: "benign" });
    expect(answerFromVirusTotal(i, vt(0, 2))).toMatchObject({ verdict: "benign" });
    expect(answerFromVirusTotal(i, { data: { attributes: {} } })).toBeNull();
    expect(answerFromVirusTotal(i, "<html>")).toBeNull();
  });
  it("MISP: exact value only; to_ids → malicious, recorded only → suspicious", () => {
    const i = { type: "ip" as const, value: IP };
    const attr = (value: string, to_ids: boolean) => ({ value, to_ids, timestamp: "1750000000", Event: { info: "Brute force wave" } });
    expect(answerFromMisp(i, { response: { Attribute: [attr(IP, true)] } })).toMatchObject({ verdict: "malicious" });
    expect(answerFromMisp(i, { response: { Attribute: [attr(IP, false)] } })).toMatchObject({ verdict: "suspicious" });
    expect(answerFromMisp(i, { response: { Attribute: [attr("45.155.205.120", true)] } })).toBeNull();
    expect(answerFromMisp(i, { response: { Attribute: [] } })).toBeNull();
    expect(answerFromMisp(i, null)).toBeNull();
  });
  it("OpenCTI: the score decides; being recorded is not being malicious", () => {
    const i = { type: "domain" as const, value: "evil.example.org" };
    const node = (score: number | null) => ({ data: { stixCyberObservables: { edges: [{ node: { observable_value: "evil.example.org", x_opencti_score: score, updated_at: new Date(Date.now() - 86_400_000).toISOString(), objectLabel: [{ value: "phishing" }] } }] } } });
    expect(answerFromOpenCti(i, node(85))).toMatchObject({ verdict: "malicious", confidence: 85 });
    expect(answerFromOpenCti(i, node(50))).toMatchObject({ verdict: "suspicious" });
    expect(answerFromOpenCti(i, node(10))).toMatchObject({ verdict: "unknown" });
    expect(answerFromOpenCti(i, node(null))).toMatchObject({ verdict: "unknown", confidence: null });
    expect(answerFromOpenCti(i, { data: { stixCyberObservables: { edges: [] } } })).toBeNull();
  });
});

describe("looking up", () => {
  it("no connection → not_configured, and nothing is called", async () => {
    expect((await lookupIndicators(tA, [{ type: "ip", value: IP }])).status).toBe("not_configured");
    expect(calls).toHaveLength(0);
  });
  it("asks each source on its own host with its own credential, and remembers the answer", async () => {
    await create(adminA, { kind: "virustotal", name: "VT", config: {}, secrets: { api_key: VT_KEY } });
    await create(adminA, { kind: "misp", name: "Our MISP", config: { host: "misp.example.com" }, secrets: { api_key: "misp-key-1" } });
    await create(adminA, { kind: "opencti", name: "Our CTI", config: { host: "cti.example.com" }, secrets: { api_token: "cti-token-1" } });
    respond = (c) => c.url.includes("virustotal") ? { status: 200, body: vt(9) }
      : c.url.includes("misp") ? { status: 200, body: { response: { Attribute: [{ value: IP, to_ids: true, Event: { info: "Wave" } }] } } }
      : { status: 200, body: { data: { stixCyberObservables: { edges: [] } } } };
    const r = await lookupIndicators(tA, [{ type: "ip", value: IP }]);
    expect(r.status).toBe("ok");
    expect(r.results.map((x) => [x.source, x.verdict]).sort()).toEqual([["MISP", "malicious"], ["VirusTotal", "malicious"]]);
    expect(calls.map((c) => c.url).sort()).toEqual(["https://cti.example.com/graphql", "https://misp.example.com/attributes/restSearch", `https://www.virustotal.com/api/v3/ip_addresses/${IP}`]);
    expect(calls.find((c) => c.url.includes("virustotal"))!.headers["x-apikey"]).toBe(VT_KEY);
    expect(calls.find((c) => c.url.includes("misp"))!.headers.authorization).toBe("misp-key-1");
    expect(calls.find((c) => c.url.includes("cti"))!.headers.authorization).toBe("Bearer cti-token-1");
    // No key crosses to another source.
    for (const c of calls) if (!c.url.includes("virustotal")) expect(JSON.stringify(c)).not.toContain(VT_KEY);
    await lookupIndicators(tA, [{ type: "ip", value: IP }]);
    expect(calls).toHaveLength(3);
  });
  it("another workspace's source is never asked, and its answers are not shared", async () => {
    await create(adminB, { kind: "virustotal", name: "VT-B", config: {}, secrets: { api_key: VT_KEY } });
    respond = () => ({ status: 200, body: vt(9) });
    await lookupIndicators(tB, [{ type: "ip", value: IP }]);
    const before = calls.length;
    expect((await lookupIndicators(tA, [{ type: "ip", value: IP }])).status).toBe("not_configured");
    expect(calls).toHaveLength(before);
  });
  it("a failing source does not fail the others; its key never reaches the stored error", async () => {
    await create(adminA, { kind: "virustotal", name: "VT", config: {}, secrets: { api_key: VT_KEY } });
    await create(adminA, { kind: "misp", name: "M", config: { host: "misp.example.com" }, secrets: { api_key: "misp-SECRET-key" } });
    respond = (c) => c.url.includes("virustotal") ? { status: 200, body: vt(0) } : { status: 500, body: "boom misp-SECRET-key" };
    const r = await lookupIndicators(tA, [{ type: "ip", value: IP }]);
    expect(r.status).toBe("ok");
    expect(r.sources.find((s) => s.kind === "misp")!.ok).toBe(false);
    expect(r.results).toHaveLength(1);
    const row = (await query("SELECT failures, last_error FROM integration_connections WHERE kind = 'misp'")).rows[0];
    expect(row.failures).toBe(1);
    expect(String(row.last_error)).not.toContain("SECRET");
    respond = () => ({ status: 401, body: "{}" }); clearIntelCache();
    expect((await lookupIndicators(tA, [{ type: "ip", value: "8.8.4.4" }])).status).toBe("unavailable");
  });
  it("VirusTotal: at most four lookups per call, a quota answer stops quietly, unknown (404) is no opinion", async () => {
    await create(adminA, { kind: "virustotal", name: "VT", config: {}, secrets: { api_key: VT_KEY } });
    respond = () => ({ status: 200, body: vt(5) });
    await lookupIndicators(tA, Array.from({ length: 9 }, (_, n) => ({ type: "ip" as const, value: `8.8.8.${n + 1}` })));
    expect(calls).toHaveLength(4);
    calls = []; clearIntelCache();
    let n = 0; respond = () => (++n === 1 ? { status: 404 } : n === 2 ? { status: 429 } : { status: 200, body: vt(5) });
    const r = await lookupIndicators(tA, [{ type: "ip", value: "1.1.1.1" }, { type: "ip", value: "1.0.0.1" }, { type: "ip", value: "9.9.9.9" }]);
    expect(calls).toHaveLength(2);
    expect(r.results).toHaveLength(0);
    expect(r.status).toBe("ok");
  });
  it("a type no connected source supports is reported, not sent", async () => {
    await create(adminA, { kind: "virustotal", name: "VT", config: {}, secrets: { api_key: VT_KEY } });
    const r = await lookupIndicators(tA, [{ type: "email", value: "a@example.com" }, { type: "cve", value: "CVE-2021-44228" }]);
    expect(r.skipped.map((s) => s.reason)).toEqual(["unsupported", "unsupported"]);
    expect(calls).toHaveLength(0);
  });
});

describe("POST /alerts/:id/intel", () => {
  it("an analyst asks about the alert's source address; a viewer cannot; another workspace sees nothing; it is audited", async () => {
    await create(adminA, { kind: "virustotal", name: "VT", config: {}, secrets: { api_key: VT_KEY } });
    await ingestFindings(tA, "wazuh", [{ externalId: "e1", title: "Brute force", severity: "high", summary: "s", occurredAt: null, sourceIp: IP, target: "web-1", mitre: [], confidence: 70, asset: null }]);
    const id = findingAlertId(tA, "wazuh", "e1");
    respond = () => ({ status: 200, body: vt(8) });
    expect((await request(app).post(`/alerts/${id}/intel`).set(...bearer(viewerA))).status).toBe(403);
    expect((await request(app).post(`/alerts/${id}/intel`).set(...bearer(adminB))).status).toBe(404);
    const r = await request(app).post(`/alerts/${id}/intel`).set(...bearer(adminA));
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ status: "ok", results: [{ source: "VirusTotal", verdict: "malicious", indicator: IP }] });
    expect(JSON.stringify(r.body)).not.toContain(VT_KEY);
    expect((await query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1 AND action = 'intel.lookup'", [tA])).rows[0].n).toBe(1);
  });
});
