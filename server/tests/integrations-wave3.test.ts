/**
 * Third wave: AbuseIPDB (reputation), Microsoft Entra ID (identity risk, and approved sign-in block), Palo Alto
 * Cortex XDR (incidents), Tenable and Qualys (vulnerabilities), Fortinet FortiGate (through CEF).
 * Every vendor is simulated from its documented API shape; none of this has met a real account.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { createHash, randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { ingestFindings } from "../src/integrations/ingest.js";
import * as registry from "../src/integrations/registry.js";
import { answerFromAbuseIpdb } from "../src/integrations/abuseipdb.js";
import { entraAdapter, findingFromRiskDetection } from "../src/integrations/entra.js";
import { cortexAdapter, cortexHeaders, findingFromCortexIncident } from "../src/integrations/cortex.js";
import { findingFromTenable, tenableAdapter } from "../src/integrations/tenable.js";
import { detectionsFromXml, knowledgeFromXml, qualysAdapter, xmlText } from "../src/integrations/qualys.js";
import { componentOf, findingFromScannerVuln } from "../src/integrations/vuln-shared.js";
import { cefAdapter } from "../src/integrations/cef.js";
import { clearIntelCache, lookupIndicators } from "../src/threat-intel.js";
import { listCampaigns } from "../src/campaigns.js";
import { proposeAction, runQueued, syncWithApproval } from "../src/actions/engine.js";
import { decide } from "../src/approvals/engine.js";
import type { User } from "../src/types.js";

let tA: string, admin: User, admin2: User, admin3: User;
const now = () => Math.floor(Date.now() / 1000);
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version, auth_time: now() }, { expiresIn: "1h" })}`] as const;
const create = (body: Record<string, unknown>) => request(app).post("/integrations").set(...as(admin)).send(body);
const sig = new AbortController().signal;
const GUID = "11111111-1111-4111-8111-111111111111";
const HEX64 = "ab".repeat(32);
const ctx = (config: Record<string, unknown>, secrets: Record<string, string>) => ({ id: randomUUID(), tenantId: tA, config, secrets });

type Call = { url: string; method: string; headers: Record<string, string>; body: string };
let calls: Call[]; let respond: (c: Call) => { status: number; body?: unknown };
const realFetch = globalThis.fetch;
const hosts = () => [...new Set(calls.map((c) => new URL(c.url).host))].sort();

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
afterEach(() => { globalThis.fetch = realFetch; });
beforeEach(async () => {
  await truncateAll(); clearIntelCache();
  tA = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business')", [tA]);
  const h = await bcrypt.hash("password123", 4);
  const mk = (email: string) => store.insertUser({ email, password_hash: h, tenant_id: tA, role: "admin", status: "active" });
  admin = await mk("a1@a.io"); admin2 = await mk("a2@a.io"); admin3 = await mk("a3@a.io");
  await query("UPDATE users SET email_verified_at = now()");
  calls = []; respond = () => ({ status: 404 });
  globalThis.fetch = (async (input: URL | string, init: RequestInit = {}) => {
    const c: Call = { url: String(input), method: String(init.method ?? "GET"), headers: Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>)), body: String(init.body ?? "") };
    calls.push(c);
    const r = respond(c);
    return new Response(r.status === 204 ? null : typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {}), { status: r.status });
  }) as typeof fetch;
});

describe("catalogue", () => {
  it("the new connections are available with the right plane and direction", async () => {
    const cat = (await request(app).get("/integrations/catalogue").set(...as(admin))).body.integrations as { kind: string }[];
    const by = Object.fromEntries(cat.map((c) => [c.kind, c]));
    for (const k of ["entra_id", "cortex_xdr", "tenable", "qualys"]) expect(by[k], k).toMatchObject({ status: "available", plane: "data", inbound: "pull", outbound: [] });
    expect(by.abuseipdb).toMatchObject({ plane: "data", inbound: null, intel: true });
    expect(by.entra_response).toMatchObject({ plane: "tool", inbound: null, outbound: ["respond"] });
    // Reading identity risk can never change an account: a different connection, credential and code path do that.
    expect(registry.responseAdapter("entra_id")).toBeNull();
    expect(registry.pullKinds()).not.toContain("entra_response");
  });
});

describe("AbuseIPDB", () => {
  const i = { type: "ip" as const, value: "45.155.205.12" };
  const data = (score: number, reports: number) => ({ data: { abuseConfidenceScore: score, totalReports: reports, lastReportedAt: new Date(Date.now() - 3600_000).toISOString(), isp: "Bad Hosting", countryCode: "NL", usageType: "Data Center" } });
  it("the score decides; an address nobody reported is nothing known, not safe", () => {
    expect(answerFromAbuseIpdb(i, data(100, 420))).toMatchObject({ verdict: "malicious", confidence: 100 });
    expect(answerFromAbuseIpdb(i, data(40, 6))).toMatchObject({ verdict: "suspicious" });
    expect(answerFromAbuseIpdb(i, data(5, 1))).toMatchObject({ verdict: "unknown" });
    expect(answerFromAbuseIpdb(i, data(0, 0))).toBeNull();
    expect(answerFromAbuseIpdb(i, "<html>")).toBeNull();
  });
  it("is asked for addresses only, with the key in the Key header, on its own host", async () => {
    const KEY = "c".repeat(80);
    expect((await create({ kind: "abuseipdb", name: "AbuseIPDB", config: {}, secrets: { api_key: KEY } })).status).toBe(201);
    respond = () => ({ status: 200, body: data(90, 50) });
    const r = await lookupIndicators(tA, [i, { type: "domain", value: "evil.example.org" }, { type: "ip", value: "10.0.0.1" }]);
    expect(r.results).toMatchObject([{ source: "AbuseIPDB", verdict: "malicious", indicator: i.value }]);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://api.abuseipdb.com/api/v2/check?ipAddress=45.155.205.12&maxAgeInDays=90");
    expect(calls[0]!.headers.Key).toBe(KEY);
    expect(r.skipped.map((s) => s.reason).sort()).toEqual(["private_address", "unsupported"]);
  });
});

describe("Microsoft Entra ID (identity risk)", () => {
  const det = (extra: Record<string, unknown> = {}) => ({ id: "rd-1", riskEventType: "leakedCredentials", riskLevel: "high", riskState: "atRisk", riskDetail: "none", detectedDateTime: new Date(Date.now() - 600_000).toISOString(), activityDateTime: new Date(Date.now() - 900_000).toISOString(), ipAddress: "45.155.205.12", userPrincipalName: "Jane@Acme.io", location: { city: "Amsterdam", countryOrRegion: "NL" }, ...extra });
  it("a risk detection becomes an alert about the account, in plain words; dismissed and hidden ones do not", () => {
    expect(findingFromRiskDetection(det())).toMatchObject({ externalId: "rd-1", severity: "high", target: "jane@acme.io", sourceIp: "45.155.205.12", mitre: ["T1078"], asset: { name: "jane@acme.io", kind: "user" } });
    expect(findingFromRiskDetection(det())!.title).toBe("Entra ID: The account's password was found in a leak — jane@acme.io");
    expect(findingFromRiskDetection(det({ riskEventType: "somethingNew", riskLevel: "medium" }))).toMatchObject({ severity: "medium", title: "Entra ID: Identity risk detected (somethingNew) — jane@acme.io" });
    for (const skip of [{ riskLevel: "hidden" }, { riskLevel: "none" }, { riskState: "dismissed" }, { riskState: "remediated" }, { id: "" }]) expect(findingFromRiskDetection(det(skip)), JSON.stringify(skip)).toBeNull();
  });
  it("polls Graph with a client-credentials token, only on Microsoft's two hosts, and moves the cursor", async () => {
    respond = (c) => c.url.includes("login.microsoftonline.com") ? { status: 200, body: { access_token: "tok" } } : { status: 200, body: { value: [det(), det({ id: "rd-2", riskLevel: "hidden" })] } };
    const out = await entraAdapter.poll(ctx({ directory_id: GUID, client_id: GUID }, { client_secret: "s3cret" }), null, sig);
    expect(out.findings).toHaveLength(1);
    expect(hosts()).toEqual(["graph.microsoft.com", "login.microsoftonline.com"]);
    expect(new URL(calls[1]!.url).pathname).toBe("/v1.0/identityProtection/riskDetections");
    expect(calls[1]!.headers.authorization).toBe("Bearer tok");
    expect(Date.parse((out.cursor as { since: string }).since)).toBeGreaterThan(Date.now() - 3600_000);
    await ingestFindings(tA, "entra_id", out.findings);
    expect((await query("SELECT kind, sources FROM assets WHERE tenant_id = $1 AND name = 'jane@acme.io'", [tA])).rows[0]).toMatchObject({ kind: "user", sources: ["entra_id"] });
  });
  it("a refusal says which permission and licence are needed", async () => {
    respond = (c) => c.url.includes("login.microsoftonline.com") ? { status: 200, body: { access_token: "tok" } } : { status: 403, body: {} };
    await expect(entraAdapter.poll(ctx({ directory_id: GUID, client_id: GUID }, { client_secret: "s" }), null, sig)).rejects.toThrow(/IdentityRiskEvent\.Read\.All/);
  });
});

describe("Microsoft Entra ID (response): blocking sign-in, after two people approve", () => {
  it("PATCHes accountEnabled=false for exactly that account; never before approval", async () => {
    await request(app).put("/soc/protection").set(...as(admin)).send({ mode: "hybrid", auto_actions: [], acknowledge: true }).expect(200);
    expect((await create({ kind: "entra_response", name: "Entra response", config: { directory_id: GUID, client_id: GUID, never: ["breakglass@acme.io"] }, secrets: { client_secret: "entra-SECRET" } })).status).toBe(201);
    respond = (c) => c.url.includes("login.microsoftonline.com") ? { status: 200, body: { access_token: "tok" } } : { status: 204 };
    const run = async (account: string, action = "account.disable") => {
      const { action: a } = await proposeAction(tA, { action_id: action, input: { account, system: "entra" }, actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "live", idempotency_key: `k-${randomUUID()}` });
      expect(a.status).toBe("awaiting_approval");
      expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(patches);
      const row = (await query("SELECT approval_id, action_digest, risk_class FROM action_requests WHERE id = $1", [a.id])).rows[0];
      for (const u of row.risk_class === "R4" ? [admin2, admin3] : [admin2]) await decide(tA, row.approval_id, { userId: u.id, decision: "approve", actionDigest: row.action_digest, mfaVerified: true });
      await syncWithApproval(tA, a.id, { kind: "system", component: "test" });
      return runQueued(tA, a.id);
    };
    let patches = 0;
    expect(await run("jane@acme.io")).toMatchObject({ status: "executed", result: { did: "block_sign_in", target: "jane@acme.io" } });
    patches = 1;
    const patch = calls.find((c) => c.method === "PATCH")!;
    expect(patch.url).toBe("https://graph.microsoft.com/v1.0/users/jane%40acme.io");
    expect(JSON.parse(patch.body)).toEqual({ accountEnabled: false });
    expect(await run("breakglass@acme.io")).toMatchObject({ status: "failed", error: expect.stringMatching(/never-touch/) });
    expect(await run("jane@acme.io", "account.enable")).toMatchObject({ status: "executed", result: { did: "allow_sign_in" } });
    expect(JSON.parse(calls.filter((c) => c.method === "PATCH")[1]!.body)).toEqual({ accountEnabled: true });
    expect(JSON.stringify((await query("SELECT result, error FROM action_requests WHERE tenant_id = $1", [tA])).rows)).not.toContain("SECRET");
  });
});

describe("Palo Alto Cortex XDR", () => {
  const inc = (extra: Record<string, unknown> = {}) => ({ incident_id: "412", incident_name: "", description: "'Ransomware activity' along with 4 other alerts", severity: "high", status: "new", alert_count: 5, hosts: ["LAPTOP-7:abc123"], users: ["acme\\\\jane"], creation_time: Date.now() - 900_000, modification_time: Date.now() - 600_000, mitre_techniques_ids_and_names: ["T1486 - Data Encrypted for Impact"], ...extra });
  it("an advanced key never travels: the header is SHA-256(key + nonce + timestamp); a standard key is sent as it is", () => {
    const h = cortexHeaders("7", "KEY", "advanced", 1_700_000_000_000, "n".repeat(64));
    expect(h).toMatchObject({ "x-xdr-auth-id": "7", "x-xdr-timestamp": "1700000000000", "x-xdr-nonce": "n".repeat(64) });
    expect(h.authorization).toBe(createHash("sha256").update(`KEY${"n".repeat(64)}1700000000000`).digest("hex"));
    expect(JSON.stringify(h)).not.toContain("KEY");
    expect(cortexHeaders("7", "KEY", "standard").authorization).toBe("KEY");
  });
  it("an incident becomes one alert about its first host; resolved ones are skipped", () => {
    expect(findingFromCortexIncident(inc())).toMatchObject({ externalId: "412", severity: "high", target: "LAPTOP-7", mitre: ["T1486"], asset: { name: "LAPTOP-7", kind: "endpoint" } });
    expect(findingFromCortexIncident(inc({ status: "resolved_true_positive" }))).toBeNull();
    expect(findingFromCortexIncident(inc({ incident_id: "" }))).toBeNull();
  });
  it("polls the tenant's own API host by modification time; any other host is refused when saving", async () => {
    respond = () => ({ status: 200, body: { reply: { total_count: 1, incidents: [inc()] } } });
    const out = await cortexAdapter.poll(ctx({ api_host: "api-acme.xdr.eu.paloaltonetworks.com", api_key_id: "7", key_type: "advanced" }, { api_key: "KEY" }), null, sig);
    expect(out.findings).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://api-acme.xdr.eu.paloaltonetworks.com/public_api/v1/incidents/get_incidents/");
    expect(JSON.parse(calls[0]!.body).request_data.filters[0]).toMatchObject({ field: "modification_time", operator: "gte" });
    for (const bad of ["evil.com", "api-acme.xdr.eu.paloaltonetworks.com.evil.com", "10.0.0.1", "https://api-acme.xdr.eu.paloaltonetworks.com"]) {
      expect((await create({ kind: "cortex_xdr", name: "XDR", config: { api_host: bad, api_key_id: "7" }, secrets: { api_key: "K" } })).status, bad).toBe(400);
    }
  });
});

describe("vulnerability findings from scanners", () => {
  it("are written the way Legion's vulnerability skills read them (CVE-… affects <component>)", async () => {
    expect(componentOf("Apache Log4j < 2.15.0 RCE (Log4Shell)")).toBe("Apache-Log4j-2.15.0-RCE-Log4Shell");
    const f = findingFromScannerVuln({ scanner: "Tenable", id: "a:1", name: "Apache Log4j < 2.15.0 RCE", cves: ["cve-2021-44228", "not-a-cve", "CVE-2021-45046"], severity: "critical", host: "web-1", ip: "10.0.0.5", os: "Linux", firstFound: null, solution: "Upgrade to 2.17.1", detail: null, hasFix: true })!;
    expect(f.title).toBe("CVE-2021-44228 affects Apache-Log4j-2.15.0-RCE on web-1");
    expect(f.summary).toContain("CVEs: CVE-2021-44228, CVE-2021-45046");
    expect(f.summary).toContain("A fix is available.");
    await ingestFindings(tA, "tenable", [f]);
    expect((await store.listVulnerabilityAlerts(tA, 10)).map((a) => a.title)).toEqual([f.title]);
    // No CVE: still an alert, named by the scanner, but not a "vulnerability finding" for the skills.
    expect(findingFromScannerVuln({ scanner: "Qualys", id: "h:9", name: "SSL certificate expired", cves: [], severity: "high", host: null, ip: "10.0.0.9", os: null, firstFound: null, solution: null, detail: null, hasFix: null })!.title).toBe("Qualys: SSL certificate expired on 10.0.0.9");
  });
  it("a weakness is not an attack: a scanner finding and an alert on the same host are not joined into a campaign", async () => {
    const f = (source: string, title: string) => ingestFindings(tA, source, [{ externalId: randomUUID(), title, severity: "critical", summary: "s", occurredAt: null, sourceIp: null, target: "web-1", mitre: [], confidence: 80, asset: null }]);
    await f("tenable", "CVE-2021-44228 affects log4j on web-1");
    await f("qualys", "CVE-2021-44228 affects log4j on web-1");
    await f("wazuh", "CVE-2021-44228 affects log4j-core");
    await f("crowdstrike", "Malware blocked");
    expect((await listCampaigns(tA)).filter((c) => c.rule === "multi_platform")).toHaveLength(0);
  });
});

describe("Tenable", () => {
  const vuln = (extra: Record<string, unknown> = {}) => ({ asset: { uuid: "0d2f6a8e-1111-4222-8333-444455556666", hostname: "web-1", ipv4: "10.0.0.5", operating_system: ["Ubuntu 22.04"] }, plugin: { id: 156860, name: "Apache Log4j < 2.15.0 RCE", cve: ["CVE-2021-44228"], cvss3_base_score: 10, has_patch: true, solution: "Upgrade.", exploit_available: true }, severity: "critical", state: "open", first_found: new Date(Date.now() - 86_400_000).toISOString(), ...extra });
  const keys = { access_key: HEX64, secret_key: HEX64 };
  const UUIDX = "22222222-2222-4222-8222-222222222222";
  it("maps a vulnerability to one alert per asset and plugin; fixed ones and unknown severities are skipped", () => {
    expect(findingFromTenable(vuln())).toMatchObject({ externalId: "0d2f6a8e-1111-4222-8333-444455556666:156860", severity: "critical", target: "web-1", asset: { name: "web-1", ip: "10.0.0.5", os: "Ubuntu 22.04" } });
    expect(findingFromTenable(vuln())!.title).toBe("CVE-2021-44228 affects Apache-Log4j-2.15.0-RCE on web-1");
    expect(findingFromTenable(vuln({ state: "fixed" }))).toBeNull();
    expect(findingFromTenable(vuln({ severity: "info" }))).toBeNull();
  });
  it("never waits for the export: one poll asks for it, a later one reads it; then the cursor moves forward", async () => {
    respond = (c) => c.method === "POST" ? { status: 200, body: { export_uuid: UUIDX } } : { status: 404 };
    const first = await tenableAdapter.poll(ctx({ min_severity: "high" }, keys), null, sig);
    expect(first.findings).toEqual([]);
    expect(first.cursor).toMatchObject({ export: { uuid: UUIDX } });
    expect(JSON.parse(calls[0]!.body).filters).toMatchObject({ severity: ["high", "critical"], state: ["open", "reopened"] });
    expect(calls[0]!.headers["x-apikeys"]).toBe(`accessKey=${HEX64};secretKey=${HEX64}`);
    respond = () => ({ status: 200, body: { status: "PROCESSING", chunks_available: [] } });
    const waiting = await tenableAdapter.poll(ctx({}, keys), first.cursor, sig);
    expect(waiting).toEqual({ findings: [], cursor: first.cursor });
    respond = (c) => c.url.endsWith("/status") ? { status: 200, body: { status: "FINISHED", chunks_available: [1, 2] } } : { status: 200, body: [vuln(), vuln({ state: "fixed" })] };
    const done = await tenableAdapter.poll(ctx({}, keys), first.cursor, sig);
    expect(done.findings).toHaveLength(2);
    expect(done.cursor).toEqual({ since: (first.cursor as { export: { at: number } }).export.at });
    expect(hosts()).toEqual(["cloud.tenable.com"]);
  });
  it("a failed, expired or vanished export is asked for again from the same point", async () => {
    const stuck = { since: 1_700_000_000, export: { uuid: UUIDX, at: now() - 3 * 3600 } };
    respond = () => ({ status: 200, body: { status: "PROCESSING" } });
    expect((await tenableAdapter.poll(ctx({}, keys), stuck, sig)).cursor).toEqual({ since: 1_700_000_000 });
    respond = () => ({ status: 200, body: { status: "ERROR" } });
    expect((await tenableAdapter.poll(ctx({}, keys), { ...stuck, export: { uuid: UUIDX, at: now() } }, sig)).cursor).toEqual({ since: 1_700_000_000 });
    respond = () => ({ status: 404 });
    expect((await tenableAdapter.poll(ctx({}, keys), { ...stuck, export: { uuid: UUIDX, at: now() } }, sig)).cursor).toEqual({ since: 1_700_000_000 });
    // A cursor that names something that is not an export id is ignored, never put into a URL.
    respond = () => ({ status: 200, body: { export_uuid: UUIDX } });
    await tenableAdapter.poll(ctx({}, keys), { since: 1_700_000_000, export: { uuid: "../../admin", at: now() } }, sig);
    expect(calls.at(-1)!.url).toBe("https://cloud.tenable.com/vulns/export");
  });
});

describe("Qualys", () => {
  const detections = (warning = "") => `<?xml version="1.0"?><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>
    <HOST><ID>4411</ID><IP>10.0.0.5</IP><DNS><![CDATA[web-1.acme.io]]></DNS><OS><![CDATA[Ubuntu Linux 22.04]]></OS>
      <DETECTION_LIST>
        <DETECTION><QID>376157</QID><TYPE>Confirmed</TYPE><SEVERITY>5</SEVERITY><STATUS>Active</STATUS><FIRST_FOUND_DATETIME>2026-11-01T10:00:00Z</FIRST_FOUND_DATETIME></DETECTION>
        <DETECTION><QID>38170</QID><TYPE>Potential</TYPE><SEVERITY>4</SEVERITY><STATUS>Active</STATUS></DETECTION>
        <DETECTION><QID>90001</QID><TYPE>Confirmed</TYPE><SEVERITY>4</SEVERITY><STATUS>Fixed</STATUS></DETECTION>
      </DETECTION_LIST></HOST>
    <HOST><ID>not-a-number</ID><IP>10.0.0.6</IP><DETECTION_LIST><DETECTION><QID>1</QID><TYPE>Confirmed</TYPE><SEVERITY>5</SEVERITY><STATUS>New</STATUS></DETECTION></DETECTION_LIST></HOST>
  </HOST_LIST>${warning}</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>`;
  const kb = `<KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><VULN_LIST><VULN><QID>376157</QID><TITLE><![CDATA[Apache Log4j Remote Code Execution (Log4Shell)]]></TITLE><PATCHABLE>1</PATCHABLE>
    <CVE_LIST><CVE><ID><![CDATA[CVE-2021-44228]]></ID><URL>x</URL></CVE></CVE_LIST><SOLUTION><![CDATA[Upgrade to <b>2.17.1</b>.]]></SOLUTION></VULN></VULN_LIST></RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>`;
  it("reads only the documented tags: confirmed, open detections; nothing is expanded or followed", () => {
    expect(detectionsFromXml(detections())).toEqual([{ hostId: "4411", host: "web-1.acme.io", ip: "10.0.0.5", os: "Ubuntu Linux 22.04", qid: "376157", severity: 5, firstFound: "2026-11-01T10:00:00.000Z" }]);
    expect(knowledgeFromXml(kb).get("376157")).toMatchObject({ title: "Apache Log4j Remote Code Execution (Log4Shell)", cves: ["CVE-2021-44228"], patchable: true });
    // An entity declaration is text to this reader, never something to resolve.
    const hostile = `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><A><ID>&xxe;</ID><T>a &amp; b &lt;c&gt;</T></A>`;
    expect(xmlText(hostile, "ID")).toBe("&xxe;");
    expect(xmlText(hostile, "T")).toBe("a & b <c>");
    expect(detectionsFromXml("not xml at all")).toEqual([]);
    expect(detectionsFromXml("<HOST>".repeat(5000))).toEqual([]);
  });
  it("polls the chosen platform with Basic auth and joins detections with the knowledge base", async () => {
    respond = (c) => c.url.includes("/detection/") ? { status: 200, body: detections() } : { status: 200, body: kb };
    const out = await qualysAdapter.poll(ctx({ platform: "eu1" }, { username: "reader", password: "pw-SECRET" }), null, sig);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({ externalId: "4411:376157", severity: "critical", target: "web-1.acme.io" });
    expect(out.findings[0]!.title).toBe("CVE-2021-44228 affects Apache-Log4j-Remote-Code-Execution-Log4Shell on web-1.acme.io");
    expect(hosts()).toEqual(["qualysapi.qualys.eu"]);
    expect(calls[0]!.headers.authorization).toBe(`Basic ${Buffer.from("reader:pw-SECRET").toString("base64")}`);
    expect(calls[0]!.headers["x-requested-with"]).toBe("Legion");
    expect(new URLSearchParams(calls[0]!.body).get("severities")).toBe("4-5");
    expect(new URLSearchParams(calls[1]!.body).get("ids")).toBe("376157");
    expect(Date.parse((out.cursor as { since: string }).since)).toBeGreaterThan(Date.now() - 60_000);
    expect((await create({ kind: "qualys", name: "Q", config: { platform: "evil.com" }, secrets: { username: "u", password: "p" } })).status).toBe(400);
  });
  it("a long list is read in parts: the cursor keeps Qualys's next host id and the same start time", async () => {
    const warn = `<WARNING><CODE>1980</CODE><TEXT>500 record limit exceeded.</TEXT><URL><![CDATA[https://qualysapi.qualys.eu/api/2.0/fo/asset/host/vm/detection/?action=list&id_min=4412]]></URL></WARNING>`;
    respond = (c) => c.url.includes("/detection/") ? { status: 200, body: detections(warn) } : { status: 200, body: kb };
    const first = await qualysAdapter.poll(ctx({ platform: "eu1" }, { username: "u", password: "p" }), { since: "2026-11-01T00:00:00.000Z" }, sig);
    expect(first.cursor).toMatchObject({ since: "2026-11-01T00:00:00.000Z", id_min: "4412" });
    respond = (c) => c.url.includes("/detection/") ? { status: 200, body: detections() } : { status: 200, body: kb };
    const second = await qualysAdapter.poll(ctx({ platform: "eu1" }, { username: "u", password: "p" }), first.cursor, sig);
    expect(new URLSearchParams(calls.filter((c) => c.url.includes("/detection/")).at(-1)!.body).get("id_min")).toBe("4412");
    expect(second.cursor).toEqual({ since: (first.cursor as { started: string }).started });
  });
});

describe("Fortinet FortiGate (through a CEF collector)", () => {
  it("what the firewall found is in the title; the source address and the device are kept", () => {
    const line = `<189>Nov 14 10:00:00 fw-01 CEF:0|Fortinet|Fortigate|v7.4.3|16384|utm:ips signature|8|deviceExternalId=FGT60F0000000001 FTNTFGTattack=Apache.Log4j.Error.Log.Remote.Code.Execution src=45.155.205.12 dst=10.0.0.5 dhost=web-1 act=dropped FTNTFGTseverity=critical msg=IPS signature matched`;
    const r = cefAdapter.normalize(line);
    expect(r.skipped).toBe(false);
    if (r.skipped) return;
    expect(r.findings[0]).toMatchObject({ title: "FortiGate utm:ips signature: Apache.Log4j.Error.Log.Remote.Code.Execution", severity: "high", sourceIp: "45.155.205.12", target: "web-1" });
    expect(r.findings[0]!.summary).toContain("action=dropped");
    // Another vendor's CEF line is unchanged.
    const other = cefAdapter.normalize(`CEF:0|Acme|Thing|1|100|Port scan|5|src=45.155.205.12 FTNTFGTattack=ignored`);
    if (!other.skipped) expect(other.findings[0]!.title).toBe("Port scan");
  });
});
