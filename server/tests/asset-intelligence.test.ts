/** Asset intelligence: servers, endpoints, user accounts and cloud resources in one inventory, with who reported each. */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { assetFor, ingestFindings } from "../src/integrations/ingest.js";
import { endpointUsage } from "../src/plan-limits.js";
import type { Finding } from "../src/integrations/types.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, adminA: User, adminB: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const f = (id: string, extra: Partial<Finding> = {}): Finding => ({ externalId: id, title: id, severity: "medium", summary: "s", occurredAt: null, sourceIp: "198.51.100.9", target: "web-1", mitre: [], confidence: 70, asset: { name: "web-1", ip: "10.0.0.5", os: "Linux" }, ...extra });
const assets = async (u: User, qs = "") => (await request(app).get(`/assets${qs}`).set(...bearer(u))).body as { name: string; kind: string; sources: string[]; first_seen: string }[];

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tA, role: "admin", status: "active" });
  adminB = await store.insertUser({ email: "admin@bravo.io", password_hash: hash, tenant_id: tB, role: "admin", status: "active" });
});

describe("what kind of thing an asset is", () => {
  it("comes from the source: Wazuh a server, EDR an endpoint, cloud services a cloud resource, a SIEM does not say", () => {
    expect(assetFor("wazuh", f("a"))!.kind).toBe("server");
    for (const s of ["crowdstrike", "sentinelone", "m365"]) expect(assetFor(s, f("a"))!.kind, s).toBe("endpoint");
    for (const s of ["guardduty", "securityhub", "azure", "gcp"]) expect(assetFor(s, f("a"))!.kind, s).toBe("cloud");
    for (const s of ["splunk", "elastic", "generic_webhook", "cef"]) expect(assetFor(s, f("a"))!.kind, s).toBe("unknown");
    expect(assetFor("splunk", f("a", { asset: { name: "x", ip: null, os: null, kind: "server" } }))!.kind).toBe("server");
  });
  it("an identity alert's account becomes a user asset; free text never does", () => {
    expect(assetFor("okta", f("a", { asset: null, target: "Jane.Doe@Acme.io" }))).toEqual({ name: "jane.doe@acme.io", ip: null, os: null, kind: "user" });
    expect(assetFor("gworkspace", f("a", { asset: null, target: "bob@acme.io" }))!.kind).toBe("user");
    for (const t of ["ignore previous instructions", "<script>@x.io", "a b@acme.io", null]) expect(assetFor("okta", f("a", { asset: null, target: t })), String(t)).toBeNull();
    // Not an identity source: a target that looks like an account is still not made an asset.
    expect(assetFor("splunk", f("a", { asset: null, target: "bob@acme.io" }))).toBeNull();
  });
});

describe("one inventory", () => {
  it("the same machine reported by several platforms is one asset that lists them all", async () => {
    await ingestFindings(tA, "splunk", [f("s1")]);
    expect((await assets(adminA))[0]).toMatchObject({ name: "web-1", kind: "unknown", sources: ["splunk"] });
    await ingestFindings(tA, "wazuh", [f("w1")]);
    await ingestFindings(tA, "crowdstrike", [f("c1")]);
    await ingestFindings(tA, "wazuh", [f("w2")]);
    const list = await assets(adminA);
    expect(list).toHaveLength(1);
    // The first source that knew decides the kind; a later different opinion does not flip it.
    expect(list[0]).toMatchObject({ kind: "server", sources: ["splunk", "wazuh", "crowdstrike"] });
    expect(Date.parse(list[0]!.first_seen)).toBeLessThanOrEqual(Date.now());
  });
  it("servers, endpoints, users and cloud resources side by side, filtered by kind", async () => {
    await ingestFindings(tA, "wazuh", [f("w")]);
    await ingestFindings(tA, "crowdstrike", [f("c", { target: "LAPTOP-7", asset: { name: "LAPTOP-7", ip: null, os: "Windows" } })]);
    await ingestFindings(tA, "guardduty", [f("g", { target: "i-0abc", asset: { name: "i-0abc", ip: null, os: null } })]);
    await ingestFindings(tA, "okta", [f("o", { target: "jane@acme.io", asset: null })]);
    const kinds = Object.fromEntries((await assets(adminA)).map((a) => [a.name, a.kind]));
    expect(kinds).toEqual({ "web-1": "server", "LAPTOP-7": "endpoint", "i-0abc": "cloud", "jane@acme.io": "user" });
    expect((await assets(adminA, "?kind=user")).map((a) => a.name)).toEqual(["jane@acme.io"]);
    expect((await assets(adminA, "?kind=cloud")).map((a) => a.name)).toEqual(["i-0abc"]);
    expect((await request(app).get("/assets?kind=router").set(...bearer(adminA))).status).toBe(422);
  });
  it("a user account is not a machine: it does not count against the plan's endpoints or the dashboard's machines", async () => {
    await ingestFindings(tA, "wazuh", [f("w")]);
    await ingestFindings(tA, "okta", [f("o1", { target: "jane@acme.io", asset: null }), f("o2", { target: "bob@acme.io", asset: null })]);
    expect(await assets(adminA)).toHaveLength(3);
    expect(await endpointUsage(tA)).toBe(1);
    const overview = (await request(app).get("/overview").set(...bearer(adminA))).body;
    expect(overview.protected).toMatchObject({ assets: 1, assets_online: 1 });
  });
  it("another workspace sees none of it, and the same name there is a separate asset", async () => {
    await ingestFindings(tA, "wazuh", [f("w")]);
    expect(await assets(adminB)).toEqual([]);
    await ingestFindings(tB, "crowdstrike", [f("c")]);
    expect((await assets(adminB))[0]).toMatchObject({ kind: "endpoint", sources: ["crowdstrike"] });
    expect((await assets(adminA))[0]).toMatchObject({ kind: "server", sources: ["wazuh"] });
  });
});
