/**
 * Tenable Vulnerability Management (Tenable.io) — open high and critical vulnerabilities, per asset (pull, read only).
 *
 * Tenable gives bulk data through an export that takes minutes to prepare, so one poll never waits for it:
 *   poll 1  asks for an export of what changed since the cursor            → remembers its id in the cursor
 *   poll 2+ asks whether it is ready; when it is, reads its chunks         → findings, cursor moves forward
 * An export that fails, or is not ready after two hours, is dropped and asked for again.
 * API keys of a user with the Basic role and "Can View" on the assets (X-ApiKeys header), sealed per connection;
 * cloud.tenable.com only. One Legion alert per (asset, plugin): re-scans do not repeat it.
 * Legion never starts a scan and never changes anything in Tenable.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, parseTime, pickIp } from "./shared.js";
import { findingFromScannerVuln } from "./vuln-shared.js";
import type { Severity } from "../types.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const HOST = "https://cloud.tenable.com";
const KEY = /^[a-f0-9]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_CHUNKS = 10;
const MAX_FINDINGS = 2000;
const GIVE_UP_MS = 2 * 3600_000;
const SEVERITIES: Record<string, Severity> = { critical: "critical", high: "high", medium: "medium", low: "low" };

export function findingFromTenable(v: Obj): Finding | null {
  const asset = isObj(v.asset) ? v.asset : {};
  const plugin = isObj(v.plugin) ? v.plugin : {};
  const severity = SEVERITIES[String(v.severity ?? "").toLowerCase()];
  const assetId = cleanText(asset.uuid, 80), pluginId = cleanText(plugin.id, 20);
  if (!severity || !assetId || !pluginId) return null;
  const state = String(v.state ?? "").toLowerCase();
  if (state === "fixed") return null;
  const os = Array.isArray(asset.operating_system) ? cleanText(asset.operating_system[0], 80) : cleanText(asset.operating_system, 80);
  return findingFromScannerVuln({
    scanner: "Tenable", id: `${assetId}:${pluginId}`, name: cleanText(plugin.name, 200), cves: Array.isArray(plugin.cve) ? plugin.cve.map(String) : [], severity,
    host: cleanText(asset.hostname ?? asset.fqdn ?? asset.netbios_name, 255) || null, ip: pickIp(asset.ipv4, asset.ipv6), os: os || null,
    firstFound: parseTime(v.first_found), solution: cleanText(plugin.solution, 600) || null,
    detail: [typeof plugin.cvss3_base_score === "number" ? `CVSS v3 ${plugin.cvss3_base_score}` : "", typeof plugin.vpr === "object" && isObj(plugin.vpr) && typeof plugin.vpr.score === "number" ? `Tenable VPR ${plugin.vpr.score}` : "", plugin.exploit_available === true ? "An exploit exists." : ""].filter(Boolean).join(". ") || null,
    hasFix: typeof plugin.has_patch === "boolean" ? plugin.has_patch : null,
  });
}

interface Cursor { since: number; export?: { uuid: string; at: number } }
function readCursor(c: unknown): Cursor {
  const o = isObj(c) ? c : {};
  const now = Math.floor(Date.now() / 1000);
  const since = typeof o.since === "number" && Number.isInteger(o.since) && o.since > 0 && o.since <= now + 300 ? o.since : now - 30 * 86_400;
  const e = isObj(o.export) && typeof o.export.uuid === "string" && UUID.test(o.export.uuid) && typeof o.export.at === "number" ? { uuid: o.export.uuid, at: o.export.at } : undefined;
  return { since, export: e };
}

export const tenableAdapter: PullAdapter = {
  manifest: {
    kind: "tenable", displayName: "Tenable Vulnerability Management", vendor: "Tenable", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["cloud.tenable.com"],
    summary: "Open vulnerabilities per asset with their CVEs, severity and fix, from Tenable's vulnerability export. High and critical by default. Read only.",
    auth: "API access key and secret key of a Tenable user with the Basic role and view access to the assets; sealed per connection.",
  },
  configSchema: z.strictObject({ min_severity: z.enum(["medium", "high", "critical"]).default("high") }),
  secretFields: ["access_key", "secret_key"],
  async poll(conn, cursor, signal) {
    if (!KEY.test(conn.secrets.access_key ?? "") || !KEY.test(conn.secrets.secret_key ?? "")) throw new Error("The Tenable API keys are not valid (64 hexadecimal characters each)");
    const m = tenableAdapter.manifest;
    const headers = { "x-apikeys": `accessKey=${conn.secrets.access_key};secretKey=${conn.secrets.secret_key}`, accept: "application/json", "content-type": "application/json" };
    const call = async (method: string, path: string, body?: unknown, maxBytes = 1024 * 1024) => {
      const res = await adapterFetch(m, `${HOST}${path}`, { method, signal, timeoutMs: 30_000, maxBytes, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      if (res.status === 429 || res.status >= 500) throw new Error(`Tenable answered ${res.status}; will retry`);
      if (res.status === 401 || res.status === 403) throw new Error(`Tenable refused the request (${res.status}); check the API keys and that the user may view vulnerabilities`);
      return res;
    };
    const cur = readCursor(cursor);
    const now = Math.floor(Date.now() / 1000);

    if (!cur.export) {
      const min = String(conn.config.min_severity ?? "high");
      const severity = min === "critical" ? ["critical"] : min === "medium" ? ["medium", "high", "critical"] : ["high", "critical"];
      const res = await call("POST", "/vulns/export", { num_assets: 500, filters: { severity, state: ["open", "reopened"], since: cur.since } });
      if (res.status !== 200) throw new Error(`Tenable answered ${res.status} (starting the export)`);
      let uuid = "";
      try { uuid = String((JSON.parse(res.body) as { export_uuid?: unknown }).export_uuid ?? ""); } catch { /* below */ }
      if (!UUID.test(uuid)) throw new Error("Tenable returned no export id");
      return { findings: [], cursor: { since: cur.since, export: { uuid, at: now } } };
    }

    const st = await call("GET", `/vulns/export/${cur.export.uuid}/status`);
    // The export is gone (expired or unknown): start again from the same point.
    if (st.status === 404) return { findings: [], cursor: { since: cur.since } };
    if (st.status !== 200) throw new Error(`Tenable answered ${st.status} (export status)`);
    let status = ""; let chunks: number[] = [];
    try {
      const b = JSON.parse(st.body) as { status?: unknown; chunks_available?: unknown };
      status = String(b.status ?? "").toUpperCase();
      chunks = (Array.isArray(b.chunks_available) ? b.chunks_available : []).filter((c): c is number => typeof c === "number" && Number.isInteger(c) && c > 0 && c < 100_000);
    } catch { throw new Error("Tenable returned invalid JSON"); }
    if (status === "ERROR" || status === "CANCELLED") return { findings: [], cursor: { since: cur.since } };
    if (status !== "FINISHED") {
      if ((now - cur.export.at) * 1000 > GIVE_UP_MS) return { findings: [], cursor: { since: cur.since } };
      return { findings: [], cursor: cur };
    }
    const findings: Finding[] = [];
    for (const c of chunks.slice(0, MAX_CHUNKS)) {
      const res = await call("GET", `/vulns/export/${cur.export.uuid}/chunks/${c}`, undefined, 64 * 1024 * 1024);
      if (res.status !== 200) throw new Error(`Tenable answered ${res.status} (export chunk ${c})`);
      let rows: unknown[] = [];
      try { const b = JSON.parse(res.body); rows = Array.isArray(b) ? b : []; } catch { throw new Error("Tenable returned invalid JSON"); }
      for (const v of rows) {
        if (!isObj(v) || findings.length >= MAX_FINDINGS) continue;
        const f = findingFromTenable(v);
        if (f) findings.push(f);
      }
    }
    // The next export starts where this one was asked for; what changed while it was prepared comes then.
    return { findings, cursor: { since: cur.export.at } };
  },
};
