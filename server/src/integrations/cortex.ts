/**
 * Palo Alto Networks Cortex XDR — incidents (pull, read only): the XDR's own grouping of endpoint, network and
 * identity alerts into one case.
 *
 * POST /public_api/v1/incidents/get_incidents/ on the tenant's API host (api-<name>.xdr.<region>.paloaltonetworks.com,
 * chosen by name — never a free URL). An API key with the Viewer role; the key is sealed per connection. With an
 * "advanced" key (the default, recommended by Palo Alto) each request carries a fresh nonce and timestamp and
 * the SHA-256 of key + nonce + timestamp, so the key itself never travels; a "standard" key is sent as it is.
 * Cursor: the newest modification_time. One Argust alert per incident id. Argust never changes an incident.
 */
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, cursorSince, mitreIn, parseTime, severityOf } from "./shared.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const FQDN = /^api-[a-z0-9][a-z0-9-]{0,62}\.xdr\.[a-z0-9]{2,10}\.paloaltonetworks\.com$/;
const PAGE = 100;
const MAX_PAGES = 5;

export function cortexHeaders(keyId: string, key: string, type: string, now = Date.now(), nonce = randomBytes(32).toString("hex")): Record<string, string> {
  const base = { "x-xdr-auth-id": keyId, "content-type": "application/json", accept: "application/json" };
  if (type === "standard") return { ...base, authorization: key };
  const ts = String(now);
  return { ...base, "x-xdr-timestamp": ts, "x-xdr-nonce": nonce, authorization: createHash("sha256").update(key + nonce + ts).digest("hex") };
}

export function findingFromCortexIncident(i: Obj): Finding | null {
  const id = cleanText(i.incident_id, 100);
  if (!id) return null;
  const status = String(i.status ?? "").toLowerCase();
  if (status.startsWith("resolved")) return null;
  // "host name:endpoint id" entries; the name is what other tools call the machine.
  const hosts = (Array.isArray(i.hosts) ? i.hosts : []).map((h) => cleanText(String(h).split(":")[0], 255)).filter(Boolean);
  const users = (Array.isArray(i.users) ? i.users : []).map((u) => cleanText(u, 120)).filter(Boolean);
  const name = cleanText(i.incident_name, 200) || cleanText(i.description, 300) || `Cortex XDR incident ${id}`;
  const ms = typeof i.creation_time === "number" && i.creation_time > 0 ? new Date(i.creation_time).toISOString() : null;
  const techniques = Array.isArray(i.mitre_techniques_ids_and_names) ? i.mitre_techniques_ids_and_names.map(String) : [];
  const sev = String(i.severity ?? "").toLowerCase();
  return {
    externalId: id,
    title: cleanText(`Cortex XDR: ${name}`, 300),
    severity: sev === "informational" ? "low" : severityOf(sev || "medium"),
    summary: [cleanText(i.description, 2000), typeof i.alert_count === "number" ? `Alerts in the incident: ${i.alert_count}` : "", hosts.length ? `Hosts: ${hosts.slice(0, 8).join(", ")}` : "", users.length ? `Users: ${users.slice(0, 8).join(", ")}` : "", `Status: ${cleanText(i.status, 40) || "new"}`].filter(Boolean).join("\n"),
    occurredAt: parseTime(ms),
    sourceIp: null,
    target: hosts[0] ?? users[0] ?? null,
    mitre: mitreIn(techniques),
    confidence: 80,
    asset: hosts[0] ? { name: hosts[0], ip: null, os: null, kind: "endpoint" } : null,
  };
}

export const cortexAdapter: PullAdapter = {
  manifest: {
    kind: "cortex_xdr", displayName: "Palo Alto Cortex XDR", vendor: "Palo Alto Networks", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["*.xdr.*.paloaltonetworks.com"],
    summary: "Cortex XDR incidents (endpoint, network and identity alerts the XDR grouped into one case), polled by modification time. Read only.",
    auth: "Cortex XDR API key with the Viewer role (advanced key recommended) and its key ID; the key is sealed per connection.",
  },
  configSchema: z.strictObject({
    api_host: z.string().toLowerCase().regex(FQDN, "Your Cortex XDR API host, for example api-acme.xdr.us.paloaltonetworks.com"),
    api_key_id: z.string().regex(/^\d{1,10}$/, "The API key ID (a number)"),
    key_type: z.enum(["advanced", "standard"]).default("advanced"),
  }),
  secretFields: ["api_key"],
  async poll(conn, cursor, signal) {
    const since = cursorSince(cursor);
    const findings: Finding[] = [];
    let newest = since;
    for (let page = 0; page < MAX_PAGES; page++) {
      const res = await adapterFetch(cortexAdapter.manifest, `https://${String(conn.config.api_host)}/public_api/v1/incidents/get_incidents/`, {
        method: "POST", signal, timeoutMs: 30_000, maxBytes: 16 * 1024 * 1024,
        headers: cortexHeaders(String(conn.config.api_key_id), conn.secrets.api_key ?? "", String(conn.config.key_type ?? "advanced")),
        body: JSON.stringify({ request_data: { filters: [{ field: "modification_time", operator: "gte", value: Date.parse(since) }], search_from: page * PAGE, search_to: (page + 1) * PAGE, sort: { field: "modification_time", keyword: "asc" } } }),
      });
      if (res.status === 429 || res.status >= 500) throw new Error(`Cortex XDR answered ${res.status}; will retry`);
      if (res.status === 401 || res.status === 403) throw new Error(`Cortex XDR refused the request (${res.status}); check the key, its ID, its type (advanced or standard) and the Viewer role`);
      if (res.status !== 200) throw new Error(`Cortex XDR answered ${res.status}`);
      let list: unknown[] = [];
      try { const r = (JSON.parse(res.body) as { reply?: { incidents?: unknown } }).reply?.incidents; list = Array.isArray(r) ? r : []; } catch { throw new Error("Cortex XDR returned invalid JSON"); }
      for (const i of list) {
        if (!isObj(i)) continue;
        const f = findingFromCortexIncident(i);
        if (f) findings.push(f);
        const t = typeof i.modification_time === "number" && i.modification_time > 0 && i.modification_time <= Date.now() + 300_000 ? new Date(i.modification_time).toISOString() : null;
        if (t && t > newest) newest = t;
      }
      if (list.length < PAGE) break;
    }
    return { findings, cursor: { since: newest } };
  },
};
