/**
 * MISP — your own threat-sharing platform: is this indicator in an event you or your community recorded?
 *
 * Read only: POST /attributes/restSearch with the exact value (a search, despite the verb). The API key of a
 * read-only MISP user is sealed per connection. The host is the customer's own server, so it goes through
 * guardedFetch: a public DNS name over HTTPS only, never an internal address. An attribute marked "to_ids"
 * (meant for detection) makes the indicator malicious; one that is only recorded makes it suspicious; an
 * attribute on a warning list is skipped by MISP itself (enforceWarninglist).
 */
import { z } from "zod";
import { guardedFetch, validCustomerHost } from "./guarded-fetch.js";
import { cleanText, parseTime } from "./shared.js";
import type { IntelAdapter, IntelAnswer, IntelIndicator } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

export function answerFromMisp(i: IntelIndicator, body: unknown): IntelAnswer | null {
  const attrs = isObj(body) && isObj(body.response) && Array.isArray(body.response.Attribute) ? body.response.Attribute.filter(isObj) : [];
  // Exact matches only: a provider may answer only what was asked.
  const hits = attrs.filter((a) => typeof a.value === "string" && a.value.toLowerCase() === i.value.toLowerCase());
  if (!hits.length) return null;
  const ids = hits.some((a) => a.to_ids === true || a.to_ids === "1" || a.to_ids === 1);
  const events = [...new Set(hits.map((a) => cleanText(isObj(a.Event) ? a.Event.info : "", 120)).filter(Boolean))].slice(0, 3);
  const times = hits.map((a) => (typeof a.timestamp === "string" && /^\d{9,11}$/.test(a.timestamp) ? parseTime(new Date(Number(a.timestamp) * 1000).toISOString()) : null)).filter((t): t is string => !!t).sort();
  return {
    indicator: i.value, type: i.type, verdict: ids ? "malicious" : "suspicious", confidence: ids ? 80 : 50, lastSeen: times.at(-1) ?? null,
    notes: cleanText(`In ${hits.length} MISP attribute${hits.length === 1 ? "" : "s"}${ids ? ", marked for detection" : ""}.${events.length ? ` Events: ${events.join("; ")}.` : ""}`, 500),
  };
}

export const mispAdapter: IntelAdapter = {
  manifest: {
    kind: "misp", displayName: "MISP", vendor: "MISP Project", status: "available", plane: "data", inbound: null, outbound: [], intel: true,
    egressHosts: [],
    summary: "Checks addresses, domains, URLs, file hashes and e-mail addresses against the events in your own MISP. Asked on demand. Read only.",
    auth: "API key of a read-only MISP user, sealed per connection. Your MISP must be reachable from the internet over HTTPS with a valid certificate.",
  },
  configSchema: z.strictObject({ host: z.string().toLowerCase().max(253).refine(validCustomerHost, "The DNS name of your MISP server, for example misp.example.com (no https://, no address)") }),
  secretFields: ["api_key"],
  supports: ["ip", "domain", "url", "hash", "email"],
  maxPerCall: 20,
  async lookup(conn, indicators, signal) {
    const out: IntelAnswer[] = [];
    for (const i of indicators) {
      const res = await guardedFetch(String(conn.config.host), "/attributes/restSearch", {
        method: "POST", signal, timeoutMs: 15_000, maxBytes: 2 * 1024 * 1024,
        headers: { authorization: conn.secrets.api_key ?? "", accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify({ returnFormat: "json", value: i.value, limit: 25, includeEventInfo: true, enforceWarninglist: true, deleted: false }),
      });
      if (res.status === 401 || res.status === 403) throw new Error(`MISP refused the API key (${res.status})`);
      if (res.status !== 200) throw new Error(`MISP answered ${res.status}`);
      let body: unknown = null;
      try { body = JSON.parse(res.body); } catch { throw new Error("MISP returned invalid JSON"); }
      const a = answerFromMisp(i, body);
      if (a) out.push(a);
    }
    return out;
  },
};
