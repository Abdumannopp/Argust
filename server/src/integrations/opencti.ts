/**
 * OpenCTI — your own threat-intelligence knowledge base: is this indicator a known observable, and how is it scored?
 *
 * Read only: one GraphQL query (stixCyberObservables, exact value) with the token of a read-only OpenCTI user,
 * sealed per connection. The host is the customer's own server, so it goes through guardedFetch (public DNS
 * name over HTTPS only). OpenCTI's own score (x_opencti_score, 0–100) decides: 70+ malicious, 40–69
 * suspicious, below that no opinion — being recorded in a knowledge base is not being malicious.
 */
import { z } from "zod";
import { guardedFetch, validCustomerHost } from "./guarded-fetch.js";
import { cleanText, parseTime } from "./shared.js";
import type { IntelAdapter, IntelAnswer, IntelIndicator } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const QUERY = `query LegionLookup($filters: FilterGroup) { stixCyberObservables(first: 10, filters: $filters) { edges { node { entity_type observable_value x_opencti_score updated_at objectLabel { value } } } } }`;

export function answerFromOpenCti(i: IntelIndicator, body: unknown): IntelAnswer | null {
  const edges = isObj(body) && isObj(body.data) && isObj(body.data.stixCyberObservables) && Array.isArray(body.data.stixCyberObservables.edges) ? body.data.stixCyberObservables.edges : [];
  const nodes = edges.map((e) => (isObj(e) && isObj(e.node) ? e.node : null)).filter((n): n is Obj => !!n && typeof n.observable_value === "string" && n.observable_value.toLowerCase() === i.value.toLowerCase());
  if (!nodes.length) return null;
  const scored = nodes.filter((n) => typeof n.x_opencti_score === "number" && n.x_opencti_score >= 0 && n.x_opencti_score <= 100);
  const score = scored.length ? Math.max(...scored.map((n) => n.x_opencti_score as number)) : null;
  const labels = [...new Set(nodes.flatMap((n) => (Array.isArray(n.objectLabel) ? n.objectLabel : []).map((l) => cleanText(isObj(l) ? l.value : "", 40)).filter(Boolean)))].slice(0, 6);
  const times = nodes.map((n) => parseTime(n.updated_at)).filter((t): t is string => !!t).sort();
  return {
    indicator: i.value, type: i.type, verdict: score === null ? "unknown" : score >= 70 ? "malicious" : score >= 40 ? "suspicious" : "unknown", confidence: score, lastSeen: times.at(-1) ?? null,
    notes: cleanText(`Known observable in OpenCTI${score === null ? ", not scored" : `, score ${score} of 100`}.${labels.length ? ` Labels: ${labels.join(", ")}.` : ""}`, 400),
  };
}

export const openctiAdapter: IntelAdapter = {
  manifest: {
    kind: "opencti", displayName: "OpenCTI", vendor: "Filigran", status: "available", plane: "data", inbound: null, outbound: [], intel: true,
    egressHosts: [],
    summary: "Checks addresses, domains, URLs, file hashes and e-mail addresses against the observables in your own OpenCTI, with its score. Asked on demand. Read only.",
    auth: "API token of a read-only OpenCTI user, sealed per connection. Your OpenCTI must be reachable from the internet over HTTPS with a valid certificate.",
  },
  configSchema: z.strictObject({ host: z.string().toLowerCase().max(253).refine(validCustomerHost, "The DNS name of your OpenCTI server, for example opencti.example.com (no https://, no address)") }),
  secretFields: ["api_token"],
  supports: ["ip", "domain", "url", "hash", "email"],
  maxPerCall: 20,
  async lookup(conn, indicators, signal) {
    const out: IntelAnswer[] = [];
    for (const i of indicators) {
      const res = await guardedFetch(String(conn.config.host), "/graphql", {
        method: "POST", signal, timeoutMs: 15_000, maxBytes: 2 * 1024 * 1024,
        headers: { authorization: `Bearer ${conn.secrets.api_token ?? ""}`, accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify({ query: QUERY, variables: { filters: { mode: "and", filters: [{ key: "value", values: [i.value], operator: "eq" }], filterGroups: [] } } }),
      });
      if (res.status === 401 || res.status === 403) throw new Error(`OpenCTI refused the token (${res.status})`);
      if (res.status !== 200) throw new Error(`OpenCTI answered ${res.status}`);
      let body: unknown = null;
      try { body = JSON.parse(res.body); } catch { throw new Error("OpenCTI returned invalid JSON"); }
      if (isObj(body) && Array.isArray(body.errors) && body.errors.length) throw new Error(`OpenCTI refused the query: ${cleanText(isObj(body.errors[0]) ? body.errors[0].message : "", 120) || "error"}`);
      const a = answerFromOpenCti(i, body);
      if (a) out.push(a);
    }
    return out;
  },
};
