/**
 * AbuseIPDB — how often an address has been reported for abuse (API v2 "check", read only).
 *
 * Addresses only. The customer's own API key is sealed per connection and sent as the "Key" header to
 * api.abuseipdb.com. The verdict is AbuseIPDB's confidence score (0–100): 75 and above malicious, 25–74
 * suspicious. An address nobody reported is "nothing known" — not "safe": absence of reports proves nothing.
 * Nothing is reported TO AbuseIPDB: Argust only asks.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, parseTime } from "./shared.js";
import type { IntelAdapter, IntelAnswer, IntelIndicator } from "./types.js";

const KEY = /^[a-f0-9]{80}$/i;

export function answerFromAbuseIpdb(i: IntelIndicator, body: unknown): IntelAnswer | null {
  const d = (body as { data?: Record<string, unknown> } | null)?.data;
  if (!d || typeof d !== "object") return null;
  const score = typeof d.abuseConfidenceScore === "number" && d.abuseConfidenceScore >= 0 && d.abuseConfidenceScore <= 100 ? d.abuseConfidenceScore : null;
  const reports = typeof d.totalReports === "number" && d.totalReports >= 0 ? d.totalReports : 0;
  if (score === null || (score === 0 && reports === 0)) return null;
  const isp = cleanText(d.isp, 80), country = cleanText(d.countryCode, 4), usage = cleanText(d.usageType, 60);
  return {
    indicator: i.value, type: "ip", verdict: score >= 75 ? "malicious" : score >= 25 ? "suspicious" : "unknown", confidence: score, lastSeen: parseTime(d.lastReportedAt),
    notes: cleanText(`Abuse confidence ${score} of 100 from ${reports} report${reports === 1 ? "" : "s"} in 90 days.${isp ? ` Network: ${isp}.` : ""}${usage ? ` Use: ${usage}.` : ""}${country ? ` Country: ${country}.` : ""}`, 400),
  };
}

export const abuseipdbAdapter: IntelAdapter = {
  manifest: {
    kind: "abuseipdb", displayName: "AbuseIPDB", vendor: "AbuseIPDB", status: "available", plane: "data", inbound: null, outbound: [], intel: true,
    egressHosts: ["api.abuseipdb.com"],
    summary: "How often an address was reported for attacks, spam or scanning in the last 90 days, as a 0–100 score. Asked on demand; Argust reports nothing to it. Read only.",
    auth: "Your AbuseIPDB API key, sealed per connection.",
  },
  configSchema: z.strictObject({}),
  secretFields: ["api_key"],
  supports: ["ip"],
  maxPerCall: 10,
  async lookup(conn, indicators, signal) {
    if (!KEY.test(conn.secrets.api_key ?? "")) throw new Error("The AbuseIPDB API key is not valid (80 hexadecimal characters)");
    const out: IntelAnswer[] = [];
    for (const i of indicators) {
      if (i.type !== "ip") continue;
      const res = await adapterFetch(abuseipdbAdapter.manifest, `https://api.abuseipdb.com/api/v2/check?${new URLSearchParams({ ipAddress: i.value, maxAgeInDays: "90" })}`, {
        method: "GET", signal, timeoutMs: 15_000, maxBytes: 256 * 1024, headers: { Key: conn.secrets.api_key!, accept: "application/json" },
      });
      if (res.status === 429) break; // Daily quota: keep what was answered.
      if (res.status === 401 || res.status === 403) throw new Error(`AbuseIPDB refused the API key (${res.status})`);
      if (res.status === 422) continue; // An address it does not accept: no opinion.
      if (res.status !== 200) throw new Error(`AbuseIPDB answered ${res.status}`);
      let body: unknown = null;
      try { body = JSON.parse(res.body); } catch { throw new Error("AbuseIPDB returned invalid JSON"); }
      const a = answerFromAbuseIpdb(i, body);
      if (a) out.push(a);
    }
    return out;
  },
};
