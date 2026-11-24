/**
 * VirusTotal — reputation of addresses, domains, URLs and file hashes (API v3, read only).
 *
 * Argust asks about one indicator at a time with the customer's own API key (sealed per connection), on
 * www.virustotal.com only. The verdict is the count of security vendors: malicious when several flag it,
 * suspicious when one or two do, benign when many looked and none did. Nothing is uploaded: a hash is looked
 * up, a file is never sent; a URL is looked up by its identifier, it is not submitted for scanning.
 * Free keys allow four lookups a minute, so one call spends at most four; a 429 ends the call quietly.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText } from "./shared.js";
import type { IntelAdapter, IntelAnswer, IntelIndicator } from "./types.js";

const HASH = /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const KEY = /^[a-f0-9]{64}$/i;

function pathFor(i: IntelIndicator): string | null {
  if (i.type === "ip") return `/api/v3/ip_addresses/${encodeURIComponent(i.value)}`;
  if (i.type === "domain") return `/api/v3/domains/${encodeURIComponent(i.value)}`;
  if (i.type === "hash") return HASH.test(i.value) ? `/api/v3/files/${i.value.toLowerCase()}` : null;
  if (i.type === "url") return `/api/v3/urls/${Buffer.from(i.value).toString("base64url")}`;
  return null;
}

export function answerFromVirusTotal(i: IntelIndicator, body: unknown): IntelAnswer | null {
  const attrs = (body as { data?: { attributes?: Record<string, unknown> } } | null)?.data?.attributes;
  const stats = attrs?.last_analysis_stats as Record<string, unknown> | undefined;
  if (!stats || typeof stats !== "object") return null;
  const n = (k: string) => (typeof stats[k] === "number" && stats[k] >= 0 ? (stats[k] as number) : 0);
  const mal = n("malicious"), sus = n("suspicious"), clean = n("harmless") + n("undetected");
  const total = mal + sus + clean;
  if (!total) return null;
  const verdict = mal >= 3 ? "malicious" : mal + sus >= 1 ? "suspicious" : clean >= 10 ? "benign" : "unknown";
  const seen = typeof attrs?.last_analysis_date === "number" ? new Date(attrs.last_analysis_date * 1000) : null;
  const owner = cleanText(attrs?.as_owner, 80), country = cleanText(attrs?.country, 4);
  return {
    indicator: i.value, type: i.type, verdict,
    confidence: verdict === "unknown" ? null : Math.round((Math.max(mal + sus, verdict === "benign" ? clean : 0) / total) * 100),
    lastSeen: seen && !Number.isNaN(seen.getTime()) && seen.getTime() <= Date.now() + 86_400_000 ? seen.toISOString() : null,
    notes: cleanText(`${mal} of ${total} security vendors flag it as malicious, ${sus} as suspicious.${owner ? ` Network: ${owner}.` : ""}${country ? ` Country: ${country}.` : ""}`, 400),
  };
}

export const virustotalAdapter: IntelAdapter = {
  manifest: {
    kind: "virustotal", displayName: "VirusTotal", vendor: "Google", status: "available", plane: "data", inbound: null, outbound: [], intel: true,
    egressHosts: ["www.virustotal.com"],
    summary: "Reputation of addresses, domains, URLs and file hashes: how many security vendors flag each. Asked on demand; nothing is uploaded. Read only.",
    auth: "Your VirusTotal API key, sealed per connection.",
  },
  configSchema: z.strictObject({}),
  secretFields: ["api_key"],
  supports: ["ip", "domain", "url", "hash"],
  maxPerCall: 4,
  async lookup(conn, indicators, signal) {
    if (!KEY.test(conn.secrets.api_key ?? "")) throw new Error("The VirusTotal API key is not valid (64 hexadecimal characters)");
    const out: IntelAnswer[] = [];
    for (const i of indicators) {
      const path = pathFor(i);
      if (!path) continue;
      const res = await adapterFetch(virustotalAdapter.manifest, `https://www.virustotal.com${path}`, {
        method: "GET", signal, timeoutMs: 15_000, maxBytes: 2 * 1024 * 1024, headers: { "x-apikey": conn.secrets.api_key!, accept: "application/json" },
      });
      if (res.status === 404) continue; // VirusTotal has never seen it: no opinion.
      if (res.status === 429) break; // Quota: keep what was answered.
      if (res.status === 401 || res.status === 403) throw new Error(`VirusTotal refused the API key (${res.status})`);
      if (res.status !== 200) throw new Error(`VirusTotal answered ${res.status}`);
      let body: unknown = null;
      try { body = JSON.parse(res.body); } catch { throw new Error("VirusTotal returned invalid JSON"); }
      const a = answerFromVirusTotal(i, body);
      if (a) out.push(a);
    }
    return out;
  },
};
