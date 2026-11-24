/**
 * Qualys VMDR — confirmed, open, severity 4–5 vulnerabilities per host (pull, read only).
 *
 * Two calls of the Qualys API v2, both on the customer's Qualys platform (chosen from a fixed list — the platform
 * is in the account's URL; never a free address):
 *   host detection list   which QIDs are open on which hosts, changed since the cursor
 *   knowledge base        the name, CVEs and fix of those QIDs
 * Qualys answers in XML. Only the handful of documented tags Argust needs are read, from a size-capped response,
 * with no general XML parser: no entities are expanded and no external reference is ever followed.
 * A read-only API user (Reader role, API access), sent as HTTP Basic; sealed per connection.
 * One Argust alert per (host, QID). Argust never launches a scan and never changes anything in Qualys.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, cursorSince, parseTime, pickIp } from "./shared.js";
import { findingFromScannerVuln } from "./vuln-shared.js";
import type { Finding, PullAdapter } from "./types.js";

export const QUALYS_PLATFORMS = {
  us1: "qualysapi.qualys.com", us2: "qualysapi.qg2.apps.qualys.com", us3: "qualysapi.qg3.apps.qualys.com", us4: "qualysapi.qg4.apps.qualys.com",
  eu1: "qualysapi.qualys.eu", eu2: "qualysapi.qg2.apps.qualys.eu", in1: "qualysapi.qg1.apps.qualys.in", ca1: "qualysapi.qg1.apps.qualys.ca",
  ae1: "qualysapi.qg1.apps.qualys.ae", uk1: "qualysapi.qg1.apps.qualys.co.uk", au1: "qualysapi.qg1.apps.qualys.com.au",
} as const;
const MAX_HOSTS = 500;
const MAX_FINDINGS = 2000;

/** The text of the first <tag>…</tag> in a fragment, CDATA unwrapped and the five basic entities decoded. Nothing else. */
export function xmlText(fragment: string, tag: string): string {
  const m = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`).exec(fragment);
  if (!m) return "";
  const raw = m[1]!.trim();
  const cdata = /^<!\[CDATA\[([\s\S]*?)\]\]>$/.exec(raw);
  if (cdata) return cdata[1]!;
  return raw.replace(/<[^>]*>/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&").trim();
}
/** Every <tag>…</tag> block in a fragment (not nested in itself), bounded. */
export function xmlBlocks(fragment: string, tag: string, max: number): string[] {
  const out: string[] = [];
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(fragment)) !== null && out.length < max) out.push(m[1]!);
  return out;
}

export interface QualysDetection { hostId: string; host: string | null; ip: string | null; os: string | null; qid: string; severity: number; firstFound: string | null }

export function detectionsFromXml(xml: string): QualysDetection[] {
  const out: QualysDetection[] = [];
  for (const h of xmlBlocks(xml, "HOST", MAX_HOSTS)) {
    const list = xmlBlocks(h, "DETECTION_LIST", 1)[0] ?? "";
    const head = h.replace(/<DETECTION_LIST>[\s\S]*<\/DETECTION_LIST>/, "");
    const hostId = xmlText(head, "ID");
    if (!/^\d{1,15}$/.test(hostId)) continue;
    const host = cleanText(xmlText(head, "DNS") || xmlText(head, "NETBIOS"), 255) || null;
    for (const d of xmlBlocks(list, "DETECTION", 500)) {
      const qid = xmlText(d, "QID"); const severity = Number(xmlText(d, "SEVERITY"));
      const status = xmlText(d, "STATUS").toLowerCase();
      if (!/^\d{1,9}$/.test(qid) || !(severity >= 1 && severity <= 5) || status === "fixed") continue;
      // Only what Qualys confirmed: a "Potential" detection is a guess, an "Info" one is not a weakness.
      if (xmlText(d, "TYPE") !== "Confirmed") continue;
      out.push({ hostId, host, ip: pickIp(xmlText(head, "IP"), xmlText(head, "IPV6")), os: cleanText(xmlText(head, "OS"), 80) || null, qid, severity, firstFound: parseTime(xmlText(d, "FIRST_FOUND_DATETIME")) });
    }
  }
  return out;
}

export function knowledgeFromXml(xml: string): Map<string, { title: string; cves: string[]; solution: string; patchable: boolean | null }> {
  const out = new Map<string, { title: string; cves: string[]; solution: string; patchable: boolean | null }>();
  for (const v of xmlBlocks(xml, "VULN", 1000)) {
    const qid = xmlText(v, "QID");
    if (!/^\d{1,9}$/.test(qid)) continue;
    const p = xmlText(v, "PATCHABLE");
    out.set(qid, {
      title: cleanText(xmlText(v, "TITLE"), 200), cves: xmlBlocks(xmlBlocks(v, "CVE_LIST", 1)[0] ?? "", "CVE", 30).map((c) => xmlText(c, "ID")),
      solution: cleanText(xmlText(v, "SOLUTION"), 600), patchable: p === "1" ? true : p === "0" ? false : null,
    });
  }
  return out;
}

export const qualysAdapter: PullAdapter = {
  manifest: {
    kind: "qualys", displayName: "Qualys VMDR", vendor: "Qualys", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: Object.values(QUALYS_PLATFORMS),
    summary: "Confirmed open vulnerabilities of severity 4 and 5 per host, with their CVEs and fix, from Qualys host detections. Read only.",
    auth: "A Qualys user with the Reader role and API access (user name and password, HTTP Basic); sealed per connection.",
  },
  configSchema: z.strictObject({ platform: z.enum(Object.keys(QUALYS_PLATFORMS) as [keyof typeof QUALYS_PLATFORMS, ...(keyof typeof QUALYS_PLATFORMS)[]]).default("us1") }),
  secretFields: ["username", "password"],
  async poll(conn, cursor, signal) {
    const host = QUALYS_PLATFORMS[String(conn.config.platform ?? "us1") as keyof typeof QUALYS_PLATFORMS] ?? QUALYS_PLATFORMS.us1;
    const m = qualysAdapter.manifest;
    const headers = { authorization: `Basic ${Buffer.from(`${conn.secrets.username ?? ""}:${conn.secrets.password ?? ""}`).toString("base64")}`, "x-requested-with": "Argust", "content-type": "application/x-www-form-urlencoded" };
    const post = async (path: string, form: Record<string, string>, what: string) => {
      const res = await adapterFetch(m, `https://${host}${path}`, { method: "POST", signal, timeoutMs: 60_000, maxBytes: 32 * 1024 * 1024, headers, body: new URLSearchParams(form).toString() });
      if (res.status === 409 || res.status === 429 || res.status >= 500) throw new Error(`Qualys answered ${res.status} (${what}); will retry`);
      if (res.status === 401 || res.status === 403) throw new Error(`Qualys refused the request (${res.status}); check the platform, the user and that it has API access`);
      if (res.status !== 200) throw new Error(`Qualys answered ${res.status} (${what})`);
      return res.body;
    };
    const since = cursorSince(cursor, 30 * 24);
    // A long list comes in parts: Qualys says from which host id the next part starts, and the cursor keeps it.
    const part = (cursor as { id_min?: unknown; started?: unknown } | null) ?? {};
    const idMin = typeof part.id_min === "string" && /^\d{1,15}$/.test(part.id_min) ? part.id_min : null;
    const started = idMin && typeof part.started === "string" && parseTime(part.started) ? part.started : new Date().toISOString();
    const xml = await post("/api/2.0/fo/asset/host/vm/detection/", {
      action: "list", status: "New,Active,Re-Opened", severities: "4-5", show_results: "0", show_igs: "0", truncation_limit: String(MAX_HOSTS),
      detection_updated_since: since.replace(/\.\d+Z$/, "Z"), ...(idMin ? { id_min: idMin } : {}),
    }, "host detections");
    const detections = detectionsFromXml(xml).slice(0, MAX_FINDINGS);
    const findings: Finding[] = [];
    if (detections.length) {
      const qids = [...new Set(detections.map((d) => d.qid))].slice(0, 1000);
      const kb = knowledgeFromXml(await post("/api/2.0/fo/knowledge_base/vuln/", { action: "list", details: "Basic", ids: qids.join(",") }, "knowledge base"));
      for (const d of detections) {
        const k = kb.get(d.qid);
        const f = findingFromScannerVuln({
          scanner: "Qualys", id: `${d.hostId}:${d.qid}`, name: k?.title || `Qualys QID ${d.qid}`, cves: k?.cves ?? [], severity: d.severity >= 5 ? "critical" : "high",
          host: d.host, ip: d.ip, os: d.os, firstFound: d.firstFound, solution: k?.solution || null, detail: `Qualys QID ${d.qid}, severity ${d.severity} of 5`, hasFix: k?.patchable ?? null,
        });
        if (f) findings.push(f);
      }
    }
    // More hosts than one answer holds: the next poll continues from the host id Qualys names, with the same
    // "since"; only when the whole list was read does "since" move to when this pass began.
    const next = /<WARNING>[\s\S]*?<URL>[\s\S]*?[?&;]id_min=(\d{1,15})[\s\S]*?<\/URL>/.exec(xml)?.[1] ?? null;
    return { findings, cursor: next && next !== idMin ? { since, id_min: next, started } : { since: started } };
  },
};
