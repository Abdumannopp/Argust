/**
 * Fortinet FortiGate — security events the firewall SENDS to Legion (push).
 *
 * A FortiGate is a device on the customer's network: Legion never calls into it. Instead, a FortiOS
 * "automation stitch" (trigger: a log event; action: Webhook) posts each matching event to
 *   POST /security-events/webhook/fortigate?connection=<id>      Authorization: Bearer <token>
 * FortiOS cannot sign a request, so the proof is a long random token that belongs to one connection, sent in a
 * header over TLS and compared in constant time; the workspace is whatever that connection belongs to. A token
 * is weaker than the signed sensor webhook (a captured request could be replayed), so a replay only ever
 * re-delivers an event that is dropped as a duplicate, and a wrong token counts against the sender's address.
 *
 * Accepted bodies: the JSON object described in INTEGRATIONS.md (built from %%log.…%% variables), an array of
 * them, or raw FortiOS log lines (key=value). Routine traffic and notice-level lines are skipped on purpose.
 * Legion cannot change anything on the FortiGate.
 */
import { z } from "zod";
import { cleanText, mitreIn, parseTime, pickIp, sha } from "./shared.js";
import type { Severity } from "../types.js";
import type { Finding, NormalizeResult, PushAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_EVENTS = 200;
/** Subtypes that are a detection whatever their log level. */
const DETECTIONS = new Set(["ips", "virus", "anomaly", "waf", "dlp", "botnet", "emailfilter-virus"]);
const BY_LEVEL: Record<string, Severity | null> = { emergency: "critical", alert: "critical", critical: "high", error: "high", warning: "medium", notice: null, information: null, debug: null };
const BY_SEVERITY: Record<string, Severity> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "low" };

/** `date=2026-11-14 type="utm" attack="A B" srcip=1.2.3.4` → fields. Quoted values may contain spaces. */
export function parseFortiLine(line: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([A-Za-z][A-Za-z0-9_]{0,40})=(?:"((?:[^"\\]|\\.)*)"|(\S*))/g;
  let m: RegExpExecArray | null; let n = 0;
  while ((m = re.exec(line)) !== null && n++ < 150) out[m[1]!] = (m[2] ?? m[3] ?? "").replace(/\\(.)/g, "$1");
  return out;
}

/** A value FortiOS filled in; a template variable it left as it was ("%%log.attack%%") is empty. */
const val = (e: Obj, k: string, max: number): string => { const v = cleanText(e[k], max); return v.startsWith("%%") || v === "N/A" ? "" : v; };

export function findingFromFortiEvent(e: Obj): Finding | null {
  const type = val(e, "type", 30).toLowerCase(), subtype = val(e, "subtype", 40).toLowerCase(), level = val(e, "level", 20).toLowerCase();
  if (type === "traffic") return null;
  const detection = DETECTIONS.has(subtype);
  const severity = BY_SEVERITY[val(e, "severity", 20).toLowerCase()] ?? BY_LEVEL[level] ?? (detection ? "medium" : null);
  if (!severity) return null;
  const found = val(e, "attack", 200) || val(e, "virus", 200) || val(e, "msg", 300) || val(e, "logdesc", 200);
  if (!found) return null;
  const src = pickIp(val(e, "srcip", 60)), dst = pickIp(val(e, "dstip", 60));
  const device = val(e, "devname", 120), action = val(e, "action", 40), user = val(e, "user", 120);
  const ns = val(e, "eventtime", 25);
  const when = /^\d{16,19}$/.test(ns) ? parseTime(new Date(Number(ns.slice(0, 13))).toISOString()) : parseTime(`${val(e, "date", 12)}T${val(e, "time", 10)}Z`);
  const target = val(e, "hostname", 255) || val(e, "dstname", 255) || dst || device || null;
  return {
    externalId: `fgt-${sha([val(e, "logid", 20), ns || `${val(e, "date", 12)} ${val(e, "time", 10)}`, src, dst, found, val(e, "sessionid", 20)].join("|")).slice(0, 40)}`,
    title: cleanText(`FortiGate ${subtype || type || "event"}: ${found}`, 300),
    severity,
    summary: [found, action ? `Action: ${action}` : "", src ? `From: ${src}` : "", dst ? `To: ${dst}` : "", user ? `User: ${user}` : "", device ? `Firewall: ${device}` : "", val(e, "ref", 200) ? `Reference: ${val(e, "ref", 200)}` : ""].filter(Boolean).join("\n"),
    occurredAt: when,
    sourceIp: src,
    target,
    mitre: mitreIn(found),
    confidence: detection ? 75 : 60,
    asset: null,
  };
}

export const fortigateAdapter: PushAdapter & { configSchema: z.ZodType<Record<string, unknown>>; secretFields: string[]; validateSecrets(s: Record<string, string>): string | null } = {
  manifest: {
    kind: "fortigate", displayName: "Fortinet FortiGate", vendor: "Fortinet", status: "available", plane: "data", inbound: "push", outbound: [],
    egressHosts: [],
    summary: "Intrusion, virus, anomaly and other warning-or-worse events your FortiGate sends through an automation stitch webhook. Legion never connects to the firewall. Read only.",
    auth: "A long random token of one connection, sent as Authorization: Bearer by the FortiGate webhook action. POST /security-events/webhook/fortigate?connection=<id>.",
  },
  configSchema: z.strictObject({}),
  secretFields: ["token"],
  validateSecrets: (s) => (/^[A-Za-z0-9_\-.~+/=]{32,200}$/.test(s.token ?? "") ? null : "token: at least 32 letters, digits or - _ . ~ + / = (use a long random value)"),
  normalize(payload: unknown): NormalizeResult {
    let events: Obj[] = [];
    if (typeof payload === "string") events = payload.split(/\r?\n/).filter((l) => l.includes("=")).slice(0, MAX_EVENTS).map(parseFortiLine);
    else if (Array.isArray(payload)) events = payload.filter(isObj).slice(0, MAX_EVENTS);
    else if (isObj(payload)) events = Array.isArray(payload.events) ? payload.events.filter(isObj).slice(0, MAX_EVENTS) : [payload];
    const findings = events.map(findingFromFortiEvent).filter((f): f is Finding => f !== null);
    return findings.length ? { skipped: false, source: "fortigate", findings } : { skipped: true, reason: "no security event" };
  },
};
