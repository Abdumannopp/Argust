/**
 * Microsoft Entra ID — identity risk detections (Entra ID Protection) over Microsoft Graph (pull, read only):
 * leaked credentials, impossible travel, sign-ins from anonymous or malware-linked addresses, password spray,
 * unfamiliar sign-in properties, token anomalies.
 *
 * An app registration with the application permission IdentityRiskEvent.Read.All (client credentials); Legion
 * asks login.microsoftonline.com for a token and reads graph.microsoft.com only. The client secret is sealed
 * per connection. Risk detections need Entra ID P1 or P2. Cursor: the newest detectedDateTime. One Legion alert
 * per detection id. Read only: this connection can never change an account (that is "entra_response").
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, cursorSince, parseTime, pickIp } from "./shared.js";
import type { Severity } from "../types.js";
import type { Finding, PullAdapter } from "./types.js";
import type { IntegrationManifest } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_PAGES = 10;
const LEVEL: Record<string, Severity> = { high: "high", medium: "medium", low: "low" };
/** What each detection type means, in plain words, and the technique it points to. */
const TYPES: Record<string, { text: string; mitre: string[] }> = {
  leakedCredentials: { text: "The account's password was found in a leak", mitre: ["T1078"] },
  passwordSpray: { text: "Password spray against this account", mitre: ["T1110"] },
  unlikelyTravel: { text: "Sign-ins from places too far apart to travel between", mitre: ["T1078"] },
  impossibleTravel: { text: "Impossible travel between sign-ins", mitre: ["T1078"] },
  anonymizedIPAddress: { text: "Sign-in from an anonymous address (Tor or an anonymising VPN)", mitre: ["T1090"] },
  maliciousIPAddress: { text: "Sign-in from an address known for attacks", mitre: ["T1078"] },
  malwareInfectedIPAddress: { text: "Sign-in from an address linked to malware", mitre: ["T1078"] },
  suspiciousIPAddress: { text: "Sign-in from a suspicious address", mitre: ["T1078"] },
  unfamiliarFeatures: { text: "Sign-in with properties never seen for this account", mitre: ["T1078"] },
  anomalousToken: { text: "A session token was used in an unusual way (possible token theft)", mitre: ["T1528"] },
  tokenIssuerAnomaly: { text: "A token from an issuer that looks compromised", mitre: ["T1606"] },
  suspiciousInboxForwarding: { text: "A suspicious mail forwarding rule", mitre: ["T1114"] },
  mcasSuspiciousInboxManipulationRules: { text: "Suspicious inbox rules that hide or move mail", mitre: ["T1564"] },
  adminConfirmedUserCompromised: { text: "An administrator confirmed the account is compromised", mitre: ["T1078"] },
  investigationsThreatIntelligence: { text: "Microsoft threat intelligence flagged this sign-in", mitre: ["T1078"] },
  attackerinTheMiddle: { text: "Sign-in through an attacker-in-the-middle phishing proxy", mitre: ["T1557"] },
};

export function findingFromRiskDetection(d: Obj): Finding | null {
  const id = cleanText(d.id, 200);
  const type = cleanText(d.riskEventType, 80);
  if (!id || !type) return null;
  const level = String(d.riskLevel ?? "").toLowerCase();
  // "none" and "hidden" carry no risk Legion can state; a dismissed or remediated detection is history.
  if (!(level in LEVEL)) return null;
  const state = String(d.riskState ?? "").toLowerCase();
  if (state === "dismissed" || state === "remediated" || state === "confirmedsafe") return null;
  const user = cleanText(d.userPrincipalName, 200).toLowerCase();
  const known = TYPES[type];
  const loc = isObj(d.location) ? [cleanText(d.location.city, 60), cleanText(d.location.countryOrRegion, 10)].filter(Boolean).join(", ") : "";
  const text = known?.text ?? `Identity risk detected (${type})`;
  return {
    externalId: id,
    title: cleanText(`Entra ID: ${text}${user ? ` — ${user}` : ""}`, 300),
    severity: LEVEL[level]!,
    summary: [text + ".", user ? `Account: ${user}` : "", loc ? `Location: ${loc}` : "", d.riskDetail && d.riskDetail !== "none" ? `Detail: ${cleanText(d.riskDetail, 80)}` : "", d.detectionTimingType ? `Detection: ${cleanText(d.detectionTimingType, 40)}` : "", `State: ${cleanText(d.riskState, 40) || "at risk"}`].filter(Boolean).join("\n"),
    occurredAt: parseTime(d.activityDateTime) ?? parseTime(d.detectedDateTime),
    sourceIp: pickIp(d.ipAddress),
    target: user || null,
    mitre: known?.mitre ?? [],
    confidence: level === "high" ? 85 : level === "medium" ? 70 : 50,
    asset: user ? { name: user, ip: null, os: null, kind: "user" } : null,
  };
}

/** Client-credentials token for Microsoft Graph, for any manifest that declares both Microsoft hosts. */
export async function graphToken(manifest: Pick<IntegrationManifest, "egressHosts">, directoryId: string, clientId: string, clientSecret: string, signal: AbortSignal): Promise<string> {
  const res = await adapterFetch(manifest, `https://login.microsoftonline.com/${encodeURIComponent(directoryId)}/oauth2/v2.0/token`, {
    method: "POST", signal, timeoutMs: 20_000, maxBytes: 64 * 1024, headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, scope: "https://graph.microsoft.com/.default", grant_type: "client_credentials" }).toString(),
  });
  if (res.status !== 200) throw new Error(`Microsoft sign-in failed (${res.status}); check the directory id, application id and client secret`);
  let token = "";
  try { token = String((JSON.parse(res.body) as { access_token?: unknown }).access_token ?? ""); } catch { /* below */ }
  if (!token) throw new Error("Microsoft sign-in returned no token");
  return token;
}

export const entraAdapter: PullAdapter = {
  manifest: {
    kind: "entra_id", displayName: "Microsoft Entra ID (identity risk)", vendor: "Microsoft", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["graph.microsoft.com", "login.microsoftonline.com"],
    summary: "Identity risk detections from Entra ID Protection: leaked passwords, impossible travel, anonymous or malicious addresses, password spray, token theft. Read only.",
    auth: "Entra app registration with the application permission IdentityRiskEvent.Read.All (client credentials); the client secret is sealed per connection. Needs Entra ID P1 or P2.",
  },
  configSchema: z.strictObject({
    directory_id: z.string().uuid("Directory (tenant) id, a GUID"),
    client_id: z.string().uuid("Application (client) id, a GUID"),
  }),
  secretFields: ["client_secret"],
  async poll(conn, cursor, signal) {
    const m = entraAdapter.manifest;
    const token = await graphToken(m, String(conn.config.directory_id), String(conn.config.client_id), conn.secrets.client_secret ?? "", signal);
    const since = cursorSince(cursor);
    let url: string | null = `https://graph.microsoft.com/v1.0/identityProtection/riskDetections?${new URLSearchParams({ $filter: `detectedDateTime ge ${since}`, $top: "200" })}`;
    const findings: Finding[] = [];
    let newest = since;
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res = await adapterFetch(m, url, { method: "GET", signal, timeoutMs: 30_000, maxBytes: 8 * 1024 * 1024, headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
      if (res.status === 429 || res.status >= 500) throw new Error(`Microsoft Graph answered ${res.status}; will retry`);
      if (res.status !== 200) throw new Error(`Microsoft Graph refused the request (${res.status}); check that IdentityRiskEvent.Read.All has admin consent and the directory has Entra ID P1 or P2`);
      let body: { value?: unknown; "@odata.nextLink"?: unknown } = {};
      try { body = JSON.parse(res.body); } catch { throw new Error("Microsoft Graph returned invalid JSON"); }
      for (const d of Array.isArray(body.value) ? body.value : []) {
        if (!isObj(d)) continue;
        const f = findingFromRiskDetection(d);
        if (f) findings.push(f);
        const t = parseTime(d.detectedDateTime);
        if (t && t > newest) newest = t;
      }
      const next = body["@odata.nextLink"];
      url = typeof next === "string" ? next : null; // adapterFetch refuses any host but graph.microsoft.com
    }
    return { findings, cursor: { since: newest } };
  },
};
